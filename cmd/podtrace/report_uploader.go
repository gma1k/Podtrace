package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/gma1k/podtrace/internal/hostfs"
	"github.com/gma1k/podtrace/internal/reportsink/objectstore"
)

const envObjectStoreCredentialsDir = "PODTRACE_OBJECTSTORE_CREDENTIALS_DIR"

const reportLocationFile = "/var/run/podtrace/report-location.txt"

const terminationLogPath = "/dev/termination-log"

var keyHintStateFile = "/var/run/podtrace/upload-key-hint.txt"

func newReportUploaderCmd() *cobra.Command {
	var (
		reportFile     string
		reportToSpec   string
		summaryPath    string
		watchInterval  time.Duration
		maxWaitTimeout time.Duration
	)

	cmd := &cobra.Command{
		Use:   "report-uploader",
		Short: "Sidecar uploader for session diagnose artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if reportFile == "" || reportToSpec == "" {
				return errors.New("--report-file and --report-to are both required")
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return runReportUploader(ctx, reportUploaderOptions{
				ReportFile:     reportFile,
				SummaryFile:    summaryPath,
				ReportToSpec:   reportToSpec,
				WatchInterval:  watchInterval,
				MaxWaitTimeout: maxWaitTimeout,
			})
		},
	}
	cmd.Flags().StringVar(&reportFile, "report-file", "", "Path to the report file the main container produces")
	cmd.Flags().StringVar(&reportToSpec, "report-to", "",
		"Target sink. One of: kind/namespace/name (kind=configmap|secret) "+
			"or an object-store URI (s3://, gs://, azblob://)")
	cmd.Flags().StringVar(&summaryPath, "summary-file", "",
		"Optional summary JSON path. ObjectStore uploads also push this under <key>.summary.json")
	cmd.Flags().DurationVar(&watchInterval, "watch-interval", 500*time.Millisecond, "Poll interval while waiting for the report file")
	cmd.Flags().DurationVar(&maxWaitTimeout, "max-wait", 0, "Maximum time to wait for the report file before uploading what exists (0 = wait until SIGTERM)")
	return cmd
}

type reportUploaderOptions struct {
	ReportFile     string
	SummaryFile    string
	ReportToSpec   string
	WatchInterval  time.Duration
	MaxWaitTimeout time.Duration
}

func runReportUploader(ctx context.Context, opts reportUploaderOptions) error {
	if opts.WatchInterval <= 0 {
		opts.WatchInterval = 500 * time.Millisecond
	}

	waitCtx := ctx
	if opts.MaxWaitTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, opts.MaxWaitTimeout)
		defer cancel()
	}

	if err := waitForFile(waitCtx, opts.ReportFile, opts.WatchInterval); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("wait for report file: %w", err)
		}
	}

	// With --max-wait 0 the wait above ends BECAUSE ctx was cancelled —
	// SIGTERM is the designed trigger ("wait until SIGTERM, then upload
	// what exists"). Running the upload on that cancelled context made it
	// fail instantly on the exact path it exists for, so detach it and
	// apply a bounded grace period instead.
	uploadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), uploadGracePeriod)
	defer cancel()
	return uploadIfPresent(uploadCtx, opts)
}

// uploadGracePeriod bounds the post-shutdown upload so a hung sink cannot
// keep the sidecar alive past the pod's termination grace period.
const uploadGracePeriod = 30 * time.Second

func waitForFile(ctx context.Context, path string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func uploadIfPresent(ctx context.Context, opts reportUploaderOptions) error {
	raw, err := hostfs.ReadFile(opts.ReportFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read report file: %w", err)
	}

	if isObjectStoreURI(opts.ReportToSpec) {
		return uploadToObjectStore(ctx, opts, raw)
	}
	return uploadReport(ctx, opts.ReportToSpec, string(raw))
}

func isObjectStoreURI(spec string) bool {
	return strings.Contains(spec, "://")
}

func uploadToObjectStore(ctx context.Context, opts reportUploaderOptions, report []byte) error {
	creds, err := loadObjectStoreCredentials()
	if err != nil {
		return fmt.Errorf("object-store credentials: %w", err)
	}
	sink, err := objectstore.New(ctx, objectstore.Config{
		URI:         opts.ReportToSpec,
		Credentials: creds,
		Policy:      objectstore.PolicyFromEnv(),
	})
	if err != nil {
		return fmt.Errorf("object-store sink: %w", err)
	}
	defer func() {
		// Close() failures during shutdown are best-effort: the upload
		// already happened (or failed loudly) above. Surface to stderr
		// so cluster operators can correlate persistent close errors
		// with broader sidecar lifecycle issues.
		if cerr := sink.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: object-store sink close: %v\n", cerr)
		}
	}()

	keyHint := buildObjectKeyHint()
	resolved, err := sink.Upload(ctx, keyHint, "text/plain", bytes.NewReader(report))
	if err != nil {
		return fmt.Errorf("upload report: %w", err)
	}

	if opts.SummaryFile != "" {
		summary, err := hostfs.ReadFile(opts.SummaryFile)
		if err == nil && len(summary) > 0 {
			summaryHint := keyHint + ".summary.json"
			if _, err := sink.Upload(ctx, summaryHint, "application/json", bytes.NewReader(summary)); err != nil {
				fmt.Fprintf(os.Stderr, "warning: summary upload failed: %v\n", err)
			}
		}
	}

	if err := writeResolvedLocation(resolved); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write resolved location: %v\n", err)
	}
	if err := hostfs.WriteFile(terminationLogPath, []byte(resolved), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: write termination message: %v\n", err)
	}
	return nil
}

func loadObjectStoreCredentials() (map[string][]byte, error) {
	dir := os.Getenv(envObjectStoreCredentialsDir)
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read credentials dir %q: %w", dir, err)
	}
	out := make(map[string][]byte, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "..") {
			continue
		}
		if e.IsDir() {
			continue
		}
		data, err := hostfs.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read credential file %q: %w", e.Name(), err)
		}
		out[e.Name()] = data
	}
	return out, nil
}

// buildObjectKeyHint returns a stable per-session object-key suffix.
func buildObjectKeyHint() string {
	if existing, ok := readPersistedKeyHint(); ok {
		return existing
	}
	hint := freshObjectKeyHint(time.Now)
	persistKeyHint(hint)
	return hint
}

func freshObjectKeyHint(nowFn func() time.Time) string {
	pod := os.Getenv("HOSTNAME")
	if pod == "" {
		pod = "session"
	}
	stamp := nowFn().UTC().Format("2006-01-02T15-04-05Z")
	return fmt.Sprintf("%s-%s.txt", pod, stamp)
}

// readPersistedKeyHint loads a previously-stored key suffix from the
// state file in the shared volume.
func readPersistedKeyHint() (string, bool) {
	raw, err := hostfs.ReadFile(keyHintStateFile)
	if err != nil {
		return "", false
	}
	hint := strings.TrimSpace(string(raw))
	if hint == "" {
		return "", false
	}
	return hint, true
}

// persistKeyHint writes the key suffix to the state file. Failures
// are logged but non-fatal.
func persistKeyHint(hint string) {
	if err := hostfs.WriteFile(keyHintStateFile, []byte(hint), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: persist key hint: %v\n", err)
	}
}

func writeResolvedLocation(uri string) error {
	if err := hostfs.WriteFile(reportLocationFile, []byte(uri), 0o600); err != nil {
		return err
	}
	return nil
}
