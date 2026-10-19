package exporter

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gma1k/podtrace/internal/netguard"
)

// PartialExportError reports an export that did not deliver a whole batch.
// FailedTraces names the traces that hit a transient failure and must be
// offered again.
type PartialExportError struct {
	FailedTraces map[string]struct{}
	Err          error
}

func (e *PartialExportError) Error() string { return e.Err.Error() }

func (e *PartialExportError) Unwrap() error { return e.Err }

// Retry reports whether the trace must be offered to the exporter again.
func (e *PartialExportError) Retry(traceID string) bool {
	_, ok := e.FailedTraces[traceID]
	return ok
}

// permanentError marks a failure that resending the same payload cannot fix.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }

func (e *permanentError) Unwrap() error { return e.err }

func permanent(err error) error {
	return &permanentError{err: err}
}

// isPermanent also treats an egress-guard refusal as permanent: the guard
// refuses the same destination on every attempt, so retrying would only
// pile the batch up until the traces expire.
func isPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p) || errors.Is(err, netguard.ErrBlocked)
}

// statusError turns an unexpected HTTP status into an error, marking the
// client errors a backend will keep returning for the same payload as
// permanent. 408 and 429 are retryable by definition.
func statusError(code int) error {
	err := fmt.Errorf("unexpected status code: %d", code)
	if code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests {
		return permanent(err)
	}
	return err
}

// exportOutcome accumulates per-trace results of one ExportTraces call.
type exportOutcome struct {
	failed map[string]struct{}
	errs   []error
}

// record notes err against the given traces; transient errors schedule
// them for retry, permanent ones are reported but not retried.
func (o *exportOutcome) record(err error, traceIDs ...string) {
	if err == nil {
		return
	}
	o.errs = append(o.errs, err)
	if isPermanent(err) {
		return
	}
	if o.failed == nil {
		o.failed = make(map[string]struct{}, len(traceIDs))
	}
	for _, id := range traceIDs {
		o.failed[id] = struct{}{}
	}
}

func (o *exportOutcome) err() error {
	if len(o.errs) == 0 {
		return nil
	}
	return &PartialExportError{FailedTraces: o.failed, Err: errors.Join(o.errs...)}
}
