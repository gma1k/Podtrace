package nodespawn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/gma1k/podtrace/internal/logger"
)

// MachineBootID returns this machine's kernel boot ID, or "" when it
// cannot be read (non-Linux workstations). Overridable for tests.
var MachineBootID = func() string {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// MachinePIDNamespace returns the inode of this process's PID namespace, or
// "" when it cannot be read.
var MachinePIDNamespace = func() string {
	link, err := readPIDNamespaceLink()
	if err != nil {
		return ""
	}
	inode, ok := strings.CutPrefix(link, "pid:[")
	if !ok {
		return ""
	}
	return strings.TrimSuffix(inode, "]")
}

var readPIDNamespaceLink = func() (string, error) {
	return os.Readlink("/proc/self/ns/pid")
}

// DeletePod best-effort deletes the spawn pod; NotFound is swallowed so retries
// and parallel reapers don't error out.
func DeletePod(ctx context.Context, clientset kubernetes.Interface, namespace, name string) error {
	zero := int64(0)
	err := clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{
		GracePeriodSeconds: &zero,
	})
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("nodespawn: delete %s/%s: %w", namespace, name, err)
}

// DeletePodGracefully deletes the spawn pod with a grace period, so the
// kubelet sends its podtrace SIGTERM and lets it finish before killing it.
func DeletePodGracefully(ctx context.Context, clientset kubernetes.Interface, namespace, name string, grace time.Duration) error {
	seconds := int64(grace / time.Second)
	err := clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{
		GracePeriodSeconds: &seconds,
	})
	if err == nil || IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("nodespawn: delete %s/%s: %w", namespace, name, err)
}

// ReapStale deletes spawn pods whose owning CLI process is gone.
func ReapStale(ctx context.Context, clientset kubernetes.Interface, namespace, ownerHost string) (int, error) {
	return reapStaleWithLiveness(ctx, clientset, namespace, ownerHost, processAlive)
}

// reapStaleWithLiveness is the test-injectable form. Production callers use
// ReapStale, which wires in the OS-backed processAlive check.
func reapStaleWithLiveness(
	ctx context.Context,
	clientset kubernetes.Interface,
	namespace, ownerHost string,
	alive func(int) bool,
) (int, error) {
	labelSel := fmt.Sprintf("%s=%s", LabelManagedBy, ManagedByValue)
	if ownerHost != "" {
		labelSel += fmt.Sprintf(",%s=%s", LabelOwnerHost, sanitizeLabelValue(ownerHost))
	}
	list, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: labelSel})
	if err != nil {
		return 0, fmt.Errorf("nodespawn: list stale pods: %w", err)
	}

	localBootID := MachineBootID()
	localPIDNS := MachinePIDNamespace()
	reaped := 0
	for i := range list.Items {
		p := &list.Items[i]

		expired := podOlderThan(p.Labels[LabelCreatedAt], reapAgeBound(p.Spec.ActiveDeadlineSeconds))

		if !expired && localBootID != "" {
			if podBootID := p.Labels[LabelOwnerBootID]; podBootID != "" && podBootID != sanitizeLabelValue(localBootID) {
				continue
			}
		}

		if !expired {
			if podPIDNS := p.Labels[LabelOwnerPIDNS]; podPIDNS != "" && podPIDNS != sanitizeLabelValue(localPIDNS) {
				continue
			}
			pidStr := p.Labels[LabelOwnerPID]
			if pidStr == "" {
				logger.Debug("Spawn pod has no owner-pid label; not reaping (anomaly — surface but don't touch)",
					zap.String("namespace", p.Namespace),
					zap.String("name", p.Name))
				continue
			}
			pid, perr := strconv.Atoi(pidStr)
			if perr != nil || pid <= 0 {
				logger.Debug("Spawn pod has malformed owner-pid label; not reaping",
					zap.String("namespace", p.Namespace),
					zap.String("name", p.Name),
					zap.String("owner-pid", pidStr))
				continue
			}
			if alive(pid) {
				continue
			}
		}

		if derr := DeletePod(ctx, clientset, p.Namespace, p.Name); derr == nil {
			reaped++
			logger.Debug("Reaped orphan spawn pod",
				zap.String("namespace", p.Namespace),
				zap.String("name", p.Name),
				zap.Bool("expired", expired))
		}
	}
	return reaped, nil
}

// reapAgeBound returns the age past which a spawn pod is reaped
// unconditionally: ReaperMaxAge, or for traces spawned with a longer
// explicit deadline, that deadline plus a grace period.
func reapAgeBound(activeDeadlineSeconds *int64) time.Duration {
	bound := ReaperMaxAge
	if activeDeadlineSeconds != nil && *activeDeadlineSeconds > 0 {
		withGrace := time.Duration(*activeDeadlineSeconds)*time.Second + 10*time.Minute
		if withGrace > bound {
			bound = withGrace
		}
	}
	return bound
}

// podOlderThan parses the created-at label (unix seconds) and reports
// whether the pod is older than maxAge.
func podOlderThan(createdAt string, maxAge time.Duration) bool {
	if createdAt == "" {
		return false
	}
	sec, err := strconv.ParseInt(createdAt, 10, 64)
	if err != nil || sec <= 0 {
		return false
	}
	return time.Since(time.Unix(sec, 0)) > maxAge
}

func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return true
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		return false
	}
	return true
}
