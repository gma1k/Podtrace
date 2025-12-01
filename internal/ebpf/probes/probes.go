package probes

import (
	"fmt"
	"os"
	"strings"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func AttachProbes(coll *ebpf.Collection) ([]link.Link, error) {
	var links []link.Link

	probes := map[string]string{
		"kprobe_tcp_connect":       "tcp_v4_connect",
		"kretprobe_tcp_connect":    "tcp_v4_connect",
		"kprobe_tcp_v6_connect":    "tcp_v6_connect",
		"kretprobe_tcp_v6_connect": "tcp_v6_connect",
		"kprobe_tcp_sendmsg":       "tcp_sendmsg",
		"kretprobe_tcp_sendmsg":    "tcp_sendmsg",
		"kprobe_tcp_recvmsg":       "tcp_recvmsg",
		"kretprobe_tcp_recvmsg":    "tcp_recvmsg",
		"kprobe_udp_sendmsg":       "udp_sendmsg",
		"kretprobe_udp_sendmsg":    "udp_sendmsg",
		"kprobe_udp_recvmsg":       "udp_recvmsg",
		"kretprobe_udp_recvmsg":    "udp_recvmsg",
		"kprobe_vfs_write":         "vfs_write",
		"kretprobe_vfs_write":      "vfs_write",
		"kprobe_vfs_read":          "vfs_read",
		"kretprobe_vfs_read":       "vfs_read",
		"kprobe_vfs_fsync":         "vfs_fsync",
		"kretprobe_vfs_fsync":      "vfs_fsync",
	}

	for progName, symbol := range probes {
		prog := coll.Programs[progName]
		if prog == nil {
			continue
		}

		var l link.Link
		var err error

		if strings.HasPrefix(progName, "kretprobe_") {
			l, err = link.Kretprobe(symbol, prog, nil)
		} else {
			l, err = link.Kprobe(symbol, prog, nil)
		}

		if err != nil {
			for _, existingLink := range links {
				existingLink.Close()
			}
			return nil, fmt.Errorf("failed to attach %s: %w", progName, err)
		}

		links = append(links, l)
	}

	if tracepointProg := coll.Programs["tracepoint_sched_switch"]; tracepointProg != nil {
		tp, err := link.Tracepoint("sched", "sched_switch", tracepointProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") {
				fmt.Fprintf(os.Stderr, "Note: CPU/scheduling tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	if tcpStateProg := coll.Programs["tracepoint_tcp_set_state"]; tcpStateProg != nil {
		tp, err := link.Tracepoint("tcp", "tcp_set_state", tcpStateProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				fmt.Fprintf(os.Stderr, "Note: TCP state tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	if pageFaultProg := coll.Programs["tracepoint_page_fault_user"]; pageFaultProg != nil {
		tp, err := link.Tracepoint("exceptions", "page_fault_user", pageFaultProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				fmt.Fprintf(os.Stderr, "Note: Page fault tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	if oomKillProg := coll.Programs["tracepoint_oom_kill_process"]; oomKillProg != nil {
		tp, err := link.Tracepoint("oom", "oom_kill_process", oomKillProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				fmt.Fprintf(os.Stderr, "Note: OOM kill tracking unavailable: %v\n", err)
			}
		} else {
			links = append(links, tp)
		}
	}

	return links, nil
}

func AttachDNSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	var links []link.Link
	libcPath := FindLibcPath(containerID)
	if libcPath != "" {
		uprobe, err := link.OpenExecutable(libcPath)
		if err == nil {
			if uprobeProg := coll.Programs["uprobe_getaddrinfo"]; uprobeProg != nil {
				l, err := uprobe.Uprobe("getaddrinfo", uprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					fmt.Fprintf(os.Stderr, "Note: DNS tracking (uprobe) unavailable: %v\n", err)
				}
			}
			if uretprobeProg := coll.Programs["uretprobe_getaddrinfo"]; uretprobeProg != nil {
				l, err := uprobe.Uretprobe("getaddrinfo", uretprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					fmt.Fprintf(os.Stderr, "Note: DNS tracking (uretprobe) unavailable: %v\n", err)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Note: DNS tracking unavailable (libc not found)\n")
		}
	} else {
		fmt.Fprintf(os.Stderr, "Note: DNS tracking unavailable (libc path not found)\n")
	}
	return links
}

func FindLibcPath(containerID string) string {
	libcPaths := []string{
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
		"/lib/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib64/libc.so.6",
		"/usr/lib/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
	}

	for _, path := range libcPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}

	if containerID != "" {
		containerPaths := FindLibcInContainer(containerID)
		for _, path := range containerPaths {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}

	return ""
}

func FindLibcInContainer(containerID string) []string {
	var paths []string
	containerRoot := fmt.Sprintf("/var/lib/docker/containers/%s/rootfs", containerID)
	if _, err := os.Stat(containerRoot); err == nil {
		libcPaths := []string{
			containerRoot + "/lib/x86_64-linux-gnu/libc.so.6",
			containerRoot + "/lib64/libc.so.6",
			containerRoot + "/lib/libc.so.6",
			containerRoot + "/usr/lib/x86_64-linux-gnu/libc.so.6",
			containerRoot + "/usr/lib64/libc.so.6",
			containerRoot + "/usr/lib/libc.so.6",
		}
		paths = append(paths, libcPaths...)
	}

	procPaths := []string{
		"/proc/1/root/lib/x86_64-linux-gnu/libc.so.6",
		"/proc/1/root/lib64/libc.so.6",
		"/proc/1/root/lib/libc.so.6",
		"/proc/1/root/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/proc/1/root/usr/lib64/libc.so.6",
		"/proc/1/root/usr/lib/libc.so.6",
	}
	paths = append(paths, procPaths...)

	return paths
}
