package probes

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"

	"github.com/podtrace/podtrace/internal/config"
	"github.com/podtrace/podtrace/internal/logger"
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
		"kprobe_do_futex":          "do_futex",
		"kretprobe_do_futex":       "do_futex",
		"kprobe_do_sys_openat2":    "do_sys_openat2",
		"kretprobe_do_sys_openat2": "do_sys_openat2",
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
				_ = existingLink.Close()
			}
			return nil, NewProbeAttachError(progName, err)
		}

		links = append(links, l)
	}

	if tracepointProg := coll.Programs["tracepoint_sched_switch"]; tracepointProg != nil {
		tp, err := link.Tracepoint("sched", "sched_switch", tracepointProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") {
				logger.Info("CPU/scheduling tracking unavailable", zap.Error(err))
			}
		} else {
			links = append(links, tp)
		}
	}

	if tcpStateProg := coll.Programs["tracepoint_tcp_set_state"]; tcpStateProg != nil {
		tp, err := link.Tracepoint("tcp", "tcp_set_state", tcpStateProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				logger.Debug("TCP state tracking unavailable", zap.Error(err))
			}
		} else {
			links = append(links, tp)
		}
	}

	if tcpRetransProg := coll.Programs["tracepoint_tcp_retransmit_skb"]; tcpRetransProg != nil {
		tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", tcpRetransProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				logger.Info("TCP retransmission tracking unavailable", zap.Error(err))
			}
		} else {
			links = append(links, tp)
		}
	}

	if netDevProg := coll.Programs["tracepoint_net_dev_xmit"]; netDevProg != nil {
		tp, err := link.Tracepoint("net", "net_dev_xmit", netDevProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				logger.Info("Network device error tracking unavailable", zap.Error(err))
			}
		} else {
			links = append(links, tp)
		}
	}

	if pageFaultProg := coll.Programs["tracepoint_page_fault_user"]; pageFaultProg != nil {
		tp, err := link.Tracepoint("exceptions", "page_fault_user", pageFaultProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				logger.Info("Page fault tracking unavailable", zap.Error(err))
			}
		} else {
			links = append(links, tp)
		}
	}

	if oomKillProg := coll.Programs["tracepoint_oom_kill_process"]; oomKillProg != nil {
		tp, err := link.Tracepoint("oom", "oom_kill_process", oomKillProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				logger.Debug("OOM kill tracking unavailable", zap.Error(err))
			}
		} else {
			links = append(links, tp)
		}
	}

	if forkProg := coll.Programs["tracepoint_sched_process_fork"]; forkProg != nil {
		tp, err := link.Tracepoint("sched", "sched_process_fork", forkProg, nil)
		if err != nil {
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "not found") {
				logger.Info("Process fork tracking unavailable", zap.Error(err))
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
					logger.Info("DNS tracking (uprobe) unavailable", zap.Error(err))
				}
			}
			if uretprobeProg := coll.Programs["uretprobe_getaddrinfo"]; uretprobeProg != nil {
				l, err := uprobe.Uretprobe("getaddrinfo", uretprobeProg, nil)
				if err == nil {
					links = append(links, l)
				} else {
					logger.Info("DNS tracking (uretprobe) unavailable", zap.Error(err))
				}
			}
		} else {
			logger.Info("DNS tracking unavailable (libc not found)")
		}
	} else {
		logger.Info("DNS tracking unavailable (libc path not found)")
	}
	return links
}

func AttachSyncProbes(coll *ebpf.Collection, containerID string) []link.Link {
	var links []link.Link
	libcPath := FindLibcPath(containerID)
	if libcPath == "" {
		return links
	}
	uprobe, err := link.OpenExecutable(libcPath)
	if err != nil {
		logger.Info("Lock tracking unavailable", zap.Error(err))
		return links
	}
	if prog := coll.Programs["uprobe_pthread_mutex_lock"]; prog != nil {
		l, err := uprobe.Uprobe("pthread_mutex_lock", prog, nil)
		if err == nil {
			links = append(links, l)
		} else if !strings.Contains(err.Error(), "symbol pthread_mutex_lock not found") {
			logger.Info("Pthread mutex lock tracking unavailable", zap.Error(err))
		}
	}
	if prog := coll.Programs["uretprobe_pthread_mutex_lock"]; prog != nil {
		l, err := uprobe.Uretprobe("pthread_mutex_lock", prog, nil)
		if err == nil {
			links = append(links, l)
		} else if !strings.Contains(err.Error(), "symbol pthread_mutex_lock not found") {
			logger.Info("Pthread mutex lock tracking unavailable", zap.Error(err))
		}
	}
	return links
}

func AttachDBProbes(coll *ebpf.Collection, containerID string) []link.Link {
	var links []link.Link

	libpqPaths := findDBLibs(containerID, []string{"libpq.so.5", "libpq.so"})
	for _, path := range libpqPaths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		if prog := coll.Programs["uprobe_PQexec"]; prog != nil {
			l, err := exe.Uprobe("PQexec", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
		if prog := coll.Programs["uretprobe_PQexec"]; prog != nil {
			l, err := exe.Uretprobe("PQexec", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
	}

	mysqlPaths := findDBLibs(containerID, []string{"libmysqlclient.so.21", "libmysqlclient.so"})
	for _, path := range mysqlPaths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(path)
		if err != nil {
			continue
		}
		if prog := coll.Programs["uprobe_mysql_real_query"]; prog != nil {
			l, err := exe.Uprobe("mysql_real_query", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
		if prog := coll.Programs["uretprobe_mysql_real_query"]; prog != nil {
			l, err := exe.Uretprobe("mysql_real_query", prog, nil)
			if err == nil {
				links = append(links, l)
			}
		}
	}

	return links
}

type dbProbeConfig struct {
	name           string
	libPatterns    []string
	acquireSymbols []string
	releaseSymbol  string
	exhaustSymbol  string
	acquireProg    string
	releaseProg    string
	exhaustProg    string
	exhaustRetProg string
}

func AttachPoolProbes(coll *ebpf.Collection, containerID string) []link.Link {
	var links []link.Link

	var binaryPaths []string
	if pid := findContainerProcess(containerID); pid > 0 {
		logger.Debug("Found container process", zap.Uint32("pid", pid), zap.String("containerID", containerID))

		binaryPath := findGoBinaryViaProcessMaps(pid)
		if binaryPath == "" {
			binaryPath = findGoBinaryInProcess(pid)
		}
		if binaryPath == "" {
			binaryPath = findGoBinaryInContainer(containerID, pid)
		}

		if binaryPath != "" {
			binaryPaths = append(binaryPaths, binaryPath)
			logger.Debug("Found Go binary for pool monitoring", zap.String("path", binaryPath), zap.Uint32("pid", pid))
		} else {
			logger.Debug("Go binary not found for process", zap.Uint32("pid", pid))
		}
	} else {
		logger.Debug("Container process not found", zap.String("containerID", containerID))
	}

	dbConfigs := []dbProbeConfig{
		{
			name:           "sqlite",
			libPatterns:    []string{"libsqlite3.so.0", "libsqlite3.so", "sqlite3.so"},
			acquireSymbols: []string{"sqlite3_prepare_v2", "sqlite3_prepare", "sqlite3_prepare16", "sqlite3_prepare16_v2"},
			releaseSymbol:  "sqlite3_finalize",
			exhaustSymbol:  "sqlite3_step",
			acquireProg:    "uprobe_sqlite3_prepare_v2",
			releaseProg:    "uretprobe_sqlite3_finalize",
			exhaustProg:    "uprobe_sqlite3_step",
			exhaustRetProg: "uretprobe_sqlite3_step",
		},
		{
			name:           "postgresql",
			libPatterns:    []string{"libpq.so.5", "libpq.so"},
			acquireSymbols: []string{"PQconnectStart"},
			releaseSymbol:  "PQfinish",
			exhaustSymbol:  "PQexec",
			acquireProg:    "uprobe_PQconnectStart",
			releaseProg:    "uretprobe_PQfinish",
			exhaustProg:    "uprobe_PQexec_pool",
			exhaustRetProg: "",
		},
		{
			name:           "mysql",
			libPatterns:    []string{"libmysqlclient.so.21", "libmysqlclient.so"},
			acquireSymbols: []string{"mysql_real_connect"},
			releaseSymbol:  "mysql_close",
			exhaustSymbol:  "mysql_real_query",
			acquireProg:    "uprobe_mysql_real_connect",
			releaseProg:    "uretprobe_mysql_close",
			exhaustProg:    "uprobe_mysql_real_query_pool",
			exhaustRetProg: "",
		},
	}

	for _, dbConfig := range dbConfigs {
		var dbPaths []string
		dbPaths = append(dbPaths, binaryPaths...)
		libPaths := findDBLibs(containerID, dbConfig.libPatterns)
		dbPaths = append(dbPaths, libPaths...)

		if len(dbPaths) == 0 {
			logger.Debug("No libraries found for database", zap.String("database", dbConfig.name), zap.String("containerID", containerID))
			continue
		}

		for _, path := range dbPaths {
			logger.Debug("Attaching pool probes", zap.String("database", dbConfig.name), zap.String("path", path))
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}
			exe, err := link.OpenExecutable(path)
			if err != nil {
				logger.Debug("Failed to open executable for pool probes", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
				continue
			}

			for _, symbol := range dbConfig.acquireSymbols {
				if prog := coll.Programs[dbConfig.acquireProg]; prog != nil {
					l, err := exe.Uprobe(symbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool acquire probe", zap.String("database", dbConfig.name), zap.String("symbol", symbol), zap.String("path", path))
						break
					}
				}
			}

			if dbConfig.releaseProg != "" && dbConfig.releaseSymbol != "" {
				if prog := coll.Programs[dbConfig.releaseProg]; prog != nil {
					l, err := exe.Uretprobe(dbConfig.releaseSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool release probe", zap.String("database", dbConfig.name), zap.String("path", path))
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.releaseSymbol)) {
						logger.Debug("Pool release probe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}

			if dbConfig.exhaustProg != "" && dbConfig.exhaustSymbol != "" {
				if prog := coll.Programs[dbConfig.exhaustProg]; prog != nil {
					l, err := exe.Uprobe(dbConfig.exhaustSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
						logger.Debug("Attached pool exhaustion probe", zap.String("database", dbConfig.name), zap.String("path", path))
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.exhaustSymbol)) {
						logger.Debug("Pool exhaustion probe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}

			if dbConfig.exhaustRetProg != "" && dbConfig.exhaustSymbol != "" {
				if prog := coll.Programs[dbConfig.exhaustRetProg]; prog != nil {
					l, err := exe.Uretprobe(dbConfig.exhaustSymbol, prog, nil)
					if err == nil {
						links = append(links, l)
					} else if !strings.Contains(err.Error(), fmt.Sprintf("symbol %s not found", dbConfig.exhaustSymbol)) {
						logger.Debug("Pool exhaustion retprobe unavailable", zap.String("database", dbConfig.name), zap.String("path", path), zap.Error(err))
					}
				}
			}
		}
	}

	if len(links) > 0 {
		logger.Debug("Pool monitoring probes attached", zap.Int("total_links", len(links)), zap.String("containerID", containerID))
	} else {
		logger.Debug("No pool monitoring probes attached", zap.String("containerID", containerID))
	}

	return links
}

func FindLibcPath(containerID string) string {
	if containerID != "" {
		if path := findLibcInContainer(containerID); path != "" {
			return path
		}
	}

	if path := findLibcViaLdconfig(); path != "" {
		return path
	}

	if path := findLibcViaLdSoConf(); path != "" {
		return path
	}

	return findLibcViaCommonPaths()
}

func findLibcViaLdconfig() string {
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "libc.so.6") || strings.Contains(line, "libc.musl") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "=>" && i+1 < len(parts) {
					path := strings.TrimSpace(parts[i+1])
					if info, err := os.Stat(path); err == nil && !info.IsDir() {
						return path
					}
				}
			}
		}
	}
	return ""
}

func getMuslLibcNames() []string {
	names := []string{"libc.so.6"}
	arch := runtime.GOARCH

	muslArchMap := map[string]string{
		"amd64":   "x86_64",
		"arm64":   "aarch64",
		"riscv64": "riscv64",
		"ppc64le": "ppc64le",
		"s390x":   "s390x",
	}

	if muslArch, ok := muslArchMap[arch]; ok {
		names = append(names, fmt.Sprintf("libc.musl-%s.so.1", muslArch))
	}

	return names
}

func findLibcViaLdSoConf() string {
	searchPaths := config.GetDefaultLibSearchPaths()

	if data, err := os.ReadFile(config.GetLdSoConfPath()); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				searchPaths = append(searchPaths, line)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetLdSoConfDPattern()); err == nil {
		for _, confFile := range matches {
			if data, err := os.ReadFile(confFile); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						searchPaths = append(searchPaths, line)
					}
				}
			}
		}
	}

	libcNames := getMuslLibcNames()
	for _, searchPath := range searchPaths {
		for _, libcName := range libcNames {
			path := filepath.Join(searchPath, libcName)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}
	return ""
}

func findLibcViaProcessMaps(pid uint32) string {
	mapsPath := fmt.Sprintf("%s/%d/maps", config.ProcBasePath, pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "libc.so") || strings.Contains(line, "libc.musl") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				path := parts[5]
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path
				}
			}
		}
	}
	return ""
}

func findContainerProcess(containerID string) uint32 {
	entries, err := os.ReadDir(config.ProcBasePath)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
			continue
		}

		cgroupPath := filepath.Join(config.ProcBasePath, pidStr, "cgroup")
		if data, err := os.ReadFile(cgroupPath); err == nil {
			if strings.Contains(string(data), containerID) {
				var pid uint32
				if _, err := fmt.Sscanf(pidStr, "%d", &pid); err == nil {
					return pid
				}
			}
		}
	}
	return 0
}

func findGoBinaryInProcess(pid uint32) string {
	exePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		logger.Debug("Failed to read exe symlink", zap.Uint32("pid", pid), zap.String("path", exePath), zap.Error(err))
		return ""
	}

	if !filepath.IsAbs(target) {
		cwdPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "cwd")
		cwd, err := os.Readlink(cwdPath)
		if err != nil {
			logger.Debug("Failed to read cwd symlink", zap.Uint32("pid", pid), zap.Error(err))
			cwd = "/"
		}
		target = filepath.Join(cwd, target)
	}

	procRootPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")
	hostPath := filepath.Join(procRootPath, strings.TrimPrefix(target, "/"))

	if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
		logger.Debug("Found binary via container root", zap.Uint32("pid", pid), zap.String("container_path", target), zap.String("host_path", hostPath))
		return hostPath
	}

	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		logger.Debug("Found binary via direct path", zap.Uint32("pid", pid), zap.String("path", target))
		return target
	}

	logger.Debug("Binary not found or not accessible", zap.Uint32("pid", pid), zap.String("target", target), zap.String("host_path", hostPath), zap.Error(err))
	return ""
}

func findGoBinaryViaProcessMaps(pid uint32) string {
	mapsPath := fmt.Sprintf("%s/%d/maps", config.ProcBasePath, pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		logger.Debug("Failed to read process maps", zap.Uint32("pid", pid), zap.Error(err))
		return ""
	}

	procRootPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")

	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "r-xp") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				binaryPath := parts[5]
				if binaryPath != "" && !strings.HasPrefix(binaryPath, "[") {
					if strings.Contains(binaryPath, ".so") || strings.Contains(binaryPath, "vdso") || strings.Contains(binaryPath, "vsyscall") {
						continue
					}

					hostPath := filepath.Join(procRootPath, strings.TrimPrefix(binaryPath, "/"))
					if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
						logger.Debug("Found binary via process maps", zap.Uint32("pid", pid), zap.String("container_path", binaryPath), zap.String("host_path", hostPath))
						return hostPath
					}

					if info, err := os.Stat(binaryPath); err == nil && !info.IsDir() {
						logger.Debug("Found binary via process maps (direct)", zap.Uint32("pid", pid), zap.String("path", binaryPath))
						return binaryPath
					}
				}
			}
		}
	}
	return ""
}

func findGoBinaryInContainer(containerID string, pid uint32) string {
	procRootPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root")

	cmdlinePath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "cmdline")
	if cmdlineData, err := os.ReadFile(cmdlinePath); err == nil {
		cmdline := string(cmdlineData)
		if len(cmdline) > 0 {
			parts := strings.Split(cmdline, "\x00")
			if len(parts) > 0 && parts[0] != "" {
				binaryPath := parts[0]
				if filepath.IsAbs(binaryPath) {
					hostPath := filepath.Join(procRootPath, strings.TrimPrefix(binaryPath, "/"))
					if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
						logger.Debug("Found binary via cmdline", zap.Uint32("pid", pid), zap.String("cmdline_path", binaryPath), zap.String("host_path", hostPath))
						return hostPath
					}
				}
			}
		}
	}

	commPath := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "comm")
	if commData, err := os.ReadFile(commPath); err == nil {
		commName := strings.TrimSpace(string(commData))
		if commName != "" {
			commonPaths := []string{
				filepath.Join("/app", commName),
				filepath.Join("/app", commName+".app"),
				filepath.Join("/usr/local/bin", commName),
				filepath.Join("/bin", commName),
				filepath.Join("/app", "main"),
				filepath.Join("/app", "app"),
			}
			for _, relPath := range commonPaths {
				hostPath := filepath.Join(procRootPath, strings.TrimPrefix(relPath, "/"))
				if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
					logger.Debug("Found binary via comm name", zap.Uint32("pid", pid), zap.String("comm", commName), zap.String("path", hostPath))
					return hostPath
				}
			}
		}
	}

	commonPaths := []string{
		"/app/pool-test-app",
		"/app/main",
		"/app/app",
		"/usr/local/bin/app",
		"/bin/app",
	}

	for _, relPath := range commonPaths {
		hostPath := filepath.Join(procRootPath, strings.TrimPrefix(relPath, "/"))
		if info, err := os.Stat(hostPath); err == nil && !info.IsDir() {
			logger.Debug("Found binary via container root common paths", zap.Uint32("pid", pid), zap.String("path", hostPath))
			return hostPath
		}
	}

	rootfsPaths := []string{
		config.GetDockerContainerRootfs(containerID),
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			for _, relPath := range commonPaths {
				path := filepath.Join(rootfs, strings.TrimPrefix(relPath, "/"))
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					logger.Debug("Found binary via container rootfs", zap.String("rootfs", rootfs), zap.String("path", path))
					return path
				}
			}
		}
	}

	return ""
}

func findLibcInContainer(containerID string) string {
	if pid := findContainerProcess(containerID); pid > 0 {
		if path := findLibcViaProcessMaps(pid); path != "" {
			return path
		}

		procRootPaths := getArchitecturePaths()
		for _, basePath := range procRootPaths {
			path := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root", basePath)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				return path
			}
		}
	}

	rootfsPaths := []string{
		config.GetDockerContainerRootfs(containerID),
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			libcPaths := getArchitecturePaths()
			for _, libcPath := range libcPaths {
				path := filepath.Join(rootfs, libcPath)
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					return path
				}
			}
		}
	}

	procPaths := getArchitecturePaths()
	for _, basePath := range procPaths {
		path := filepath.Join(config.GetDefaultProcRootPath(), basePath)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}

	return ""
}

func getArchitecturePaths() []string {
	arch := runtime.GOARCH
	paths := []string{}

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			paths = append(paths,
				fmt.Sprintf("lib/%s/libc.so.6", suffix),
				fmt.Sprintf("usr/lib/%s/libc.so.6", suffix),
			)
		}
	}

	paths = append(paths,
		"lib64/libc.so.6",
		"lib/libc.so.6",
		"usr/lib64/libc.so.6",
		"usr/lib/libc.so.6",
	)

	return paths
}

func findLibcViaCommonPaths() string {
	paths := getArchitecturePaths()
	for _, relPath := range paths {
		path := filepath.Join("/", relPath)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func findDBLibsViaLdconfig(libNames []string) []string {
	var paths []string
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return paths
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		for _, libName := range libNames {
			if strings.Contains(line, libName) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "=>" && i+1 < len(parts) {
						path := strings.TrimSpace(parts[i+1])
						if info, err := os.Stat(path); err == nil && !info.IsDir() {
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}
	return paths
}

func findDBLibsViaLdSoConf(libNames []string) []string {
	var paths []string
	searchPaths := config.GetDefaultLibSearchPaths()

	if data, err := os.ReadFile(config.GetLdSoConfPath()); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				searchPaths = append(searchPaths, line)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetLdSoConfDPattern()); err == nil {
		for _, confFile := range matches {
			if data, err := os.ReadFile(confFile); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						searchPaths = append(searchPaths, line)
					}
				}
			}
		}
	}

	for _, searchPath := range searchPaths {
		for _, libName := range libNames {
			path := filepath.Join(searchPath, libName)
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func getArchitectureDBPaths(libNames []string) []string {
	var paths []string
	arch := runtime.GOARCH

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			for _, libName := range libNames {
				paths = append(paths,
					fmt.Sprintf("/usr/lib/%s/%s", suffix, libName),
					fmt.Sprintf("/lib/%s/%s", suffix, libName),
				)
			}
		}
	}

	for _, libName := range libNames {
		paths = append(paths,
			fmt.Sprintf("/usr/lib64/%s", libName),
			fmt.Sprintf("/usr/lib/%s", libName),
			fmt.Sprintf("/lib64/%s", libName),
			fmt.Sprintf("/lib/%s", libName),
		)
	}

	return paths
}

func findDBLibsViaProcessMaps(pid uint32, libNames []string) []string {
	var paths []string
	mapsPath := fmt.Sprintf("%s/%d/maps", config.ProcBasePath, pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return paths
	}

	for _, line := range strings.Split(string(data), "\n") {
		for _, libName := range libNames {
			if strings.Contains(line, libName) {
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					path := parts[5]
					if info, err := os.Stat(path); err == nil && !info.IsDir() {
						paths = append(paths, path)
					}
				}
			}
		}
	}
	return paths
}

func findDBLibsInContainer(containerID string, libNames []string) []string {
	var paths []string

	if pid := findContainerProcess(containerID); pid > 0 {
		if foundPaths := findDBLibsViaProcessMaps(pid, libNames); len(foundPaths) > 0 {
			paths = append(paths, foundPaths...)
		}

		archPaths := getArchitectureDBPaths(libNames)
		for _, basePath := range archPaths {
			path := filepath.Join(config.ProcBasePath, fmt.Sprintf("%d", pid), "root", strings.TrimPrefix(basePath, "/"))
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
			}
		}
	}

	rootfsPaths := []string{
		config.GetDockerContainerRootfs(containerID),
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			archPaths := getArchitectureDBPaths(libNames)
			for _, basePath := range archPaths {
				path := filepath.Join(rootfs, strings.TrimPrefix(basePath, "/"))
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					paths = append(paths, path)
				}
			}
		}
	}

	archPaths := getArchitectureDBPaths(libNames)
	for _, basePath := range archPaths {
		path := filepath.Join(config.GetDefaultProcRootPath(), strings.TrimPrefix(basePath, "/"))
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			paths = append(paths, path)
		}
	}

	return paths
}

func findDBLibs(containerID string, libNames []string) []string {
	var paths []string
	seen := make(map[string]bool)

	if containerID != "" {
		containerPaths := findDBLibsInContainer(containerID, libNames)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findDBLibsViaLdconfig(libNames)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findDBLibsViaLdSoConf(libNames)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	commonPaths := getArchitectureDBPaths(libNames)
	for _, path := range commonPaths {
		if !seen[path] {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

func FindLibcInContainer(containerID string) []string {
	var paths []string
	containerRoot := config.GetDockerContainerRootfs(containerID)
	if _, err := os.Stat(containerRoot); err == nil {
		libcPaths := getArchitecturePaths()
		for _, libcPath := range libcPaths {
			paths = append(paths, filepath.Join(containerRoot, libcPath))
		}
	}

	procPaths := getArchitecturePaths()
	for _, basePath := range procPaths {
		paths = append(paths, filepath.Join(config.GetDefaultProcRootPath(), basePath))
	}

	return paths
}

func findTLSLibsViaProcessMaps(pid uint32, libPatterns []string) []string {
	var paths []string
	mapsPath := fmt.Sprintf("%s/%d/maps", config.ProcBasePath, pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return paths
	}

	for _, line := range strings.Split(string(data), "\n") {
		for _, pattern := range libPatterns {
			if strings.Contains(line, pattern) {
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					path := parts[5]
					if info, err := os.Stat(path); err == nil && !info.IsDir() {
						paths = append(paths, path)
					}
				}
			}
		}
	}
	return paths
}

func findTLSLibsInContainer(containerID string, libPatterns []string) []string {
	var paths []string

	if pid := findContainerProcess(containerID); pid > 0 {
		if foundPaths := findTLSLibsViaProcessMaps(pid, libPatterns); len(foundPaths) > 0 {
			paths = append(paths, foundPaths...)
		}
	}

	rootfsPaths := []string{
		config.GetDockerContainerRootfs(containerID),
	}

	if matches, err := filepath.Glob(config.GetContainerdOverlayPattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetContainerdNativePattern()); err == nil {
		for _, match := range matches {
			if strings.Contains(match, containerID) || filepath.Base(filepath.Dir(match)) == containerID {
				rootfsPaths = append(rootfsPaths, match)
			}
		}
	}

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	for _, rootfs := range rootfsPaths {
		if _, err := os.Stat(rootfs); err == nil {
			archPaths := getArchitectureDBPaths(libPatterns)
			for _, basePath := range archPaths {
				path := filepath.Join(rootfs, strings.TrimPrefix(basePath, "/"))
				if info, err := os.Stat(path); err == nil && !info.IsDir() {
					paths = append(paths, path)
				}
			}
			if err := filepath.Walk(rootfs, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				baseName := strings.ToLower(filepath.Base(path))
				for _, pattern := range libPatternsLower {
					if strings.Contains(baseName, pattern) {
						paths = append(paths, path)
						return nil
					}
				}
				return nil
			}); err != nil {
				continue
			}
		}
	}

	return paths
}

func findTLSLibsViaLdconfig(libPatterns []string) []string {
	var paths []string
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.Output()
	if err != nil {
		return paths
	}

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)
		for _, pattern := range libPatternsLower {
			if strings.Contains(lineLower, pattern) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "=>" && i+1 < len(parts) {
						path := strings.TrimSpace(parts[i+1])
						if info, err := os.Stat(path); err == nil && !info.IsDir() {
							paths = append(paths, path)
						}
					}
				}
			}
		}
	}
	return paths
}

func findTLSLibsViaLdSoConf(libPatterns []string) []string {
	var paths []string
	searchPaths := config.GetDefaultLibSearchPaths()

	if data, err := os.ReadFile(config.GetLdSoConfPath()); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				searchPaths = append(searchPaths, line)
			}
		}
	}

	if matches, err := filepath.Glob(config.GetLdSoConfDPattern()); err == nil {
		for _, confFile := range matches {
			if data, err := os.ReadFile(confFile); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "#") {
						searchPaths = append(searchPaths, line)
					}
				}
			}
		}
	}

	libPatternsLower := make([]string, len(libPatterns))
	for i, p := range libPatterns {
		libPatternsLower[i] = strings.ToLower(p)
	}

	for _, searchPath := range searchPaths {
		err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			baseName := strings.ToLower(filepath.Base(path))
			for _, pattern := range libPatternsLower {
				if strings.Contains(baseName, pattern) {
					paths = append(paths, path)
					return nil
				}
			}
			return nil
		})
		if err != nil {
			continue
		}
	}
	return paths
}

func findTLSLibs(containerID string) []string {
	var paths []string
	seen := make(map[string]bool)

	libPatterns := []string{"libssl", "libgnutls", "libnss", "libmbedtls", "libmbedx509", "ssl"}

	if containerID != "" {
		containerPaths := findTLSLibsInContainer(containerID, libPatterns)
		for _, path := range containerPaths {
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	ldconfigPaths := findTLSLibsViaLdconfig(libPatterns)
	for _, path := range ldconfigPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	ldSoConfPaths := findTLSLibsViaLdSoConf(libPatterns)
	for _, path := range ldSoConfPaths {
		if !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}

	archPaths := getArchitectureTLSPaths(libPatterns)
	for _, path := range archPaths {
		if !seen[path] {
			if info, err := os.Stat(path); err == nil && !info.IsDir() {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	commonLibPaths := []string{
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
		"/usr/local/lib64",
		"/usr/local/lib",
	}

	for _, libPath := range commonLibPaths {
		if _, err := os.Stat(libPath); err != nil {
			continue
		}
		err := filepath.Walk(libPath, func(walkPath string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			baseName := strings.ToLower(filepath.Base(walkPath))
			for _, pattern := range libPatterns {
				if strings.Contains(baseName, strings.ToLower(pattern)) {
					if !seen[walkPath] {
						paths = append(paths, walkPath)
						seen[walkPath] = true
					}
				}
			}
			return nil
		})
		if err != nil {
			continue
		}
	}

	return paths
}

func getArchitectureTLSPaths(libPatterns []string) []string {
	var paths []string
	arch := runtime.GOARCH

	archSuffixes := map[string][]string{
		"amd64":   {"x86_64-linux-gnu", "x86_64"},
		"arm64":   {"aarch64-linux-gnu", "aarch64"},
		"riscv64": {"riscv64-linux-gnu", "riscv64"},
		"ppc64le": {"powerpc64le-linux-gnu", "ppc64le"},
		"s390x":   {"s390x-linux-gnu", "s390x"},
		"arm":     {"arm-linux-gnueabihf", "arm-linux-gnueabi"},
		"386":     {"i386-linux-gnu", "i686-linux-gnu"},
		"mips":    {"mips-linux-gnu", "mipsel-linux-gnu"},
		"mips64":  {"mips64-linux-gnuabi64", "mips64el-linux-gnuabi64"},
	}

	if suffixes, ok := archSuffixes[arch]; ok {
		for _, suffix := range suffixes {
			basePaths := []string{
				fmt.Sprintf("/usr/lib/%s", suffix),
				fmt.Sprintf("/lib/%s", suffix),
			}
			for _, basePath := range basePaths {
				if _, err := os.Stat(basePath); err == nil {
					for _, pattern := range libPatterns {
						err := filepath.Walk(basePath, func(walkPath string, info os.FileInfo, err error) error {
							if err != nil || info.IsDir() {
								return nil
							}
							baseName := strings.ToLower(filepath.Base(walkPath))
							if strings.Contains(baseName, strings.ToLower(pattern)) {
								paths = append(paths, walkPath)
							}
							return nil
						})
						if err != nil {
							continue
						}
					}
				}
			}
		}
	}

	commonPaths := []string{
		"/usr/lib64",
		"/usr/lib",
		"/lib64",
		"/lib",
	}

	for _, basePath := range commonPaths {
		if _, err := os.Stat(basePath); err == nil {
			for _, pattern := range libPatterns {
				err := filepath.Walk(basePath, func(walkPath string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return nil
					}
					baseName := strings.ToLower(filepath.Base(walkPath))
					if strings.Contains(baseName, strings.ToLower(pattern)) {
						paths = append(paths, walkPath)
					}
					return nil
				})
				if err != nil {
					continue
				}
			}
		}
	}

	return paths
}

func AttachTLSProbes(coll *ebpf.Collection, containerID string) []link.Link {
	links := []link.Link{}

	tlsLibPaths := findTLSLibs(containerID)
	tlsSymbols := map[string][]string{
		"SSL_connect":           {"uprobe_SSL_connect", "uretprobe_SSL_connect"},
		"SSL_accept":            {"uprobe_SSL_accept", "uretprobe_SSL_accept"},
		"SSL_do_handshake":      {"uprobe_SSL_do_handshake", "uretprobe_SSL_do_handshake"},
		"gnutls_handshake":      {"uprobe_gnutls_handshake", "uretprobe_gnutls_handshake"},
		"mbedtls_ssl_handshake": {"uprobe_mbedtls_ssl_handshake", "uretprobe_mbedtls_ssl_handshake"},
	}

	for _, libPath := range tlsLibPaths {
		info, err := os.Stat(libPath)
		if err != nil || info.IsDir() {
			continue
		}
		exe, err := link.OpenExecutable(libPath)
		if err != nil {
			continue
		}

		for symbol, progNames := range tlsSymbols {
			if len(progNames) < 2 {
				continue
			}
			uprobeProg := coll.Programs[progNames[0]]
			uretprobeProg := coll.Programs[progNames[1]]

			if uprobeProg != nil {
				l, err := exe.Uprobe(symbol, uprobeProg, nil)
				if err == nil {
					links = append(links, l)
				}
			}
			if uretprobeProg != nil {
				l, err := exe.Uretprobe(symbol, uretprobeProg, nil)
				if err == nil {
					links = append(links, l)
				}
			}
		}
	}

	return links
}
