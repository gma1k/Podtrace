package probes

// ProbeGroup identifies a logical category of BPF probes that can be
// enabled or disabled at runtime via the management API.
type ProbeGroup string

const (
	GroupNetwork    ProbeGroup = "network"
	GroupFileSystem ProbeGroup = "filesystem"
	GroupDatabase   ProbeGroup = "database"
	GroupTLS        ProbeGroup = "tls"
	GroupMemory     ProbeGroup = "memory"
	GroupCPU        ProbeGroup = "cpu"
	GroupPool       ProbeGroup = "pool"
	GroupCache      ProbeGroup = "cache"     // Redis, Memcached
	GroupMessaging  ProbeGroup = "messaging" // Kafka
	GroupFastCGI    ProbeGroup = "fastcgi"   // PHP-FPM / FastCGI unix socket probes
	GroupCrypto     ProbeGroup = "crypto"    // AF_ALG crypto-socket detection
	GroupUSDT       ProbeGroup = "usdt"      // USDT (.note.stapsdt) userspace probes
)

// probeGroupMap maps each BPF program name to its ProbeGroup.
// Programs absent from this map are treated as GroupNetwork by default.
var probeGroupMap = map[string]ProbeGroup{
	// USDT
	"uprobe_usdt": GroupUSDT,

	// Network
	"kprobe_tcp_connect":             GroupNetwork,
	"kretprobe_tcp_connect":          GroupNetwork,
	"kprobe_tcp_v6_connect":          GroupNetwork,
	"kretprobe_tcp_v6_connect":       GroupNetwork,
	"kprobe_tcp_sendmsg":             GroupNetwork,
	"kretprobe_tcp_sendmsg":          GroupNetwork,
	"kprobe_tcp_recvmsg":             GroupNetwork,
	"kretprobe_tcp_recvmsg":          GroupNetwork,
	"kprobe_udp_sendmsg":             GroupNetwork,
	"kretprobe_udp_sendmsg":          GroupNetwork,
	"kprobe_udp_recvmsg":             GroupNetwork,
	"kretprobe_udp_recvmsg":          GroupNetwork,
	"tracepoint_inet_sock_set_state": GroupNetwork,
	"tracepoint_tcp_retransmit_skb":  GroupNetwork,
	"tracepoint_net_dev_xmit":        GroupNetwork,

	// FileSystem
	"kprobe_vfs_write":               GroupFileSystem,
	"kretprobe_vfs_write":            GroupFileSystem,
	"kprobe_vfs_read":                GroupFileSystem,
	"kretprobe_vfs_read":             GroupFileSystem,
	"tracepoint_sys_enter_fsync":     GroupFileSystem,
	"tracepoint_sys_exit_fsync":      GroupFileSystem,
	"tracepoint_sys_enter_fdatasync": GroupFileSystem,
	"tracepoint_sys_exit_fdatasync":  GroupFileSystem,
	"fentry_vfs_read":                GroupFileSystem,
	"fexit_vfs_read":                 GroupFileSystem,
	"fentry_vfs_write":               GroupFileSystem,
	"fexit_vfs_write":                GroupFileSystem,
	"kprobe_do_sys_openat2":          GroupFileSystem,
	"kretprobe_do_sys_openat2":       GroupFileSystem,
	"kprobe_vfs_unlink":              GroupFileSystem,
	"kretprobe_vfs_unlink":           GroupFileSystem,
	"kprobe_vfs_rename":              GroupFileSystem,
	"kretprobe_vfs_rename":           GroupFileSystem,
	"kprobe_close_fd":                GroupFileSystem,

	// CPU
	"tracepoint_sched_switch": GroupCPU,
	"kprobe_do_futex":         GroupCPU,
	"kretprobe_do_futex":      GroupCPU,

	// Memory
	"tracepoint_page_fault_user": GroupMemory,
	"tracepoint_oom_mark_victim": GroupMemory,

	// Process (grouped under CPU for simplicity)
	"raw_tracepoint_sched_process_fork": GroupCPU,
	"tracepoint_sched_process_exec":     GroupCPU,

	// TLS (uprobes attached separately via SetContainerID)
	"uprobe_getaddrinfo":           GroupTLS,
	"uretprobe_getaddrinfo":        GroupTLS,
	"uprobe_gethostbyname_r":       GroupTLS,
	"uretprobe_gethostbyname_r":    GroupTLS,
	"uprobe_gethostbyname2_r":      GroupTLS,
	"uretprobe_gethostbyname2_r":   GroupTLS,
	"uprobe_pthread_mutex_lock":    GroupTLS,
	"uretprobe_pthread_mutex_lock": GroupTLS,

	// TLS plaintext HTTP capture
	"uprobe_SSL_write":             GroupTLS,
	"uretprobe_SSL_write":          GroupTLS,
	"uprobe_SSL_read":              GroupTLS,
	"uretprobe_SSL_read":           GroupTLS,
	"uprobe_SSL_write_ex":          GroupTLS,
	"uretprobe_SSL_write_ex":       GroupTLS,
	"uprobe_SSL_read_ex":           GroupTLS,
	"uretprobe_SSL_read_ex":        GroupTLS,
	"uprobe_gnutls_record_send":    GroupTLS,
	"uretprobe_gnutls_record_send": GroupTLS,
	"uprobe_gnutls_record_recv":    GroupTLS,
	"uretprobe_gnutls_record_recv": GroupTLS,

	// Go crypto/tls (statically-linked Go HTTPS)
	"uprobe_go_tls_write":         GroupTLS,
	"uprobe_go_tls_read":          GroupTLS,
	"uprobe_go_tls_read_ret":      GroupTLS,
	"uprobe_go_tls_handshake":     GroupTLS,
	"uprobe_go_tls_handshake_ret": GroupTLS,

	// Database
	"uprobe_PQexec":    GroupDatabase,
	"uretprobe_PQexec": GroupDatabase,

	// Pool
	"uprobe_go_db_conn":            GroupPool,
	"uprobe_go_db_conn_ret":        GroupPool,
	"uprobe_sqlite3_prepare_v2":    GroupPool,
	"uprobe_sqlite3_prepare":       GroupPool,
	"uprobe_sqlite3_prepare16":     GroupPool,
	"uprobe_sqlite3_prepare16_v2":  GroupPool,
	"uretprobe_sqlite3_finalize":   GroupPool,
	"uprobe_sqlite3_step":          GroupPool,
	"uretprobe_sqlite3_step":       GroupPool,
	"uprobe_PQconnectStart":        GroupPool,
	"uretprobe_PQfinish":           GroupPool,
	"uprobe_PQexec_pool":           GroupPool,
	"uprobe_mysql_real_connect":    GroupPool,
	"uretprobe_mysql_close":        GroupPool,
	"uprobe_mysql_real_query_pool": GroupPool,

	// Cache (Redis / Memcached)
	"uprobe_redisCommand":        GroupCache,
	"uretprobe_redisCommand":     GroupCache,
	"uprobe_redisCommandArgv":    GroupCache,
	"uretprobe_redisCommandArgv": GroupCache,
	"uprobe_memcached_get":       GroupCache,
	"uretprobe_memcached_get":    GroupCache,
	"uprobe_memcached_set":       GroupCache,
	"uretprobe_memcached_set":    GroupCache,
	"uprobe_memcached_delete":    GroupCache,
	"uretprobe_memcached_delete": GroupCache,

	// Messaging (Kafka)
	"uprobe_rd_kafka_topic_new":        GroupMessaging,
	"uretprobe_rd_kafka_topic_new":     GroupMessaging,
	"uprobe_rd_kafka_produce":          GroupMessaging,
	"uretprobe_rd_kafka_produce":       GroupMessaging,
	"uprobe_rd_kafka_consumer_poll":    GroupMessaging,
	"uretprobe_rd_kafka_consumer_poll": GroupMessaging,

	// FastCGI (unix socket PHP-FPM tracing)
	"kprobe_unix_stream_recvmsg":    GroupFastCGI,
	"kretprobe_unix_stream_recvmsg": GroupFastCGI,
	"kprobe_unix_stream_sendmsg":    GroupFastCGI,

	// gRPC (second kprobe on tcp_sendmsg for HTTP/2 inspection)
	"kprobe_grpc_tcp_sendmsg": GroupNetwork,

	// HTTP/1.x (socket-level request/response line inspection)
	"kprobe_http_tcp_sendmsg":    GroupNetwork,
	"kprobe_http_tcp_recvmsg":    GroupNetwork,
	"kretprobe_http_tcp_recvmsg": GroupNetwork,

	// HTTP/2 h2c (HPACK endpoint capture)
	"kprobe_h2_tcp_sendmsg":    GroupNetwork,
	"kretprobe_h2_tcp_sendmsg": GroupNetwork,
	"kprobe_h2_tcp_recvmsg":    GroupNetwork,
	"kretprobe_h2_tcp_recvmsg": GroupNetwork,
	"kprobe_h2_tcp_close":      GroupNetwork,

	// Crypto (AF_ALG bind detection, "Copy-Fail" vulnerability interface)
	"tracepoint_sys_enter_bind": GroupCrypto,
}

// GroupForProbe returns the ProbeGroup for a BPF program name.
func GroupForProbe(progName string) ProbeGroup {
	if g, ok := probeGroupMap[progName]; ok {
		return g
	}
	return GroupNetwork
}
