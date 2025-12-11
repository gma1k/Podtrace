// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#define DB_TYPE_SQLITE 1
#define DB_TYPE_POSTGRESQL 2
#define DB_TYPE_MYSQL 3

static inline u64 get_pool_key(u32 pid, u32 tid) {
	return ((u64)pid << 32) | tid;
}

static inline void emit_pool_event(u32 pid, u32 type, u64 latency_ns, u32 db_type) {
	struct event *e = get_event_buf();
	if (!e) {
		return;
	}
	e->timestamp = bpf_ktime_get_ns();
	e->pid = pid;
	e->type = type;
	e->latency_ns = latency_ns;
	e->error = 0;
	e->bytes = 0;
	e->tcp_state = 0;
	e->stack_key = 0;
	
	const char *pool_name = "default-pool";
	if (db_type == DB_TYPE_SQLITE) {
		pool_name = "sqlite-pool";
	} else if (db_type == DB_TYPE_POSTGRESQL) {
		pool_name = "postgresql-pool";
	} else if (db_type == DB_TYPE_MYSQL) {
		pool_name = "mysql-pool";
	}
	
	bpf_probe_read_kernel_str(e->target, sizeof(e->target), pool_name);
	e->details[0] = '\0';
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

static inline void handle_pool_acquire(u32 pid, u32 tid, u64 key, u64 now, u32 db_type) {
	struct pool_state *state = bpf_map_lookup_elem(&pool_states, &key);
	if (!state) {
		struct pool_state new_state = {};
		new_state.connection_id = tid;
		new_state.last_use_ns = now;
		new_state.in_use = 1;
		bpf_map_update_elem(&pool_states, &key, &new_state, BPF_ANY);
		bpf_map_update_elem(&pool_db_types, &key, &db_type, BPF_ANY);
		bpf_map_update_elem(&pool_acquire_times, &key, &now, BPF_ANY);
		emit_pool_event(pid, EVENT_POOL_ACQUIRE, 0, db_type);
		return;
	}
	
	if (state->in_use == 0) {
		state->in_use = 1;
		state->last_use_ns = now;
		bpf_map_update_elem(&pool_states, &key, state, BPF_ANY);
		bpf_map_update_elem(&pool_db_types, &key, &db_type, BPF_ANY);
		bpf_map_update_elem(&pool_acquire_times, &key, &now, BPF_ANY);
		emit_pool_event(pid, EVENT_POOL_ACQUIRE, 0, db_type);
	} else {
		state->last_use_ns = now;
		bpf_map_update_elem(&pool_states, &key, state, BPF_ANY);
	}
}

static inline void handle_pool_release(u32 pid, u32 tid, u64 key) {
	struct pool_state *state = bpf_map_lookup_elem(&pool_states, &key);
	if (!state) {
		return;
	}
	
	u32 *db_type = bpf_map_lookup_elem(&pool_db_types, &key);
	u32 db = db_type ? *db_type : DB_TYPE_SQLITE;
	
	if (state->in_use == 1) {
		state->in_use = 0;
		bpf_map_update_elem(&pool_states, &key, state, BPF_ANY);
		emit_pool_event(pid, EVENT_POOL_RELEASE, 0, db);
	}
}

static inline void handle_pool_exhaustion(u32 pid, u32 tid, u64 key, u64 now) {
	u64 *acquire_time = bpf_map_lookup_elem(&pool_acquire_times, &key);
	if (acquire_time && now > *acquire_time) {
		u64 wait_time = now - *acquire_time;
		if (wait_time > 10000000) {
			u32 *db_type = bpf_map_lookup_elem(&pool_db_types, &key);
			u32 db = db_type ? *db_type : DB_TYPE_SQLITE;
			emit_pool_event(pid, EVENT_POOL_EXHAUSTED, wait_time, db);
		}
	}
}

SEC("uprobe/sqlite3_prepare_v2")
int uprobe_sqlite3_prepare_v2(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_acquire(pid, tid, key, now, DB_TYPE_SQLITE);
	return 0;
}

SEC("uprobe/sqlite3_prepare")
int uprobe_sqlite3_prepare(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_acquire(pid, tid, key, now, DB_TYPE_SQLITE);
	return 0;
}

SEC("uprobe/sqlite3_prepare16")
int uprobe_sqlite3_prepare16(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_acquire(pid, tid, key, now, DB_TYPE_SQLITE);
	return 0;
}

SEC("uprobe/sqlite3_prepare16_v2")
int uprobe_sqlite3_prepare16_v2(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_acquire(pid, tid, key, now, DB_TYPE_SQLITE);
	return 0;
}

SEC("uretprobe/sqlite3_finalize")
int uretprobe_sqlite3_finalize(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	handle_pool_release(pid, tid, key);
	return 0;
}

SEC("uprobe/sqlite3_step")
int uprobe_sqlite3_step(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_exhaustion(pid, tid, key, now);
	return 0;
}

SEC("uretprobe/sqlite3_step")
int uretprobe_sqlite3_step(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	bpf_map_delete_elem(&pool_acquire_times, &key);
	return 0;
}

SEC("uprobe/PQconnectStart")
int uprobe_PQconnectStart(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_acquire(pid, tid, key, now, DB_TYPE_POSTGRESQL);
	return 0;
}

SEC("uretprobe/PQfinish")
int uretprobe_PQfinish(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	handle_pool_release(pid, tid, key);
	return 0;
}

SEC("uprobe/PQexec_pool")
int uprobe_PQexec_pool(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_exhaustion(pid, tid, key, now);
	return 0;
}

SEC("uprobe/mysql_real_connect")
int uprobe_mysql_real_connect(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_acquire(pid, tid, key, now, DB_TYPE_MYSQL);
	return 0;
}

SEC("uretprobe/mysql_close")
int uretprobe_mysql_close(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	handle_pool_release(pid, tid, key);
	return 0;
}

SEC("uprobe/mysql_real_query_pool")
int uprobe_mysql_real_query_pool(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	u32 tid = (u32)bpf_get_current_pid_tgid();
	u64 key = get_pool_key(pid, tid);
	u64 now = bpf_ktime_get_ns();
	handle_pool_exhaustion(pid, tid, key, now);
	return 0;
}
