// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"


static inline u32 calculate_utilization(u64 usage, u64 limit) {
    if (limit == 0 || limit == ~0ULL) {
        return 0;
    }
    if (usage > limit) {
        return 100;
    }
    u64 percent = (usage * 100) / limit;
    return (u32)(percent > 100 ? 100 : percent);
}

static inline u32 check_alert_threshold(u32 utilization) {
    u32 key;

    key = 2;
    u32 *t_emerg = bpf_map_lookup_elem(&alert_thresholds, &key);
    u32 emerg = (t_emerg && *t_emerg > 0) ? *t_emerg : 95;

    key = 1;
    u32 *t_crit = bpf_map_lookup_elem(&alert_thresholds, &key);
    u32 crit = (t_crit && *t_crit > 0) ? *t_crit : 90;

    key = 0;
    u32 *t_warn = bpf_map_lookup_elem(&alert_thresholds, &key);
    u32 warn = (t_warn && *t_warn > 0) ? *t_warn : 80;

    if (utilization >= emerg) return 3;
    if (utilization >= crit)  return 2;
    if (utilization >= warn)  return 1;
    return 0;
}

static inline void emit_resource_alert(u64 cgroup_id, u32 resource_type, u32 utilization, u64 limit, u64 usage) {
    struct event *e = get_event_buf();
    if (!e) {
        return;
    }
    
    e->timestamp = bpf_ktime_get_ns();
    e->pid = 0;
    e->type = EVENT_RESOURCE_LIMIT;
    e->latency_ns = 0;
    e->error = (s32)utilization;
    e->bytes = usage;
    e->tcp_state = resource_type;
    e->target[0] = '\0';
    
    char *details = e->details;
    u32 idx = 0;
    u32 max_idx = MAX_STRING_LEN - 1;
    
    const char *resource_names[] = {"CPU", "MEM", "IO"};
    if (resource_type < 3) {
        const char *name = resource_names[resource_type];
        for (int i = 0; name[i] != '\0' && idx < max_idx; i++) {
            details[idx++] = name[i];
        }
    }
    
    if (idx < max_idx) details[idx++] = ':';
    
    if (utilization >= 100 && idx < max_idx - 2) {
        details[idx++] = '1';
        details[idx++] = '0';
        details[idx++] = '0';
    } else if (utilization >= 10 && idx < max_idx - 1) {
        details[idx++] = '0' + (utilization / 10);
        details[idx++] = '0' + (utilization % 10);
    } else if (idx < max_idx) {
        details[idx++] = '0' + utilization;
    }
    
    if (idx < max_idx) details[idx++] = '%';
    details[idx < MAX_STRING_LEN ? idx : max_idx] = '\0';
    
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    
    u32 alert_level = check_alert_threshold(utilization);
    struct resource_key alert_key = {
        .cgroup_id = cgroup_id,
        .resource_type = resource_type,
    };
    if (alert_level > 0) {
        bpf_map_update_elem(&cgroup_alerts, &alert_key, &alert_level, BPF_ANY);
    } else {
        bpf_map_delete_elem(&cgroup_alerts, &alert_key);
    }
}

SEC("raw_tracepoint/cgroup_mkdir")
int raw_tracepoint_cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
	struct cgroup *cgrp = (struct cgroup *)ctx->args[0];
	if (!cgrp)
		return 0;
	u64 parent = BPF_CORE_READ(cgrp, self.parent, cgroup, kn, id);
	if (!parent || !bpf_map_lookup_elem(&target_parent_cgroup_ids, &parent))
		return 0;
	u64 id = BPF_CORE_READ(cgrp, kn, id);
	if (id)
		bpf_map_update_elem(&inherited_cgroup_ids, &id, &parent, BPF_ANY);
	return 0;
}
