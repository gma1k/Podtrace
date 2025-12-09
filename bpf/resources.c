// SPDX-License-Identifier: GPL-2.0

#include "common.h"
#include "maps.h"
#include "events.h"
#include "helpers.h"

#define RESOURCE_CPU    0
#define RESOURCE_MEMORY 1
#define RESOURCE_IO     2

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
    if (utilization >= 95) {
        return 3;
    } else if (utilization >= 90) {
        return 2;
    } else if (utilization >= 80) {
        return 1;
    }
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
    if (alert_level > 0) {
        bpf_map_update_elem(&cgroup_alerts, &cgroup_id, &alert_level, BPF_ANY);
    } else {
        bpf_map_delete_elem(&cgroup_alerts, &cgroup_id);
    }
}