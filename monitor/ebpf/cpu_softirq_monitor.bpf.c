// softirq_monitor.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpu_softirq_monitor.h"

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct softirq_key);
    __type(value, u64);
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32); // vec (softirq number)
    __type(value, struct softirq_stat);
} softirq_stats SEC(".maps");

// 挂载点：软中断处理开始
SEC("tracepoint/irq/softirq_entry")
int handle_softirq_entry(struct trace_event_raw_softirq *ctx)
{
    u32 vec = ctx->vec;
    u32 cpu = bpf_get_smp_processor_id();
    u64 ts = bpf_ktime_get_ns();
    
    struct softirq_key key = { .cpu = cpu, .vec = vec };
    bpf_map_update_elem(&start_time, &key, &ts, BPF_ANY);
    return 0;
}

// 挂载点：软中断处理结束
SEC("tracepoint/irq/softirq_exit")
int handle_softirq_exit(struct trace_event_raw_softirq *ctx)
{ 
    u32 vec = ctx->vec;
    u32 cpu = bpf_get_smp_processor_id();
    u64 *start_ts;
    u64 end_ts = bpf_ktime_get_ns();
    
    // 获取开始时间
    struct softirq_key key = { .cpu = cpu, .vec = vec };
    start_ts = bpf_map_lookup_elem(&start_time, &key);
    if (!start_ts) {
        return 0; // 没有找到对应的开始时间
    }
    
    // 计算处理时间
    u64 duration = end_ts - *start_ts;
    
    // 更新统计信息
    struct softirq_stat *stat;
    stat = bpf_map_lookup_elem(&softirq_stats, &vec);
    if (!stat) {
        struct softirq_stat new_stat = {0};
        bpf_map_update_elem(&softirq_stats, &vec, &new_stat, BPF_NOEXIST);
        stat = bpf_map_lookup_elem(&softirq_stats, &vec);
        if (!stat) return 0;
    }
    
    // 更新统计值
    stat->count++;
    stat->total_time_ns += duration;
    if (duration > stat->max_time_ns) {
        stat->max_time_ns = duration;
    }
    
    // 清理开始时间
    bpf_map_delete_elem(&start_time, &key);
    return 0;
}

char _license[] SEC("license") = "GPL";