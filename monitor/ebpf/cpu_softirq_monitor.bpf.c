#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpu_softirq_monitor.h" // 假设 softirq_stat 等结构在此定义

// 用于在 softirq_entry 和 softirq_exit 之间传递时间戳的哈希表
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1);
} start SEC(".maps");

// 【已修改】: 用于存储最终统计结果的 Per-CPU 数组
// Key 是软中断向量 vec, Value 是每个 CPU 独立的 softirq_stat
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16); // 支持最多 16 种软中断类型，足够安全
    __type(key, u32);
    __type(value, struct softirq_stat);
} softirq_stats SEC(".maps");


// 挂载到 softirq_entry 函数 (或 tracepoint)
// SEC("kprobe/softirq_entry")
SEC("tracepoint/irq/softirq_entry")
int handle_softirq_entry(struct trace_event_raw_softirq* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u32 key = 0;
    bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    return 0;
}

// 挂载到 softirq_exit 函数 (或 tracepoint)
// SEC("kprobe/softirq_exit")
SEC("tracepoint/irq/softirq_exit")
int handle_softirq_exit(struct trace_event_raw_softirq* ctx)
{
    u32 key_map = 0;
    u64 *start_ts = bpf_map_lookup_elem(&start, &key_map);
    if (!start_ts) {
        // bpf_printk("[handle_softirq_exit] start_ts null");
        return 0;
    }

    u64 delta = bpf_ktime_get_ns() - *start_ts;
    
    // 从 tracepoint 上下文中获取软中断向量号 (vec)
    u32 vec = ctx->vec;

    // 【已修改】: Key 现在就是 vec
    if (vec >= 16) { // 防止 key 超出 max_entries 范围
        // bpf_printk("[handle_softirq_exit] vec >= 16");
        return 0;
    }

    // 【已修改】: 在 PERCPU_ARRAY 中, lookup 返回当前 CPU 的数据指针, 无需检查是否为 NULL
    struct softirq_stat *stat = bpf_map_lookup_elem(&softirq_stats, &vec);
    if (!stat) { // 这个检查理论上不会失败，但作为安全措施保留
        // bpf_printk("[handle_softirq_exit] stat is null");
        return 0;
    }

    // 【已修改】: 直接在获取到的指针上进行原子操作或普通更新
    // 无需区分新旧元素，也无需再调用 map_update_elem
    __sync_fetch_and_add(&stat->count, 1); // 使用原子加更安全
    __sync_fetch_and_add(&stat->total_time_ns, delta);

    // 对于 max_time_ns, 需要使用循环来原子地比较和交换 (CAS)
    // 这是一个简化的非原子版本，在高并发下可能不精确，但在很多场景下足够
    if (delta > stat->max_time_ns) {
        stat->max_time_ns = delta;
    }
    
    // (如果需要严格的原子max，可以使用 bpf_spin_lock + 普通更新)   

    return 0;
}

char LICENSE[] SEC("license") = "GPL";