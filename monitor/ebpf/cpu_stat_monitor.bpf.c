#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpu_stat_monitor.h" // 确保包含了 cpu_stat 的定义

char LICENSE[] SEC("license") = "GPL";

extern struct kernel_cpustat kernel_cpustat __ksym;

// 【关键修正】: 使用 PERCPU_ARRAY Map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256); // 足够支持多核系统，比如 256 个核心
    __type(key, u32);
    __type(value, struct cpu_stat);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} cpu_stats SEC(".maps");

SEC("fexit/kcpustat_cpu_fetch")
int BPF_PROG(fexit_kcpustat_cpu_fetch, struct kernel_cpustat *kcpustat,
             int cpu)
{
    u32 key = cpu;
    // u32 key = bpf_get_smp_processor_id();
    //  bpf_printk("sizeof(struct cpu_stat) in C is: %d bytes", sizeof(struct cpu_stat));
    
    // 在 PERCPU_ARRAY 中，lookup 永远不会失败（只要 key 在 max_entries 范围内）
    // 它返回的是当前 CPU 专属的 value 区域的指针
    struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_stats, &key);
    if (!stat) {
        // 如果不存在，先创建（虽然PERCPU_ARRAY通常是预分配的）
        struct cpu_stat new_stat = {0};
        bpf_map_update_elem(&cpu_stats, &key, &new_stat, BPF_NOEXIST);
        stat = bpf_map_lookup_elem(&cpu_stats, &key);
        if (!stat) return 0;
    }
    
    // 读取内核的 Per-CPU 统计信息
    struct kernel_cpustat* ptr = (struct kernel_cpustat*)bpf_this_cpu_ptr(&kernel_cpustat);
    if (!ptr) {
        return 0;
    }
    
    // 【优化】: 直接读取到 stat 结构体中，减少一次内存拷贝
    // 注意：这要求 stat 结构体中的字段顺序和类型与 kernel_cpustat.cpustat 数组兼容
    // 为了安全和清晰，我们还是逐个字段复制
    struct kernel_cpustat kstat;
    bpf_probe_read_kernel(&kstat, sizeof(kstat), ptr);
    
    // 更新当前 CPU 专属的统计信息
    stat->user = kstat.cpustat[CPUTIME_USER];
    stat->nice = kstat.cpustat[CPUTIME_NICE];
    stat->system = kstat.cpustat[CPUTIME_SYSTEM];
    stat->idle = kstat.cpustat[CPUTIME_IDLE];
    stat->iowait = kstat.cpustat[CPUTIME_IOWAIT];
    stat->irq = kstat.cpustat[CPUTIME_IRQ];
    stat->softirq = kstat.cpustat[CPUTIME_SOFTIRQ];
    stat->steal = kstat.cpustat[CPUTIME_STEAL];
    stat->guest = kstat.cpustat[CPUTIME_GUEST];
    stat->guest_nice = kstat.cpustat[CPUTIME_GUEST_NICE];
    stat->online = 1; // 我们可以用这个字段标记这个CPU的数据是有效的

    // bpf_printk 在高频探针中会造成性能问题，调试时才打开
    // bpf_printk("cpu %d, user %llu, system %llu", key, stat->user, stat->system);
    
    return 0;
}