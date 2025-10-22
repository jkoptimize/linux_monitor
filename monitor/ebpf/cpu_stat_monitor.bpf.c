#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cpu_stat_monitor.h"


#define MAX_NICE	19
#define MIN_NICE	-20
#define NICE_WIDTH	(MAX_NICE - MIN_NICE + 1)

#define MAX_USER_RT_PRIO	100
#define MAX_RT_PRIO		MAX_USER_RT_PRIO

#define MAX_PRIO		(MAX_RT_PRIO + NICE_WIDTH)
#define DEFAULT_PRIO		(MAX_RT_PRIO + NICE_WIDTH / 2)

#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern struct kernel_cpustat kernel_cpustat __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, struct cpu_stat);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cpu_stats SEC(".maps");

SEC("kprobe/account_process_tick")
int BPF_KPROBE(kprobe_account_process_tick, struct task_struct *p, u64 cputime)
{
    u32 key = bpf_get_smp_processor_id();
    
    // 确保PERCPU_ARRAY中的元素存在
    struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_stats, &key);
    if (!stat) {
        // 如果不存在，先创建（虽然PERCPU_ARRAY通常是预分配的）
        struct cpu_stat new_stat = {};
        bpf_map_update_elem(&cpu_stats, &key, &new_stat, BPF_NOEXIST);
        stat = bpf_map_lookup_elem(&cpu_stats, &key);
        if (!stat) return 0;
    }
    
    // 读取内核统计信息并更新
    struct kernel_cpustat* ptr = (struct kernel_cpustat*)bpf_this_cpu_ptr(&kernel_cpustat);
    if (!ptr) return 0;
    
    struct kernel_cpustat kstat = {};
    if (bpf_probe_read_kernel(&kstat, sizeof(kstat), ptr) < 0)
        return 0;
    
    // 更新统计信息
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
    bpf_printk("%d %d %d", stat->user, stat->nice, stat->system);
    
    return 0;
}

