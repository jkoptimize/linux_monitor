#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_CPUS 128

struct cpu_stat {
    long long user;
    long long nice;
    long long system;
    long long idle;
    long long iowait;
    long long irq;
    long long softirq;
    long long steal;
    long long guest;
    long long guest_nice;
    int cpu_id;
    long long timestamp;  // 添加时间戳
};

// PERCPU_ARRAY用于存储每个CPU的最新统计信息
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);
    __type(value, struct cpu_stat);
} cpu_current_stats SEC(".maps");

// 全局时间戳，用于同步
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, long long);
} global_timestamp SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

extern struct kernel_cpustat kernel_cpustat __ksym;

SEC("kprobe/account_process_tick")
int BPF_KPROBE(kprobe_account_process_tick, struct task_struct *p, u64 cputime)
{
    int cpu = bpf_get_smp_processor_id();
    u32 cpu_key = cpu;
    
    // 获取当前CPU的统计信息指针
    struct kernel_cpustat* ptr = bpf_this_cpu_ptr(&kernel_cpustat);
    if (!ptr)
        return 0;
    
    // 读取内核的CPU统计信息
    struct kernel_cpustat kstat = {};
    if (bpf_probe_read_kernel(&kstat, sizeof(kstat), ptr) < 0)
        return 0;
    
    // 获取当前时间戳
    long long ts = bpf_ktime_get_ns();
    
    // 更新PERCPU_ARRAY中的统计信息
    struct cpu_stat *stat = bpf_map_lookup_elem(&cpu_current_stats, &cpu_key);
    if (stat) {
        stat->user = kstat.cpustat[CPUTIME_USER];
        stat->nice = kstat.cpustat[CPUTIME_NICE];
        stat->system = kstat.cpustat[CPUTIME_SYSTEM];
        stat->idle = kstat.cpustat[CPUTIME_IDLE];
        stat->iowait = kstat.cpustat[CPUTIME_IOWAIT];
        stat->irq = kstat.cpustat[CPUTIME_IRQ];
        stat->softirq = kstat.cpustat[CPUTIME_SOFTIRQ];
        stat->cpu_id = cpu;
        stat->timestamp = ts;
    }
    
    return 0;
}

// 可选：定时更新全局时间戳，用于用户空间同步
SEC("tp_btf/timer_expire_entry")
int BPF_PROG(timer_expire_entry, struct hrtimer *hrtimer, enum hrtimer_restart *restart)
{
    u32 key = 0;
    long long ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&global_timestamp, &key, &ts, BPF_ANY);
    return 0;
}