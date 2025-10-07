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


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64); // tid
    __type(value, void *);
    __uint(max_entries, 1024);
} saved_seq_file SEC(".maps");

extern struct kernel_cpustat kernel_cpustat __ksym;


static inline int task_nice(const struct task_struct *p)
{
	return PRIO_TO_NICE((p)->static_prio);
}


SEC("kprobe/account_process_tick")
int BPF_KPROBE(kprobe_account_process_tick, struct task_struct *p, u64 cputime)
{
    u64 tid = bpf_get_current_pid_tgid();
    int cpu = bpf_get_smp_processor_id();
    // struct cpu_stat stat = {};

    struct kernel_cpustat* ptr;
    ptr = bpf_this_cpu_ptr(&kernel_cpustat);

    struct kernel_cpustat stat = {};
    bpf_probe_read_kernel(&stat, sizeof(stat), ptr);

    bpf_printk("user:%lld nice:%lld system:%lld", stat.cpustat[0], stat.cpustat[1], stat.cpustat[2]);

    // if (task_nice(p) > 0) {
    //     stat.nice += cputime;
    //     stat.guest_nice += cputime;
    // } else {
    //     stat.user += cputime;
    //     stat.guest += cputime;
    // }

    return 0;
}


// SEC("kprobe/account_steal_time")
// int BPF_KPROBE(kprobe_account_steal_time,  u64 cputime)
// {
//     u64 tid = bpf_get_current_pid_tgid();
//     int cpu = bpf_get_smp_processor_id();
//     struct cpu_stat stat = {};

//     stat.steal += cputime;
//     return 0;
// }

// extern struct rq runqueues __ksym;

// SEC("kprobe/account_idle_time")
// int BPF_KPROBE(kprobe_account_idle_time,  u64 cputime)
// {
//     u64 tid = bpf_get_current_pid_tgid();
//     int cpu = bpf_get_smp_processor_id();
//     struct cpu_stat stat = {};

//     // struct rq *rq;
//     // rq = scx_bpf_cpu_rq(cpu);
//     // bpf_this_cpu_ptr(&runqueues);

//     // int tmp = __sync_val_compare_and_swap(&rq->nr_iowait, );
//     if (1) {
//         stat.iowait += cputime;
//     } else {
//         stat.idle += cputime;
//     }
//     stat.steal += cputime;
//     return 0;
// }

// SEC("kprobe/account_user_time")
// int BPF_KPROBE(kprobe_account_user_time, struct task_struct *p, u64 cputime)
// {
//     u64 tid = bpf_get_current_pid_tgid();
//     int cpu = bpf_get_smp_processor_id();
//     struct cpu_stat stat = {};

//     if(task_nice(p) > 0) {
//         stat.nice += cputime;
//     } else {
//         stat.user += cputime;
//     }
//     return 0;
// }

// SEC("kprobe/account_system_index_time")
// int BPF_KPROBE(kprobe_account_system_index_time, struct task_struct *p, u64 cputime, enum cpu_usage_stat index)
// {
//     u64 tid = bpf_get_current_pid_tgid();
//     int cpu = bpf_get_smp_processor_id();
//     struct cpu_stat stat = {};

//     switch(index)
//     {
//         case CPUTIME_SYSTEM:
//             stat.system += cputime;
//             break;
//         case CPUTIME_SOFTIRQ:
//             stat.irq += cputime;
//             break;
//         case CPUTIME_IRQ:
//             stat.irq += cputime;
//             break;
//         default:
//             bpf_printk("invalid index: %d", index);
//             return 0;
//     }
    
//     return 0;
// }

