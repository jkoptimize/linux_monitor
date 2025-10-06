// cpu_usage.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "cpu_stat_monitor.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct stats);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

// 当前运行任务开始时间
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
} start_time SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int trace_cpu_time(struct trace_event_raw_sched_switch *ctx)
{
    #define PF_KTHREAD		0x00200000	
    u32 zero = 0;
    u64 ts = bpf_ktime_get_ns();
    u32 cpu = bpf_get_smp_processor_id();
    u64 *p_start = bpf_map_lookup_elem(&start_time, &zero);
    struct task_struct *prev = (struct task_struct *)ctx->prev_comm;
    struct task_struct *next = (struct task_struct *)ctx->next_comm;

    if (p_start) {
        u64 delta = ts - *p_start;
        struct stats *data = bpf_map_lookup_elem(&stats_map, &zero);
        if (data && cpu < MAX_CPU) {
            if (BPF_CORE_READ(prev, flags) & PF_KTHREAD) {
                data->cpus[cpu].system += delta;
            } else {
                data->cpus[cpu].user += delta;
            }
            bpf_printk("CPU %d switch out task %s (pid: %d), delta: %llu ns\n",
                       cpu, ctx->prev_comm, ctx->prev_pid, delta);
        } else {
            bpf_printk("data is NULL or cpu id %d out of range\n", cpu);
            return 0;
        }
    }

    // 下一个任务开始时间
    bpf_map_update_elem(&start_time, &zero, &ts, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";