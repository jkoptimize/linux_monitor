#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 自定义事件数据结构
struct event {
    u32 pid;
    u32 tid;
    u64 timestamp;
    u64 latency;
    char comm[TASK_COMM_LEN];
    u32 cpu_id;
};

// eBPF映射定义
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);    // pid
    __type(value, u64);  // timestamp
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} counters SEC(".maps");

// 跟踪点：进程唤醒
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

// 跟踪点：进程切换
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    u32 prev_pid = BPF_CORE_READ(prev, pid);
    u32 next_pid = BPF_CORE_READ(next, pid);
    
    // 获取上一个任务的唤醒时间
    u64 *wake_ts = bpf_map_lookup_elem(&start, &prev_pid);
    if (wake_ts) {
        u64 now = bpf_ktime_get_ns();
        u64 latency = now - *wake_ts;
        
        // 只记录合理的延迟
        if (latency < 1000000000) { // 1秒
            struct event e = {};
            e.pid = prev_pid;
            e.tid = prev_pid; // 简化处理
            e.timestamp = now;
            e.latency = latency;
            e.cpu_id = bpf_get_smp_processor_id();
            BPF_CORE_READ_STR_INTO(&e.comm, prev, comm);
            
            // 发送事件到用户空间
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                                 &e, sizeof(e));
        }
        
        bpf_map_delete_elem(&start, &prev_pid);
    }
    
    return 0;
}