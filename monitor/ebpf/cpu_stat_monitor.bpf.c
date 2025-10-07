// #include <linux/types.h>
// #include <bpf/bpf.h>
// #include "bpf/bpf_helpers.h"
// #include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";


enum cpu_usage_stat {
	CPUTIME_USER,
	CPUTIME_NICE,
	CPUTIME_SYSTEM,
	CPUTIME_SOFTIRQ,
	CPUTIME_IRQ,
	CPUTIME_IDLE,
	CPUTIME_IOWAIT,
	CPUTIME_STEAL,
	CPUTIME_GUEST,
	CPUTIME_GUEST_NICE,
	NR_STATS,
};

struct kernel_cpustat {
	unsigned long long cpustat[NR_STATS];
};


SEC("fexit/kcpustat_cpu_fetch")
int BPF_PROG(fexit_kcpustat_cpu_fetch, struct kernel_cpustat *kcpustat, int cpu) {
  return 0;
}

// // 定义 cpu_stat 结构体（必须与内核匹配，但不使用 CO-RE）
// struct cpu_stat {
//     __u64 user;
//     __u64 nice;
//     __u64 sys;
//     __u64 idle;
//     __u64 iowait;
//     __u64 irq;
//     __u64 softirq;
//     __u64 steal;
//     __u64 guest;
//     __u64 guest_nice;
// };

// // 定义 kernel_cpustat 结构体（必须与内核匹配，但不使用 CO-RE）
// // 注意：这是关键！必须根据您的内核版本定义
// struct kernel_cpustat {
//     unsigned long cpustat[1024][1024]; // 假设 NR_CPUS=1024
//     // 实际需要根据您的内核版本精确定义
//     // 例如：在 5.15 内核中，cpustat 是 [NR_CPUS][NR_CPUS]
// };

// // BPF 映射定义
// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __uint(max_entries, 8192);
//   __type(key, pid_t);
//   __type(value, u64);
// } exec_start SEC(".maps");

// struct {
//   __uint(type, BPF_MAP_TYPE_RINGBUF);
//   __uint(max_entries, 256 * 1024);
// } rb SEC(".maps");

// // 常量定义（必须在 BPF 程序中定义）
// #define CPUTIME_USER 0
// #define CPUTIME_NICE 1
// #define CPUTIME_SYSTEM 2
// #define CPUTIME_IDLE 3
// #define CPUTIME_IOWAIT 4
// #define CPUTIME_IRQ 5
// #define CPUTIME_SOFTIRQ 6
// #define CPUTIME_STEAL 7
// #define CPUTIME_GUEST 8
// #define CPUTIME_GUEST_NICE 9

// // 必须使用 bpf_probe_read 读取内核数据
// SEC("fexit/kcpustat_cpu_fetch")
// int BPF_PROG(fexit_kcpustat_cpu_fetch, struct kernel_cpustat *kcpustat,
//              int cpu) {
//   struct cpu_stat *stat;

//   stat = bpf_ringbuf_reserve(&rb, sizeof(*stat), 0);
//   if (!stat)
//     return 0;

//   // 使用 bpf_probe_read 读取每个字段（关键！）
//   bpf_probe_read(&stat->user, sizeof(stat->user), 
//                  &kcpustat->cpustat[CPUTIME_USER][0]);
//   bpf_probe_read(&stat->nice, sizeof(stat->nice), 
//                  &kcpustat->cpustat[CPUTIME_NICE][0]);
//   bpf_probe_read(&stat->sys, sizeof(stat->sys), 
//                  &kcpustat->cpustat[CPUTIME_SYSTEM][0]);
//   bpf_probe_read(&stat->idle, sizeof(stat->idle), 
//                  &kcpustat->cpustat[CPUTIME_IDLE][0]);
//   bpf_probe_read(&stat->iowait, sizeof(stat->iowait), 
//                  &kcpustat->cpustat[CPUTIME_IOWAIT][0]);
//   bpf_probe_read(&stat->irq, sizeof(stat->irq), 
//                  &kcpustat->cpustat[CPUTIME_IRQ][0]);
//   bpf_probe_read(&stat->softirq, sizeof(stat->softirq), 
//                  &kcpustat->cpustat[CPUTIME_SOFTIRQ][0]);
//   bpf_probe_read(&stat->steal, sizeof(stat->steal), 
//                  &kcpustat->cpustat[CPUTIME_STEAL][0]);
//   bpf_probe_read(&stat->guest, sizeof(stat->guest), 
//                  &kcpustat->cpustat[CPUTIME_GUEST][0]);
//   bpf_probe_read(&stat->guest_nice, sizeof(stat->guest_nice), 
//                  &kcpustat->cpustat[CPUTIME_GUEST_NICE][0]);

//   bpf_ringbuf_submit(stat, 0);
//   return 0;
// }