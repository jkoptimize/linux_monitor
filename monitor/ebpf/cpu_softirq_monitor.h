#ifndef __CPU_SOFTIRQ_MONITOR_H
#define __CPU_SOFTIRQ_MONITOR_H

typedef unsigned int __u32;
typedef __u32 u32;
typedef long long unsigned int __u64;
typedef __u64 u64;

// 用于存储软中断开始时间的数据结构
struct softirq_key {
    u32 cpu;
    u32 vec;
};

// 用于存储统计信息的数据结构
struct softirq_stat {
    u64 count;
    u64 total_time_ns;
    u64 max_time_ns;
};

// 软中断类型数量
#endif  // __CPU_SOFTIRQ_MONITOR_H
