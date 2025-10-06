#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


// 存储内核符号地址
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, unsigned long);
} kcpustat_addr_map SEC(".maps");

// 存储统计结果
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct kernel_cpustat);
} cpu_stats_map SEC(".maps");

extern struct kernel_cpustat kernel_cpustat __ksym;

SEC("kprobe/account_process_tick")
int BPF_KPROBE(account_process_tick_probe)
{
    int key = 0;
    unsigned long *kcpustat_addr;


    kcpustat_addr = bpf_this_cpu_ptr(&kernel_cpustat);

    // 获取内核符号地址
    kcpustat_addr = bpf_map_lookup_elem(&kcpustat_addr_map, &key);
    if (!kcpustat_addr || *kcpustat_addr == 0) {
        bpf_printk("kcpustat_addr not set\n");
        return 0;
    }
    bpf_printk("kcpustat_addr: %lx\n", *kcpustat_addr);

    struct kernel_cpustat stats = {};
    long ret = bpf_probe_read_kernel(&stats, sizeof(stats), (void *)(*kcpustat_addr));
    if (ret < 0) {
        bpf_printk("Failed to read kernel_cpustat at %lx: %ld\n", *kcpustat_addr, ret);
        return 0;
    }
    bpf_printk("Read cpustat: user=%llu, nic=%llu, system=%llu, idle=%llu iowait=%llu\n",
               stats.cpustat[0], stats.cpustat[1], stats.cpustat[2], stats.cpustat[3], stats.cpustat[4]);


    // // 获取当前CPU的存储位置
    // stats = bpf_map_lookup_elem(&cpu_stats_map, &key);
    // if (!stats) {
    //     return 0;
    // }

    // // 计算当前CPU的偏移量
    // // 对于x86架构，per-CPU偏移通常是固定的
    // int cpu_id = bpf_get_smp_processor_id();
    // unsigned long per_cpu_offset = cpu_id * 8192; // 典型的per-CPU区域大小
    
    // // 计算当前CPU的kernel_cpustat地址
    // unsigned long current_cpu_addr = *kcpustat_addr + per_cpu_offset;
    
    // // 读取当前CPU的统计信息
    // struct kernel_cpustat *current_stats = (struct kernel_cpustat *)current_cpu_addr;
    // bpf_probe_read_kernel(stats, sizeof(struct kernel_cpustat), current_stats);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";