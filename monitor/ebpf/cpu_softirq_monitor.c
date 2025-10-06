// softirq_user.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "cpu_softirq_monitor.h"
#include "cpu_softirq_monitor.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

// 软中断类型名称（与内核定义保持一致）
static const char *softirq_vec_names[10] = {
    "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", 
    "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU"
};

int main(int argc, char **argv)
{
    struct cpu_softirq_monitor_bpf *skel;
    int err;

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 增加 RLIMIT_MEMLOCK 限制
    struct rlimit rlim = {
        .rlim_cur = 100UL << 20, // 100 MB
        .rlim_max = 100UL << 20,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    // 打开和加载 eBPF 程序
    skel = cpu_softirq_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 eBPF 程序
    err = cpu_softirq_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("\n");
	printf("eBPF softirq monitor started, Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
    printf("%-12s %-8s %-12s %-12s %-12s\n", 
           "SOFTIRQ", "COUNT", "TOTAL_TIME(ms)", "AVG_TIME(us)", "MAX_TIME(us)");

    // 主循环：定期显示统计信息
    while (!exiting) {
        sleep(2); // 2秒间隔
        
        printf("\n%-12s %-8s %-12s %-12s %-12s\n", 
               "SOFTIRQ", "COUNT", "TOTAL_TIME(ms)", "AVG_TIME(us)", "MAX_TIME(us)");
        
        // 遍历所有软中断类型
        for (int vec = 0; vec < 10; vec++) {
            struct softirq_stat stat;
            int map_fd = bpf_map__fd(skel->maps.softirq_stats);
            
            if (bpf_map_lookup_elem(map_fd, &vec, &stat) == 0) {
                if (stat.count > 0) {
                    double total_ms = (double)stat.total_time_ns / 1000000.0;
                    double avg_us = (double)stat.total_time_ns / stat.count / 1000.0;
                    double max_us = (double)stat.max_time_ns / 1000.0;
                    
                    printf("%-12s %-8llu %-12.2f %-12.2f %-12.2f\n",
                           softirq_vec_names[vec], stat.count, 
                           total_ms, avg_us, max_us);
                }
            }
        }
    }

cleanup:
    // 清理资源
    cpu_softirq_monitor_bpf__destroy(skel);
    return 0;
}