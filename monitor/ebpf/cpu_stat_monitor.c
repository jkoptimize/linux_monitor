#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "cpu_stat_monitor.skel.h"  

struct kernel_cpustat {
    unsigned long long cpustat[10];
};

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}// 获取内核符号地址

int main(int argc, char **argv) {
    struct cpu_stat_monitor_bpf *skel;
    int err, map_fd;
    int key = 0;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 打开BPF程序
    skel = cpu_stat_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    // 加载BPF程序
    err = cpu_stat_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 附加BPF程序
    err = cpu_stat_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    printf("Successfully started! Press Ctrl-C to stop.\n");
    
    // 主循环 - 定期读取并打印统计信息
    while (!exiting) {
        sleep(1);
    }
    
cleanup:
    cpu_stat_monitor_bpf__destroy(skel);
    return err;
}