#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "cpu_stat_monitor.skel.h"  

struct kernel_cpustat {
    unsigned long long cpustat[10];
};
static struct cpu_stat_monitor_bpf *skel;
static int cpustats_map_fd = 0;

int init_cpu_stat_monitor() 
{
    int err, map_fd;
    int key = 0;

    // 打开BPF程序
    skel = cpu_stat_monitor_bpf__open();
    if (!skel) {
        // fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    // 加载BPF程序
    err = cpu_stat_monitor_bpf__load(skel);
    if (err) {
        // fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // 附加BPF程序
    err = cpu_stat_monitor_bpf__attach(skel);
    if (err) {
        // fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
cleanup:
    cpu_stat_monitor_bpf__destroy(skel);
    return err;
}

int get_cpustats_map_fd()
{
    cpustats_map_fd = bpf_map__fd(skel->maps.cpu_stats);
    return cpustats_map_fd;
}