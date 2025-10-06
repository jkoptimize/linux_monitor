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
}

// 获取内核符号地址
unsigned long get_kernel_symbol(const char *name) {
    FILE *f;
    unsigned long addr;
    char sym[512], type;
    
    f = fopen("/proc/kallsyms", "r");
    if (!f) {
        fprintf(stderr, "Failed to open /proc/kallsyms\n");
        return 0;
    }
    
    while (fscanf(f, "%lx %c %s", &addr, &type, sym) == 3) {
        if (strcmp(sym, name) == 0) {
            fclose(f);
            printf("Found symbol %s at address 0x%lx (type: %c)\n", name, addr, type);
            return addr;
        }
    }
    
    fclose(f);
    fprintf(stderr, "Symbol %s not found\n", name);
    return 0;
}

int main(int argc, char **argv) {
    struct cpu_stat_monitor_bpf *skel;
    int err, map_fd;
    int key = 0;
    unsigned long kcpustat_addr;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 获取内核符号地址
    kcpustat_addr = get_kernel_symbol("kernel_cpustat");
    if (!kcpustat_addr) {
        fprintf(stderr, "Failed to get kernel_cpustat address\n");
        return 1;
    }
    
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

        
    // 在加载前设置符号地址
    map_fd = bpf_map__fd(skel->maps.kcpustat_addr_map);
    // printf("Debug: Map FD = %d\n", map_fd);

    if (bpf_map_update_elem(map_fd, &key, &kcpustat_addr, BPF_ANY) != 0) {
        if (err != 0) {
            fprintf(stderr, "Error: Failed to update map. errno=%d (%s)\n", errno, strerror(errno));
            fprintf(stderr, "Error: bpf_map_update_elem returned: %d\n", err);
            goto cleanup;
        }
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
        
        // 读取并打印统计信息
        int num_cpus = libbpf_num_possible_cpus();
        struct kernel_cpustat *stats = calloc(num_cpus, sizeof(struct kernel_cpustat));
        if (!stats) continue;
        
        if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.cpu_stats_map), &key, stats) == 0) {
            for (int i = 0; i < num_cpus && i < 4; i++) { // 只显示前4个CPU
                printf("CPU%d: user=%llu nice=%llu system=%llu idle=%llu iowait=%llu\n",
                       i, stats[i].cpustat[0], stats[i].cpustat[1], 
                       stats[i].cpustat[2], stats[i].cpustat[3], stats[i].cpustat[4]);
            }
            printf("---\n");
        }
        
        free(stats);
    }
    
cleanup:
    cpu_stat_monitor_bpf__destroy(skel);
    return err;
}