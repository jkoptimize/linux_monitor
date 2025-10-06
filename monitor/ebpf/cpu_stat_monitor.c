// bootstrap.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "cpu_stat_monitor.h"
#include "cpu_stat_monitor.skel.h"  // 自动生成

static int exit_flag = 0;
// static struct cpu_stat last_cpu[MAX_CPU];
// static int cpu_count = 0;

void sig_int(int signo) {
    exit_flag = 1;
}

// 简单计算两个时间之间的差值并打印利用率
void print_cpu_diff(struct cpu_stat *curr, struct cpu_stat *prev, int cpu_id, double elapsed_ms) {
    #define DIFF(field) (curr->field - prev->field)
    long long total = DIFF(user) + DIFF(system) + DIFF(idle) + DIFF(iowait) + DIFF(steal);
    if (total == 0) {
        printf("CPU%-3d: No activity detected.\n", cpu_id);
        return;
    }

    double user = ((double)DIFF(user)) / total * 100;
    double system = ((double)DIFF(system)) / total * 100;
    double idle = ((double)DIFF(idle)) / total * 100;
    double iowait = ((double)DIFF(iowait)) / total * 100;
    double steal = ((double)DIFF(steal)) / total * 100;

    printf("CPU%-3d: User %.1f%% | System %.1f%% | Idle %.1f%% | IOWait %.1f%% | Steal %.1f%%\n",
           cpu_id, user, system, idle, iowait, steal);

        printf("CPU%-3d: User %lld | System %lld | Idle %lld | IOWait %lld | Steal %lld\n",
           cpu_id, curr->user, curr->system, curr->idle, curr->iowait, curr->steal);
}

int main(int argc, char **argv) {
    struct cpu_stat_monitor_bpf *skel;
    int err;
    struct stats prev_stat = {};
    unsigned long zero = 0;

    signal(SIGINT, sig_int);

    // 打开并加载 BPF 程序
    skel = cpu_stat_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = cpu_stat_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        goto cleanup;
    }

    err = cpu_stat_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    printf("Monitoring CPU usage... Press Ctrl+C to exit.\n");

    while (!exit_flag) {
        sleep(2);
        unsigned long cpu_count = libbpf_num_possible_cpus();
        struct stats curr_stat = {};
        int map_fd = bpf_map__fd(skel->maps.stats_map);
        
        if (bpf_map_lookup_elem(map_fd, &zero, &curr_stat) == 0) {
            for (int i = 0; i < cpu_count; i++) {
                print_cpu_diff(&curr_stat.cpus[i], &prev_stat.cpus[i], i, 2000.0);
            }
        } else {
            printf("Failed to read stats_map\n");
        }
        prev_stat = curr_stat;
        printf("\n");
    }

cleanup:
    cpu_stat_monitor_bpf__destroy(skel);
    return err;
}