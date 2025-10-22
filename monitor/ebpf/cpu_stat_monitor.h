// bootstrap.h
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define MAX_CPU 128

struct cpu_stat {
    long long user;
    long long nice;
    long long system;
    long long idle;
    long long iowait;
    long long irq;
    long long softirq;
    long long steal;
    long long guest;
    long long guest_nice;
};

int init_cpu_stat_monitor();
int get_cpustats_map_fd();

#endif /* __BOOTSTRAP_H */