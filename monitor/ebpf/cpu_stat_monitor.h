// bootstrap.h
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H
#define MAX_CPU 128

typedef unsigned int __u32;
typedef __u32 u32;
typedef long long unsigned int __u64;
typedef __u64 u64;

struct cpu_stat {
    u64 online;
    u64 user;
    u64 nice;
    u64 system;
    u64 idle;
    u64 iowait;
    u64 irq;
    u64 softirq;
    u64 steal;
    u64 guest;
    u64 guest_nice;
};

int init_cpu_stat_monitor();
int get_cpustats_map_fd();

#endif /* __BOOTSTRAP_H */