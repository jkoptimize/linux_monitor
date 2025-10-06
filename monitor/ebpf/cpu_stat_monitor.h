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

// struct stats {
//     struct cpu_stat cpu;
//     int cpu_id;
// };

#endif /* __BOOTSTRAP_H */