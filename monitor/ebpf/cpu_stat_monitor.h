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
};

struct stats {
    struct cpu_stat cpus[MAX_CPU];
    int cpu_count;
};

#endif /* __BOOTSTRAP_H */