#ifndef CPU_LOAD_MONITOR_H
#define CPU_LOAD_MONITOR_H

#include <stdint.h>

// 负载数据结构
typedef struct {
    double load_1min;       // 1分钟系统平均负载
    double load_5min;       // 5分钟系统平均负载
    double load_15min;      // 15分钟系统平均负载
    int cpu_count;          // CPU核心数量
    double load_1min_per_core; // 每个核心的1分钟平均负载
    double load_5min_per_core; // 每个核心的5分钟平均负载
    double load_15min_per_core; // 每个核心的15分钟平均负载
} LoadAvgData;

// 获取系统负载数据的接口
void get_loadavg_data(LoadAvgData *data);

#endif // CPU_LOAD_MONITOR_H