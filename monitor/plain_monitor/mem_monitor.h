#ifndef MEM_MONITOR_H
#define MEM_MONITOR_H

#include <stdint.h>

// 内存信息数据结构
typedef struct {
    unsigned long mem_total;       // MemTotal
    unsigned long mem_free;        // MemFree
    unsigned long mem_available;   // MemAvailable
    unsigned long buffers;         // Buffers
    unsigned long cached;          // Cached
    unsigned long swap_total;      // SwapTotal
    unsigned long swap_free;       // SwapFree
} MemInfo;

// 获取内存信息的接口
int get_meminfo(MemInfo *info);

#endif // MEM_MONITOR_H