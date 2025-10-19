#ifndef DISK_MONITOR_H
#define DISK_MONITOR_H

#include <stdint.h>

// 磁盘统计数据结构
typedef struct {
    char name[32];          // 磁盘名称
    unsigned long reads_completed;      // 读完成次数
    unsigned long reads_merged;         // 读合并次数  
    unsigned long sectors_read;         // 读扇区数
    unsigned long time_reading_ms;      // 读花费时间(ms)
    unsigned long writes_completed;     // 写完成次数
    unsigned long writes_merged;        // 写合并次数
    unsigned long sectors_written;      // 写扇区数
    unsigned long time_writing_ms;      // 写花费时间(ms)
    unsigned long ios_in_progress;      // 正在进行的IO数
    unsigned long time_io_ms;           // IO花费时间(ms)
    unsigned long weighted_time_io_ms;  // 加权IO花费时间(ms)
    
    // 计算得出的指标
    double read_throughput_mb;    // 读吞吐量 MB/s
    double write_throughput_mb;   // 写吞吐量 MB/s
    double total_throughput_mb;   // 总吞吐量 MB/s
    double read_iops;             // 读IOPS
    double write_iops;            // 写IOPS
    double total_iops;            // 总IOPS
    double avg_read_latency_ms;   // 平均读时延(ms)
    double avg_write_latency_ms;  // 平均写时延(ms)
    double utilization;           // 磁盘利用率(%)
} DiskStats;

// 获取磁盘统计信息的接口
int get_diskstats(DiskStats *stats, int max_count);

// 计算磁盘性能指标的接口
void calculate_disk_metrics(DiskStats *current, const DiskStats *previous, double time_interval_sec);

#endif // DISK_MONITOR_H