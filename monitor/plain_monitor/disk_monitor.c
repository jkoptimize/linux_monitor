#include "disk_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysinfo.h>
#include <ctype.h>

#define MAX_DISKS 64
#define SECTOR_SIZE 512  // 通常扇区大小为512字节

// 判断是否为ram/loop设备
static int is_ram_or_loop_device(const char *disk_name) {
    return (strncmp(disk_name, "ram", 3) == 0) || 
           (strncmp(disk_name, "loop", 4) == 0);
}

// 解析一行diskstats数据
static int parse_diskstats_line(const char *line, DiskStats *stats) {
    int fields_parsed = sscanf(line, 
        "%*d %*d %31s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
        stats->name,
        &stats->reads_completed,
        &stats->reads_merged,
        &stats->sectors_read,
        &stats->time_reading_ms,
        &stats->writes_completed,
        &stats->writes_merged,
        &stats->sectors_written,
        &stats->time_writing_ms,
        &stats->ios_in_progress,
        &stats->time_io_ms,
        &stats->weighted_time_io_ms);
    
    return (fields_parsed == 12);  // 应该解析出12个字段
}

// 读取diskstats文件
int get_diskstats(DiskStats *stats, int max_count) {
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) {
        perror("Failed to open /proc/diskstats");
        return -1;
    }
    
    char line[512];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp) && count < max_count) {
        DiskStats disk;
        memset(&disk, 0, sizeof(disk));
        
        if (parse_diskstats_line(line, &disk)) {
            // 过滤掉ram和loop设备
            if (!is_ram_or_loop_device(disk.name)) {
                stats[count] = disk;
                count++;
            }
        }
    }
    
    fclose(fp);
    return count;
}

// 计算磁盘性能指标
void calculate_disk_metrics(DiskStats *current, const DiskStats *previous, double time_interval_sec) {
    if (time_interval_sec <= 0) return;
    
    // 计算增量
    unsigned long reads_delta = current->reads_completed - previous->reads_completed;
    unsigned long writes_delta = current->writes_completed - previous->writes_completed;
    unsigned long sectors_read_delta = current->sectors_read - previous->sectors_read;
    unsigned long sectors_written_delta = current->sectors_written - previous->sectors_written;
    unsigned long read_time_delta = current->time_reading_ms - previous->time_reading_ms;
    unsigned long write_time_delta = current->time_writing_ms - previous->time_writing_ms;
    
    // 计算吞吐量 (MB/s)
    current->read_throughput_mb = (sectors_read_delta * SECTOR_SIZE) / 
                                 (1024.0 * 1024.0 * time_interval_sec);
    current->write_throughput_mb = (sectors_written_delta * SECTOR_SIZE) / 
                                  (1024.0 * 1024.0 * time_interval_sec);
    current->total_throughput_mb = current->read_throughput_mb + current->write_throughput_mb;
    
    // 计算IOPS
    current->read_iops = reads_delta / time_interval_sec;
    current->write_iops = writes_delta / time_interval_sec;
    current->total_iops = current->read_iops + current->write_iops;
    
    // 计算平均时延(ms)
    current->avg_read_latency_ms = (reads_delta > 0) ? 
        (double)read_time_delta / reads_delta : 0.0;
    current->avg_write_latency_ms = (writes_delta > 0) ? 
        (double)write_time_delta / writes_delta : 0.0;
    
    // 计算磁盘利用率(%)
    unsigned long io_time_delta = current->weighted_time_io_ms - previous->weighted_time_io_ms;
    current->utilization = (io_time_delta / 10.0) / time_interval_sec;
    if (current->utilization > 100.0) current->utilization = 100.0;
}