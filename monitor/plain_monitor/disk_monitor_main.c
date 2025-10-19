#include "disk_monitor.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define MAX_DISKS 64

int main() {
    DiskStats current[MAX_DISKS];
    DiskStats previous[MAX_DISKS];
    int disk_count;
    double interval_sec = 2.0; // 2秒间隔

    printf("开始监控磁盘性能...\n");
    printf("按Ctrl+C停止\n");
    printf("================================\n");

    // 获取初始状态
    disk_count = get_diskstats(current, MAX_DISKS);
    if (disk_count <= 0) {
        fprintf(stderr, "无法获取磁盘统计信息\n");
        return 1;
    }
    
    // 保存初始状态为上一次状态
    memcpy(previous, current, disk_count * sizeof(DiskStats));

    while (1) {
        sleep(interval_sec);
        
        // 获取当前状态
        disk_count = get_diskstats(current, MAX_DISKS);
        if (disk_count <= 0) {
            fprintf(stderr, "无法获取磁盘统计信息\n");
            continue;
        }
        
        // 计算指标
        for (int i = 0; i < disk_count; i++) {
            calculate_disk_metrics(&current[i], &previous[i], interval_sec);
        }
        
        // 打印结果
        printf("\n=== 磁盘性能统计 (%.1f秒) ===\n", interval_sec);
        printf("%-8s %8s %8s %8s %8s %8s %8s %8s\n", 
               "设备", "读吞吐", "写吞吐", "总吞吐", "读IOPS", "写IOPS", "读时延", "写时延");
        printf("%-8s %8s %8s %8s %8s %8s %8s %8s\n", 
               "", "(MB/s)", "(MB/s)", "(MB/s)", "(ops/s)", "(ops/s)", "(ms)", "(ms)");
        printf("------------------------------------------------------------------------\n");
        
        for (int i = 0; i < disk_count; i++) {
            printf("%-8s %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f\n",
                   current[i].name,
                   current[i].read_throughput_mb,
                   current[i].write_throughput_mb, 
                   current[i].total_throughput_mb,
                   current[i].read_iops,
                   current[i].write_iops,
                   current[i].avg_read_latency_ms,
                   current[i].avg_write_latency_ms);
        }
        
        // 更新上一次状态
        memcpy(previous, current, disk_count * sizeof(DiskStats));
    }
    
    return 0;
}