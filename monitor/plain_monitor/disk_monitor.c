#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>

#define MAX_DISKS 64
#define SECTOR_SIZE 512  // 通常扇区大小为512字节

// 磁盘统计数据结构
struct disk_stats {
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
};

// 全局变量存储前后两次统计
struct disk_stats current_stats[MAX_DISKS];
struct disk_stats previous_stats[MAX_DISKS];
int disk_count = 0;

// 判断是否为ram/loop设备
int is_ram_or_loop_device(const char *disk_name) {
    return (strncmp(disk_name, "ram", 3) == 0) || 
           (strncmp(disk_name, "loop", 4) == 0);
}

// 解析一行diskstats数据
int parse_diskstats_line(const char *line, struct disk_stats *stats) {
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
int read_diskstats(struct disk_stats stats[]) {
    FILE *fp = fopen("/proc/diskstats", "r");
    if (!fp) {
        perror("Failed to open /proc/diskstats");
        return -1;
    }
    
    char line[512];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp) && count < MAX_DISKS) {
        struct disk_stats disk;
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
void calculate_disk_metrics(struct disk_stats *current, struct disk_stats *previous, 
                           double time_interval_sec) {
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
    // weighted_time_io_ms 是毫秒，转换为秒并计算在时间间隔内的占比
    unsigned long io_time_delta = current->weighted_time_io_ms - previous->weighted_time_io_ms;
    current->utilization = (io_time_delta / 10.0) / time_interval_sec;  // 转换为百分比
    if (current->utilization > 100.0) current->utilization = 100.0;
}

// 打印磁盘统计信息
void print_disk_stats(const struct disk_stats stats[], int count) {
    printf("\n=== 磁盘性能统计 ===\n");
    printf("%-8s %8s %8s %8s %8s %8s %8s %8s\n", 
           "设备", "读吞吐", "写吞吐", "总吞吐", "读IOPS", "写IOPS", "读时延", "写时延");
    printf("%-8s %8s %8s %8s %8s %8s %8s %8s\n", 
           "", "(MB/s)", "(MB/s)", "(MB/s)", "(ops/s)", "(ops/s)", "(ms)", "(ms)");
    printf("------------------------------------------------------------------------\n");
    
    for (int i = 0; i < count; i++) {
        const struct disk_stats *disk = &stats[i];
        printf("%-8s %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f %8.2f\n",
               disk->name,
               disk->read_throughput_mb,
               disk->write_throughput_mb, 
               disk->total_throughput_mb,
               disk->read_iops,
               disk->write_iops,
               disk->avg_read_latency_ms,
               disk->avg_write_latency_ms);
    }
    
    // 打印详细统计
    // printf("\n=== 详细统计信息 ===\n");
    // for (int i = 0; i < count; i++) {
    //     const struct disk_stats *disk = &stats[i];
    //     printf("\n设备: %s\n", disk->name);
    //     printf("  利用率: %.1f%%\n", disk->utilization);
    //     printf("  正在进行IO数: %lu\n", disk->ios_in_progress);
    //     printf("  读合并次数: %lu\n", disk->reads_merged);
    //     printf("  写合并次数: %lu\n", disk->writes_merged);
    // }
}


int main(int argc, char *argv[]) {
    int interval = 2;  // 默认采样间隔1秒
    const char *output_file = NULL;
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0) {
            printf("用法: %s [-i 间隔秒数] [-n 采样次数] [-o 输出文件]\n", argv[0]);
            return 0;
        }
    }
    
    printf("开始监控磁盘统计信息...\n");
    
    while (1) {
        sleep(interval);
        
        // 读取当前状态
        disk_count = read_diskstats(current_stats);
        if (disk_count <= 0) {
            fprintf(stderr, "读取磁盘统计信息失败\n");
            return 1;
        }
        
        // 计算性能指标
        for (int i = 0; i < disk_count; i++) {
            calculate_disk_metrics(&current_stats[i], &previous_stats[i], interval);
        }
        
        // 打印结果
        print_disk_stats(current_stats, disk_count);
        
        
        // 更新前一次的状态
        memcpy(previous_stats, current_stats, sizeof(previous_stats));
    }
    
    return 0;
}