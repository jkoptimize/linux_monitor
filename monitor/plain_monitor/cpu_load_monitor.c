#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#define INTERVAL 5  // 5秒刷新间隔

// 定义负载数据结构
typedef struct {
    double load_1min;       // 1分钟系统平均负载
    double load_5min;       // 5分钟系统平均负载
    double load_15min;      // 15分钟系统平均负载
    int cpu_count;          // CPU核心数量
    double load_1min_per_core; // 每个核心的1分钟平均负载
    double load_5min_per_core; // 每个核心的5分钟平均负载
    double load_15min_per_core; // 每个核心的15分钟平均负载
} LoadAvgData;

// 从/proc/loadavg解析平均负载
int parse_loadavg(const char *line, LoadAvgData *data) {
    // 格式: "1.23 4.56 7.89 1/123 45678"
    // 我们只需要前三个浮点数
    int result = sscanf(line, "%lf %lf %lf", 
                       &data->load_1min, 
                       &data->load_5min, 
                       &data->load_15min);
    
    if (result != 3) {
        fprintf(stderr, "Error parsing loadavg: %s\n", line);
        return -1;
    }
    return 0;
}


// 获取并计算负载数据
void get_loadavg(LoadAvgData *data) {
    FILE *fp = fopen("/proc/loadavg", "r");
    if (!fp) {
        perror("Failed to open /proc/loadavg");
        exit(1);
    }

    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        fprintf(stderr, "Failed to read /proc/loadavg\n");
        exit(1);
    }
    fclose(fp);

    // 解析系统平均负载
    if (parse_loadavg(line, data) != 0) {
        exit(1);
    }
}

// 打印负载数据
void print_loadavg(const LoadAvgData *data) {
    printf("System Load Average:\n");
    printf("  1min:  %8.2f (system)\n", data->load_1min);
    printf("  5min:  %8.2f (system)\n", data->load_5min);
    printf("  15min: %8.2f (system)\n", data->load_15min);
}

int main() {
    LoadAvgData load_data;
    time_t last_print = time(NULL);
    
    printf("Load average statistics (refresh every %d seconds):\n", INTERVAL);
    printf("===========================================\n");
    
    while (1) {
        time_t current = time(NULL);
        if (difftime(current, last_print) >= INTERVAL) {
            last_print = current;
            
            get_loadavg(&load_data);
            printf("\n[%s] Load Average:\n", ctime(&current));
            print_loadavg(&load_data);
        }
        
        // 短暂休眠以减少CPU占用
        usleep(500000); // 500ms
    }
    
    return 0;
}