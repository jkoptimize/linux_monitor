#include "cpu_load_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <ctype.h>

// 从/proc/loadavg解析平均负载
static int parse_loadavg(const char *line, LoadAvgData *data) {
    // 格式: "1.23 4.56 7.89 1/123 45678"
    // 我们只需要前三个浮点数
    int result = sscanf(line, "%lf %lf %lf", 
                       &data->load_1min, 
                       &data->load_5min, 
                       &data->load_15min);
    
    if (result != 3) {
        return -1;
    }
    return 0;
}

// 获取并计算负载数据
void get_loadavg_data(LoadAvgData *data) {
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

    // 获取CPU核心数
    data->cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (data->cpu_count <= 0) {
        data->cpu_count = 1; // 保守默认值
    }
    // printf("cpu num: %d", data->cpu_count);

    // 计算每核心的负载
    data->load_1min_per_core = data->load_1min / data->cpu_count;
    data->load_5min_per_core = data->load_5min / data->cpu_count;
    data->load_15min_per_core = data->load_15min / data->cpu_count;
}