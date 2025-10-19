#include "mem_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

// 修正后的解析函数（静态内部函数）
static void parse_meminfo_line(const char *line, MemInfo *info) {
    char key[32];
    unsigned long value;
    const char *colon = strchr(line, ':');
    
    if (!colon) return;  // 没有冒号，跳过
    
    // 提取key（冒号前的部分）
    size_t key_len = colon - line;
    if (key_len >= sizeof(key)) return;
    strncpy(key, line, key_len);
    key[key_len] = '\0';
    
    // 跳过冒号和后续空白
    char *value_str = colon + 1;
    while (*value_str && isspace(*value_str)) value_str++;
    
    // 提取数字
    if (sscanf(value_str, "%lu", &value) == 1) {
        if (strcmp(key, "MemTotal") == 0) info->mem_total = value;
        else if (strcmp(key, "MemFree") == 0) info->mem_free = value;
        else if (strcmp(key, "MemAvailable") == 0) info->mem_available = value;
        else if (strcmp(key, "Buffers") == 0) info->buffers = value;
        else if (strcmp(key, "Cached") == 0) info->cached = value;
        else if (strcmp(key, "SwapTotal") == 0) info->swap_total = value;
        else if (strcmp(key, "SwapFree") == 0) info->swap_free = value;
    }
}

// 从/proc/meminfo读取并解析内存信息
int get_meminfo(MemInfo *info) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        perror("Failed to open /proc/meminfo");
        return -1;
    }

    char line[256];
    memset(info, 0, sizeof(MemInfo));  // 初始化为0
    
    while (fgets(line, sizeof(line), fp)) {
        parse_meminfo_line(line, info);
    }
    
    fclose(fp);
    return 0;
}