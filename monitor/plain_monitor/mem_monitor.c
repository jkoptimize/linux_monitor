#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define INTERVAL 5  // 5秒刷新间隔

// 定义内存信息数据结构
typedef struct {
    unsigned long mem_total;       // MemTotal
    unsigned long mem_free;        // MemFree
    unsigned long mem_available;   // MemAvailable
    unsigned long buffers;         // Buffers
    unsigned long cached;          // Cached
    unsigned long swap_total;      // SwapTotal
    unsigned long swap_free;       // SwapFree
} MemInfo;

// 修正后的解析函数：使用更健壮的字符串处理
void parse_meminfo_line(const char *line, MemInfo *info) {
    char key[32];
    unsigned long value;
    char *colon = strchr(line, ':');
    
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
void get_meminfo(MemInfo *info) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        perror("Failed to open /proc/meminfo");
        exit(1);
    }

    char line[256];
    memset(info, 0, sizeof(MemInfo));  // 初始化为0
    
    while (fgets(line, sizeof(line), fp)) {
        parse_meminfo_line(line, info);
    }
    
    fclose(fp);
}

// 打印内存信息
void print_meminfo(const MemInfo *info) {
    printf("Memory Statistics:\n");
    printf("  Total:        %8lu kB\n", info->mem_total);
    printf("  Free:         %8lu kB\n", info->mem_free);
    printf("  Available:    %8lu kB\n", info->mem_available);
    printf("  Buffers:      %8lu kB\n", info->buffers);
    printf("  Cached:       %8lu kB\n", info->cached);
    printf("  Swap Total:   %8lu kB\n", info->swap_total);
    printf("  Swap Free:    %8lu kB\n", info->swap_free);
}

int main() {
    MemInfo mem_info;
    time_t last_print = time(NULL);
    
    printf("Memory statistics (refresh every %d seconds):\n", INTERVAL);
    printf("===========================================\n");
    
    while (1) {
        // 获取当前时间
        time_t current = time(NULL);
        if (difftime(current, last_print) >= INTERVAL) {
            last_print = current;
            
            // 获取并打印内存信息
            get_meminfo(&mem_info);
            printf("\n[%s] Memory Statistics:\n", ctime(&current));
            print_meminfo(&mem_info);
        }
        
        // 短暂休眠以减少CPU占用
        usleep(500000);  // 500ms
    }
    
    return 0;
}