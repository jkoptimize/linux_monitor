#include "mem_monitor.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>

int main() {
    MemInfo info;
    time_t last_print = time(NULL);
    const int INTERVAL = 5; // 5秒刷新间隔

    printf("Memory statistics (refresh every %d seconds):\n", INTERVAL);
    printf("===========================================\n");

    while (1) {
        time_t current = time(NULL);
        if (difftime(current, last_print) >= INTERVAL) {
            last_print = current;

            // 获取内存信息
            if (get_meminfo(&info) == 0) {
                printf("\n[%s] Memory Statistics:\n", ctime(&current));
                printf("  Total:        %8lu kB\n", info.mem_total);
                printf("  Free:         %8lu kB\n", info.mem_free);
                printf("  Available:    %8lu kB\n", info.mem_available);
                printf("  Buffers:      %8lu kB\n", info.buffers);
                printf("  Cached:       %8lu kB\n", info.cached);
                printf("  Swap Total:   %8lu kB\n", info.swap_total);
                printf("  Swap Free:    %8lu kB\n", info.swap_free);
            } else {
                fprintf(stderr, "Failed to get memory info\n");
            }
        }
        
        // 短暂休眠
        usleep(500000); // 500ms
    }

    return 0;
}