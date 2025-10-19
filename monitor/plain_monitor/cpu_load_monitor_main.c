#include "cpu_load_monitor.h"
#include <stdio.h>

int main() {
    LoadAvgData data;
    
    get_loadavg_data(&data);
    
    printf("System Load Average:\n");
    printf("  1min:  %8.2f (system)\n", data.load_1min);
    printf("  5min:  %8.2f (system)\n", data.load_5min);
    printf("  15min: %8.2f (system)\n", data.load_15min);
    printf("CPU Cores: %d\n", data.cpu_count);
    printf("Per Core:\n");
    printf("  1min:  %8.2f\n", data.load_1min_per_core);
    printf("  5min:  %8.2f\n", data.load_5min_per_core);
    printf("  15min: %8.2f\n", data.load_15min_per_core);
    
    return 0;
}