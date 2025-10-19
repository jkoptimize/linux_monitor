#include "cpu_softirq_monitor.h"
#include <unistd.h>

int main()
{
    init_ebpf_programs();

    sleep(1);
    print();

    cleanup_ebpf_programs();

    return 0;
}