#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "cpuslatency.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct cpuslatency_bpf *skel;
    int err;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 增加资源限制
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20, // 512MB
        .rlim_max = 512UL << 20,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    // 打开并加载eBPF程序
    skel = cpuslatency_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    // 附加eBPF程序
    err = cpuslatency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    
    printf("eBPF program loaded successfully. Press Ctrl-C to stop.\n");
    
    // 保持运行
    while (!exiting) {
        sleep(1);
    }
    
cleanup:
    cpuslatency_bpf__destroy(skel);
    return 0;
}