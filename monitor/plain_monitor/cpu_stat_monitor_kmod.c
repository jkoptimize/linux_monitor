#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/cpumask.h>
#include <linux/kernel_stat.h>
#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>          // 包含vzalloc, vfree
#include <linux/hrtimer.h>       // 包含hrtimer_*函数
#include <linux/miscdevice.h>    // 包含misc_register, misc_deregister
#include <linux/sched.h>         // 包含kernel_cpustat
#include <linux/printk.h>        // 包含_printk

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)    
#error "This module requires Linux kernel version 5.6 or later"
#endif

#define MAX_CPU 128

struct cpu_stat {
    // char cpu_name[16];
    u64 user;
    u64 nice;
    u64 system;
    u64 idle;
    u64 io_wait;
    u64 irq;
    u64 soft_irq;
    u64 steal;
    u64 guest;
    u64 guest_nice;
};

static struct cpu_stat *g_cpu_stats = NULL;
static struct hrtimer cpu_stat_timer;
static ktime_t ktime;
#define UPDATE_INTERVAL_NS 1000000000L  // 1秒 = 1000000000 纳秒


static void update_cpu_stats(struct cpu_stat *stats) {
    static int times = 0;
    int cpu;
    for (cpu = 0; cpu < MAX_CPU; ++cpu) {
        if (!cpu_online(cpu)) {
            // stats[cpu].cpu_name[0] = '\0';
            continue;
        }
        // snprintf(stats[cpu].cpu_name, sizeof(stats[cpu].cpu_name), "cpu%d", cpu);
        u64 *stat = kcpustat_cpu(cpu).cpustat;
        stats[cpu].user = stat[CPUTIME_USER];
        stats[cpu].nice = stat[CPUTIME_NICE];
        stats[cpu].system = stat[CPUTIME_SYSTEM];
        stats[cpu].idle = stat[CPUTIME_IDLE];
        stats[cpu].io_wait = stat[CPUTIME_IOWAIT];
        stats[cpu].irq = stat[CPUTIME_IRQ];
        stats[cpu].soft_irq = stat[CPUTIME_SOFTIRQ];
        stats[cpu].steal = stat[CPUTIME_STEAL];
        stats[cpu].guest = stat[CPUTIME_GUEST];
        stats[cpu].guest_nice = stat[CPUTIME_GUEST_NICE];

        printk(KERN_INFO "cpu_stat_monitor: CPU0 user=%llu, nice=%llu\n", 
            stats[0].user, stats[0].nice);
    }
}

static enum hrtimer_restart cpu_stat_timer_callback(struct hrtimer *timer)
{
    update_cpu_stats(g_cpu_stats);
    hrtimer_forward_now(timer, ktime);
    return HRTIMER_RESTART;
}

//vmalloc分配的是虚拟地址连续的大块内存，物理地址并不连续，内核通过修改页表，将虚拟地址拼接连续
//virt_to_phys只能转换kmalloc等分配在直接映射区的内存地址，不能用于vmalloc或者zmalloc
//remap_pfn_range作用是将一段连续物理内存映射至用户空间的虚拟地址
//因此，virt_to_phys这里返回了失效虚拟地址，remap_pfn_range将其映射给了go，go是从无效地址读取数据
static int cpu_stat_monitor_mmap(struct file *filp, struct vm_area_struct *vma) {
    unsigned long size = sizeof(struct cpu_stat) * MAX_CPU;
    if ((vma->vm_end - vma->vm_start) < size)
        return -EINVAL;
    // 移除 update_cpu_stats 调用,因为定时器会定期更新
    return remap_pfn_range(vma, vma->vm_start,
                           virt_to_phys((void *)g_cpu_stats) >> PAGE_SHIFT,                
                           size, vma->vm_page_prot);
}

static const struct file_operations cpu_stat_monitor_fops = {
    .owner = THIS_MODULE,
    .mmap = cpu_stat_monitor_mmap,
};

static struct miscdevice cpu_stat_monitor_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "cpu_stat_monitor",
    .fops = &cpu_stat_monitor_fops,
    .mode = 0444,
};

static int __init cpu_stat_monitor_init(void) {
    g_cpu_stats = kzalloc(sizeof(struct cpu_stat) * MAX_CPU, GFP_KERNEL);
    if (!g_cpu_stats)
        return -ENOMEM;
    
    // 初始化并启动定时器
    ktime = ktime_set(0, UPDATE_INTERVAL_NS);
    hrtimer_init(&cpu_stat_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    cpu_stat_timer.function = &cpu_stat_timer_callback;
    hrtimer_start(&cpu_stat_timer, ktime, HRTIMER_MODE_REL);
    
    misc_register(&cpu_stat_monitor_dev);
    printk(KERN_INFO "cpu_stat_monitor device registered\n");
    return 0;
}

static void __exit cpu_stat_monitor_exit(void) {
    hrtimer_cancel(&cpu_stat_timer);
    misc_deregister(&cpu_stat_monitor_dev);
    if (g_cpu_stats)
        kfree(g_cpu_stats); // 使用 kfree 替代 vfree
    printk(KERN_INFO "cpu_stat_monitor device unregistered\n");
}

module_init(cpu_stat_monitor_init);
module_exit(cpu_stat_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("CPU Stat Monitor Module with mmap support");