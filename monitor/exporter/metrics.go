package exporter
/*
#cgo CFLAGS: -I${SRCDIR}/../ebpf
#cgo LDFLAGS: -lmonitor -lelf -lz
#include "cpu_softirq_monitor.h"
*/
import "C"
import "C"
import (
    "fmt"
    "log"
    "os"
    "strconv"
    "syscall"
    "reflect"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"

    "github.com/prometheus/client_golang/prometheus"
)

// 定义所有eBPF监控指标
var (
    cpuStatNumbers = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_cpu_stat",
            Help: "Process ebpf_cpu_stat",
        },
        []string{"cpu_stat_type", "node"},
    )

    networkTraffic = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_network_traffic",
            Help: "Process ebpf_network_traffic",
        },
        []string{"ingress", "egress", "node"},
    )
    
    SoftirqNumbers = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_softirqs_operations_total",
            Help: "software interrupt number",
        },
        []string{"softirq_type", "node"}, 
    )

    // Exporter自身指标
    ExporterBuildInfo = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_exporter_build_info",
            Help: "eBPF exporter build information",
        },
        []string{"version", "revision", "branch", "goversion"},
    )
    
    ExporterScrapeDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "ebpf_exporter_scrape_duration_seconds",
            Help:    "Duration of scrapes from the eBPF exporter",
            Buckets: prometheus.DefBuckets,
        },
    )
)

// createEBPFMetrics 创建所有eBPF指标集合
func createEBPFMetrics() []prometheus.Collector {
    return []prometheus.Collector{
        cpuStatNumbers,
        networkTraffic,
        SoftirqNumbers,
        ExporterBuildInfo,
        ExporterScrapeDuration,
    }
}

// 指标更新函数
type MetricUpdater struct {
    softirqMap *ebpf.Map
    cpuStatMap *ebpf.Map
    trafficMap *ebpf.Map
}

func NewMetricUpdater() (*MetricUpdater, error) {
    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("移除内存限制失败: %v", err)
    }

    softirqMap, err := attachSoftirqMonitoring()
    if err != nil {
        return nil, fmt.Errorf("NewMetricUpdater失败: %v", err)
    }
    cpuStatMap, err := attachCpuStatMonitoring()
    if err != nil {
        log.Println("加载ebpf失败,尝试kmodule获取")
        cpuStatMap = nil
    }
    // trafficMap, err := attachTrafficMonitoring()
    // if err != nil {
    //     return nil, fmt.Errorf("NewMetricUpdater失败: %v", err)
    // }

    updater := &MetricUpdater{
        softirqMap: softirqMap,
        cpuStatMap: cpuStatMap,
        // trafficMap: trafficMap,
    }
    
    log.Println("eBPF程序成功加载并附加到软中断tracepoints")
    return updater, nil
}

func attachSoftirqMonitoring() (*ebpf.Map, error) {
    var links []link.Link

    // 编译和加载eBPF程序
    collectionSpec, err := ebpf.LoadCollectionSpec(".output/cpu_softirq_monitor.bpf.o")
    if err != nil {
        return nil, fmt.Errorf("加载eBPF集合规范失败: %v", err)
    }

    collection, err := ebpf.NewCollectionWithOptions(collectionSpec, ebpf.CollectionOptions{
        Maps: ebpf.MapOptions{
            PinPath: "/sys/fs/bpf",
        },
    })
    if err != nil {
        return nil, fmt.Errorf("创建eBPF集合失败: %v", err)
    }

    // 附加第一个tracepoint: irq:softirq_entry
    if prog, exists := collection.Programs["handle_softirq_entry"]; exists {
        tp, err := link.Tracepoint("irq", "softirq_entry", prog, nil)
        if err != nil {
            return nil, fmt.Errorf("附加softirq_entry tracepoint失败: %v", err)
        }
        links = append(links, tp)
    } else {
        return nil, fmt.Errorf("找不到 handle_softirq_entry 程序")
    }
    
    // 附加第二个tracepoint: irq:softirq_exit
    if prog, exists := collection.Programs["handle_softirq_exit"]; exists {
        tp, err := link.Tracepoint("irq", "softirq_exit", prog, nil)
        if err != nil {
            return nil, fmt.Errorf("附加softirq_exit tracepoint失败: %v", err)
        }
        links = append(links, tp)
    } else {
        return nil, fmt.Errorf("找不到 handle_softirq_exit 程序")
    }

    hashMap, ok := collection.Maps["softirq_stats"]
    if !ok {
        // 关闭已创建的links
        for _, l := range links {
            l.Close()
        }
        collection.Close()
        return nil, fmt.Errorf("找不到softirq_stats映射")
    }

    return hashMap, nil
}

func attachCpuStatMonitoring() (*ebpf.Map, error) {
    var links []link.Link

    // 编译和加载eBPF程序
    collectionSpec, err := ebpf.LoadCollectionSpec(".output/cpu_stat_monitor.bpf.o")
    if err != nil {
        return nil, fmt.Errorf("加载eBPF集合规范失败: %v", err)
    }

    collection, err := ebpf.NewCollectionWithOptions(collectionSpec, ebpf.CollectionOptions{
        Maps: ebpf.MapOptions{
            PinPath: "/sys/fs/bpf",
        },
    })
    if err != nil {
        return nil, fmt.Errorf("创建eBPF集合失败: %v", err)
    }

    if prog, exists := collection.Programs["kprobe_account_process_tick"]; exists {
        tp, err := link.Kprobe("kprobe_account_process_tick", prog, nil)
        if err != nil {
            return nil, fmt.Errorf("附加softirq_entry tracepoint失败: %v", err)
        }
        links = append(links, tp)
    } else {
        return nil, fmt.Errorf("找不到 kprobe_account_process_tick 程序")
    }

    hashMap, ok := collection.Maps["cpu_stats"]
    if !ok {
        // 关闭已创建的links
        for _, l := range links {
            l.Close()
        }
        collection.Close()
        return nil, fmt.Errorf("找不到softirq_stats映射")
    }

    return hashMap, nil
}

// func attachTrafficMonitoring() (*ebpf.Map, error) {
    
// }

// UpdateSoftirqMetrics 更新软中断指标
func (m *MetricUpdater) UpdateSoftirqMetrics() error {
    // 安全检查
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
    }
    if m.softirqMap == nil {
        return fmt.Errorf("softirqMap为nil")
    }

    var key uint32
    var value SoftirqStat
    totalCount := 0
    iter := m.softirqMap.Iterate()
    for iter.Next(&key, &value) {
        softirqType := getSoftirqTypeName(key)
        log.Printf("软中断 %s (%d): Count=%d, TotalTime=%d ns, MaxTime=%d ns", 
            softirqType, key, value.Count, value.TotalTimeNs, value.MaxTimeNs)
        
        // 更新Prometheus指标
        SoftirqNumbers.With(prometheus.Labels{
            "softirq_type": softirqType,
            "node": "111",
        }).Set(float64(value.Count))
        
        totalCount += int(value.Count)     
    }
    
    if totalCount > 0 {
        log.Printf("总共处理了 %d 个软中断事件", totalCount)
    }
    
    return nil
}

// UpdateNetworkTraffic 更新网络吞吐指标
func (m *MetricUpdater) UpdateTrafficMetrics() error {
    // 安全检查
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
    }
    if m.trafficMap == nil {
        return fmt.Errorf("trafficMap为nil")
    }

    var key uint32
    var value ip_packet_info

    iter := m.trafficMap.Iterate()
    for iter.Next(&key, &value) {
        log.Printf("in %d, out %d", value.snd_rcv_bytes, value.snd_rcv_packets)
        
        // 更新Prometheus指标
        networkTraffic.With(prometheus.Labels{
            "ingress": "",
            "egress": "",
            "node": "111",
        }).Set(float64(0))
    }

    return nil
}

// UpdateNetworkTraffic 更新网络吞吐指标
func (m *MetricUpdater) UpdateCpuStatMetrics() error {
    // 安全检查
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
        
    }
    if m.cpuStatMap == nil {
        return m.UpdateCpuStatMetricsByKernelMod()
    }

    var key uint32
    var value cpu_stat

    iter := m.cpuStatMap.Iterate()
    for iter.Next(&key, &value) {
        log.Printf("user %d, system %d", value.user, value.system)
        for j, _ := range CpuStatsNames {
            val := reflect.ValueOf(value)
            cpuStatName := getCpuStatsName(uint32(j))
            cpuStatNumbers.With(prometheus.Labels{
                "cpu_stat_type": cpuStatName,
                "node": "111",
            }).Set(float64(val.FieldByName(cpuStatName).Uint()))
        }
    }

    return nil
}

func (m *MetricUpdater) UpdateCpuStatMetricsByKernelMod() error {
	file, err := os.OpenFile("/dev/cpu_stat_monitor", os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("fail to update CpuStat metric, OpenFile failed: %v\n", err)
	}
	defer file.Close()

	// 定义stat_count和stat_size
	const statCount = 128
	statSize := int(statCount * unsafe.Sizeof(cpu_stat{}))

	// 内存映射
	data, err := syscall.Mmap(int(file.Fd()), 0, statSize, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("Mmap failed: %v\n", err)
	}
	defer syscall.Munmap(data)

	var stats []cpu_stat
	{
		header := (*reflect.SliceHeader)(unsafe.Pointer(&stats))
		header.Data = uintptr(unsafe.Pointer(&data[0]))
		header.Len = statCount
		header.Cap = statCount
	}

    log.Printf("cpu_stat length: %d", len(stats))
    for _, stat := range stats {
        log.Printf("user %d, system %d", stat.user, stat.system)
        for j, _ := range CpuStatsNames {
            val := reflect.ValueOf(stat)
            cpuStatName := getCpuStatsName(uint32(j))
            cpuStatNumbers.With(prometheus.Labels{
                "cpu_stat_type": cpuStatName,
                "node": "111",
            }).Set(float64(val.FieldByName(cpuStatName).Uint()))
        }
    }

    return nil
}



func getSoftirqTypeName(i uint32) string {
    if i >= 0 || i < uint32(len(SoftirqNames)) {
        return SoftirqNames[i]
    }
    return "unknown_" + strconv.Itoa(int(i))
}

func getCpuStatsName(i uint32) string {
    if i >= 0 || i < uint32(len(CpuStatsNames)) {
        return CpuStatsNames[i]
    }
    return "unknown_" + strconv.Itoa(int(i))
}


// SetBuildInfo 设置构建信息
func SetBuildInfo(version, revision, branch, goVersion string) {
    ExporterBuildInfo.With(prometheus.Labels{
        "version":   version,
        "revision":  revision,
        "branch":    branch,
        "goversion": goVersion,
    }).Set(1)
}

