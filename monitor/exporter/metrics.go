package exporter
/*
#cgo CFLAGS: -I${SRCDIR}/../ebpf
#cgo LDFLAGS: -lmonitor -lelf -lz
#include "cpu_softirq_monitor.h"
*/
import "C"
import (
    "fmt"
    "github.com/cilium/ebpf"
    "github.com/prometheus/client_golang/prometheus"
)

// 定义所有eBPF监控指标
var (
    // SchedulerLatency = prometheus.NewHistogramVec(
    //     prometheus.HistogramOpts{
    //         Name: "ebpf_scheduler_latency_nanoseconds",
    //         Help: "Process scheduling latency distribution",
    //         Buckets: prometheus.ExponentialBuckets(1000, 2, 16), // 1us to 32ms
    //     },
    //     []string{"comm", "cpu", "node"},
    // )
    
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
        SoftirqNumbers,
        ExporterBuildInfo,
        ExporterScrapeDuration,
    }
}

// 指标更新函数
type MetricUpdater struct {
    softirqMap *ebpf.Map
}

func NewMetricUpdater() (*MetricUpdater, error) {
    // 初始化 C 的 eBPF 管理器
    if C.init_ebpf_programs() != 0 {
        return nil, fmt.Errorf("failed to initialize eBPF programs")
    }

    // 获取 map fd 并转换为 Go 的 ebpf.Map
    softirqMapFd := C.get_softirq_map_fd()
	if softirqMapFd == 0 {
		return nil, fmt.Errorf("failed to get mapFd")
	}

    var err error
    softirqMap, err := ebpf.NewMapFromFD(int(softirqMapFd))
    if err != nil {
        return nil, fmt.Errorf("failed to create syscall map: %v", err)
    }

    updater := &MetricUpdater{}
    updater.softirqMap = softirqMap
    return updater, nil;
}

type SoftirqStat struct {
    Count       uint64
    TotalTimeNs uint64
    MaxTimeNs   uint64
}

// UpdateSchedulerMetrics 更新调度器指标
func (m *MetricUpdater) UpdateSoftirqMetrics() error {
    var key  uint32
    var value SoftirqStat
    iter := m.softirqMap.Iterate()
    
    for iter.Next(&key, &value) {     
        SoftirqNumbers.With(prometheus.Labels{
            "softirq_type": string(key),
            "node":  "111",
        }).Set(float64(value.Count))
    }
    
    if err := iter.Err(); err != nil {
        return err
    }
    return nil
}

// // UpdateNetworkMetrics 更新网络指标
// func (m *MetricUpdater) UpdateNetworkMetrics(event *NetworkEvent) {
//     NetworkPackets.With(prometheus.Labels{
//         "direction":  event.Direction,
//         "protocol":   event.Protocol,
//         "interface":  event.Interface,
//         "node":       event.NodeName,
//     }).Inc()
    
//     if event.Latency > 0 {
//         NetworkLatency.With(prometheus.Labels{
//             "protocol": event.Protocol,
//             "node":     event.NodeName,
//         }).Observe(float64(event.Latency))
//     }
// }

// // UpdateCPUUsage 更新CPU使用率
// func (m *MetricUpdater) UpdateCPUUsage(usage *CPUUsageData) {
//     CPUUsage.With(prometheus.Labels{
//         "cpu":   usage.CPU,
//         "mode":  "user",
//         "node":  usage.NodeName,
//     }).Set(usage.UserPercent)
    
//     CPUUsage.With(prometheus.Labels{
//         "cpu":   usage.CPU,
//         "mode":  "system", 
//         "node":  usage.NodeName,
//     }).Set(usage.SystemPercent)
// }

// SetBuildInfo 设置构建信息
func SetBuildInfo(version, revision, branch, goVersion string) {
    ExporterBuildInfo.With(prometheus.Labels{
        "version":   version,
        "revision":  revision,
        "branch":    branch,
        "goversion": goVersion,
    }).Set(1)
}