package exporter
/*
#cgo CFLAGS: -I${SRCDIR}/../ebpf
#cgo LDFLAGS: -lmonitor -lelf -lz
#include "net_monitor.h"
#include "cpu_stat_monitor.h"
*/
import "C"
import "C"
import (
    "fmt"
    "log"
    "os"
    "bytes"
    "encoding/binary"
    "strconv"
    "syscall"
    _ "reflect"
    "unsafe"
    "math"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
    "github.com/prometheus/client_golang/prometheus"
)

var buckets []float64
// 初始化桶边界
func init() {
    for i := 1; i <= 24; i++ {
        buckets = append(buckets, float64((int(1) << i) - 1))
    }
}

// 定义所有eBPF监控指标
var (
    cpuStatNumbers = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_cpu_stat",
            Help: "Process ebpf_cpu_stat",
        },
        []string{"cpu_stat_type", "cpu", "node"},
    )

    networkTraffic = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_network_traffic",
            Help: "Process ebpf_network_traffic",
        },
        []string{"traffic_type", "node"},
    )

    SoftirqTimes = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_softirqs_operations_times",
            Help: "software interrupt number",
        },
        []string{"softirq_type", "cpu", "node"}, 
    )

    SoftirqNumbers = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "ebpf_softirqs_operations_total",
            Help: "software interrupt number",
        },
        []string{"softirq_type", "cpu", "node"}, 
    )

    TcpStatMetric = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "ebpf_tcp_conn_delay",
            Help:    "software interrupt number",
            Buckets: buckets,
        }, 
        []string{"node"},// 标签维度
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
        SoftirqTimes,
        TcpStatMetric,
        ExporterBuildInfo,
        ExporterScrapeDuration,
    }
}

// 指标更新函数
type MetricUpdater struct {
    softirqMap *ebpf.Map
    cpuStatMap *ebpf.Map
    trafficMap *ebpf.Map
    tcpStatMap *ebpf.Map
}

func NewMetricUpdater() (*MetricUpdater, error) {
    codePath := os.Getenv("KERNEL_BINARY_PATH")
    fmt.Println("kernel code path:", codePath)

    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("移除内存限制失败: %v", err)
    }

    softirqMap, err := attachSoftirqMonitoring(codePath)
    if err != nil {
        return nil, fmt.Errorf("NewMetricUpdater失败: %v", err)
    }
    cpuStatMap, err := attachCpuStatMonitoring()
    if err != nil {
        log.Println("加载ebpf失败,尝试kmodule获取: ", err)
        cpuStatMap = nil
    }
    trafficMap, err := attachTrafficMonitoring()
    if err != nil {
        return nil, fmt.Errorf("NewMetricUpdater失败: %v", err)
    }
    tcpStatMap, err := attachTcpStatMonitoring(codePath)
    if err != nil {
        return nil, fmt.Errorf("NewTcpStatMonitoring失败: %v", err)
    }

    updater := &MetricUpdater{
        softirqMap: softirqMap,
        cpuStatMap: cpuStatMap,
        trafficMap: trafficMap,
        tcpStatMap: tcpStatMap,
    }
    
    log.Println("eBPF程序成功加载并附加到软中断tracepoints")
    return updater, nil
}

func attachSoftirqMonitoring(codePath string) (*ebpf.Map, error) {
    var links []link.Link

    // Load the eBPF program specification
    spec, err := ebpf.LoadCollectionSpec(codePath + ".output/cpu_softirq_monitor.bpf.o")
    if err != nil {
        return nil, fmt.Errorf("failed to load eBPF collection spec: %v", err)
    }

    // Create a new eBPF collection
    coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
        Maps: ebpf.MapOptions{
            PinPath: "/sys/fs/bpf",
        },
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create eBPF collection: %v", err)
    }

    // Attach to the softirq_entry tracepoint
    if prog, ok := coll.Programs["handle_softirq_entry"]; ok {
        tp, err := link.Tracepoint("irq", "softirq_entry", prog, nil)
        if err != nil {
            coll.Close()
            return nil, fmt.Errorf("failed to attach to softirq_entry tracepoint: %v", err)
        }
        links = append(links, tp)
    } else {
        coll.Close()
        return nil, fmt.Errorf("could not find handle_softirq_entry program")
    }

    // Attach to the softirq_exit tracepoint
    if prog, ok := coll.Programs["handle_softirq_exit"]; ok {
        tp, err := link.Tracepoint("irq", "softirq_exit", prog, nil)
        if err != nil {
            for _, l := range links {
                l.Close()
            }
            coll.Close()
            return nil, fmt.Errorf("failed to attach to softirq_exit tracepoint: %v", err)
        }
        links = append(links, tp)
    } else {
        for _, l := range links {
            l.Close()
        }
        coll.Close()
        return nil, fmt.Errorf("could not find handle_softirq_exit program")
    }

    // Retrieve the statistics map
    statsMap, ok := coll.Maps["softirq_stats"]
    if !ok {
        for _, l := range links {
            l.Close()
        }
        coll.Close()
        return nil, fmt.Errorf("could not find softirq_stats map")
    }

    return statsMap, nil
}

func attachCpuStatMonitoring() (*ebpf.Map, error) {
  if C.init_cpu_stat_monitor() != 0 {
        return nil, fmt.Errorf("failed to initialize eBPF programs")
    }

    cpuStatfd := C.get_cpustats_map_fd()
	if cpuStatfd == -1 {
		return nil, fmt.Errorf("[attachCpuStatMonitoring]failed to get mapFd")
	}
    fmt.Println("get cpustat fd: ", cpuStatfd)
    cpuStatMap, err := ebpf.NewMapFromFD(int(cpuStatfd))
    if err != nil {
        return nil, fmt.Errorf("failed to create syscall map: %v", err)
    }

    return cpuStatMap, nil;
}

func attachTrafficMonitoring() (*ebpf.Map, error) {
    if C.init_net_monitor() != 0 {
        return nil, fmt.Errorf("failed to initialize eBPF programs")
    }

    netfd := C.net_monitor_get_packetsinfo_fd()
	if netfd == 0 {
		return nil, fmt.Errorf("[attachTrafficMonitoring]failed to get mapFd")
	}
    trafficMap, err := ebpf.NewMapFromFD(int(netfd))
    if err != nil {
        return nil, fmt.Errorf("failed to create syscall map: %v", err)
    }

    return trafficMap, nil;
}

func attachTcpStatMonitoring(codePath string) (*ebpf.Map, error) {    
    var links []link.Link
	cleanup := func() {
		for _, l := range links {
			l.Close()
		}
	}

    collectionSpec, err := ebpf.LoadCollectionSpec(codePath + ".output/tcp_stat_monitor.bpf.o")
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

	// --- 附加 KProbes (已修正) ---
	probes := map[string]string{
		"kp_inet_csk_reqsk_queue_hash_add": "inet_csk_reqsk_queue_hash_add",
		// "kp_tcp_v6_conn_request": "tcp_v6_conn_request",
		"kp_tcp_set_state":       "tcp_set_state",
	}

	for progName, kernelFunc := range probes {
		prog, exists := collection.Programs[progName]
		if !exists {
			cleanup() // 关闭之前已创建的 links
			collection.Close()
			return nil, fmt.Errorf("找不到 %s 程序", progName)
		}

		l, err := link.Kprobe(kernelFunc, prog, nil)
		if err != nil {
			cleanup() // 关闭之前已创建的 links
			collection.Close()
			return nil, fmt.Errorf("附加 %s 到 %s 失败: %v", progName, kernelFunc, err)
		}
		links = append(links, l)
	}


    hashMap, ok := collection.Maps["hist"]
    if !ok {
        // 关闭已创建的links
        for _, l := range links {
            l.Close()
        }
        collection.Close()
        return nil, fmt.Errorf("找不到hist映射")
    }

    return hashMap, nil
}


// UpdateSoftirqMetrics 更新软中断指标
func (m *MetricUpdater) UpdateSoftirqMetrics() error {
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
    }
    if m.softirqMap == nil {
        return fmt.Errorf("softirqMap为nil")
    }
    fmt.Println("[UpdateSoftirqMetrics] update once...")
    
    var vec uint32      // 1. Key 现在是 u32 (代表 vec)，Value 是一个 Per-CPU 的切片
    var perCPUStats []SoftirqStat // 这是接收所有 CPU 数据的切片

    totalEventsProcessed := 0
    iter := m.softirqMap.Iterate()

    // 2. 外层循环遍历 Map 中的每一个 key (也就是每个软中断 vec)
    for iter.Next(&vec, &perCPUStats) {
        // 3. 内层循环遍历该 key 在所有 CPU 上的值
        // 切片的索引 `cpuID` 天然地代表了 CPU 的核心号
        for cpuID, stat := range perCPUStats {
            // 如果这个 CPU 上确实发生了该类型的软中断 (count > 0)，才上报数据
            if stat.Count > 0 {
                irqTypeName := getSoftirqTypeName(vec)
                cpuIDStr := strconv.Itoa(cpuID) // 将 CPU ID 转换为字符串
                
                // 4. 使用 cpuID 和 irqTypeName 作为组合维度上报数据
                SoftirqNumbers.WithLabelValues(irqTypeName, cpuIDStr, "111").Set(float64(stat.Count))
                SoftirqTimes.WithLabelValues(irqTypeName, cpuIDStr, "111").Set(float64(stat.MaxTimeNs))

                totalEventsProcessed += int(stat.Count)
            }
        }
    }
    
    if err := iter.Err(); err != nil {
        log.Printf("遍历 softirq map 出错: %v", err)
        return err
    }
    
    if totalEventsProcessed > 0 {
        log.Printf("总共处理了 %d 个软中断事件", totalEventsProcessed)
    }
    
    return nil
}

// UpdateNetworkTraffic 更新网络吞吐指标
func (m *MetricUpdater) UpdateTrafficMetrics() error {
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
    }
    if m.trafficMap == nil {
        return fmt.Errorf("trafficMap为nil")
    }

    var key uint32
    var value ip_packet_info
    fmt.Println("[UpdateTrafficMetrics] update once...")
    iter := m.trafficMap.Iterate()
    for iter.Next(&key, &value) {
        log.Printf("bytes %d, packets %d", value.Snd_rcv_bytes, value.Snd_rcv_packets)
        networkTraffic.WithLabelValues(getTrafficName(key), "111").Set(float64(value.Snd_rcv_bytes))
        networkTraffic.WithLabelValues(getTrafficName(key), "111").Set(float64(value.Snd_rcv_packets))
    }

    return nil
}

// UpdateNetworkTraffic 更新网络吞吐指标
func (m *MetricUpdater) UpdateCpuStatMetrics() error {
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
    }
    if m.cpuStatMap == nil {
        return m.UpdateCpuStatMetricsByKernelMod()
    }
    // return m.UpdateCpuStatMetricsByKernelMod()

    var key uint32
    var perCPUValues []cpu_stat
    iter := m.cpuStatMap.Iterate()
    for iter.Next(&key, &perCPUValues) {
        if int(key) < len(perCPUValues) {
            value := perCPUValues[key]
            if (value.Online == 0) {
                continue
            }
            fmt.Printf("key: %d, user %d, system %d\n", key, value.User, value.System)
            cpuStatNumbers.WithLabelValues("User", strconv.Itoa(int(key)), "111").Set(float64(value.User))
            cpuStatNumbers.WithLabelValues("System", strconv.Itoa(int(key)), "111").Set(float64(value.System))
            cpuStatNumbers.WithLabelValues("Nice", strconv.Itoa(int(key)), "111").Set(float64(value.Nice))
            cpuStatNumbers.WithLabelValues("Idle", strconv.Itoa(int(key)), "111").Set(float64(value.Idle))
            cpuStatNumbers.WithLabelValues("Iowait", strconv.Itoa(int(key)),"111").Set(float64(value.Iowait))
            cpuStatNumbers.WithLabelValues("Irq", strconv.Itoa(int(key)), "111").Set(float64(value.Irq))
            cpuStatNumbers.WithLabelValues("Softirq", strconv.Itoa(int(key)), "111").Set(float64(value.Softirq))
            cpuStatNumbers.WithLabelValues("Steal", strconv.Itoa(int(key)), "111").Set(float64(value.Steal))
            cpuStatNumbers.WithLabelValues("Guest", strconv.Itoa(int(key)), "111").Set(float64(value.Guest))
            cpuStatNumbers.WithLabelValues("Guest_nice", strconv.Itoa(int(key)), "111").Set(float64(value.Guest_nice))
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

	// 使用 binary.Read 安全地读取数据
	reader := bytes.NewReader(data)
	stats := make([]cpu_stat, statCount)

	// --- 这是关键的修改 ---
	// 不要一次性读取整个切片，而是循环逐个读取
	// 这避免了 binary.Read 使用需要特殊对齐的 AVX 批量读取指令
	for i := 0; i < statCount; i++ {
		// 读取单个 cpu_stat 结构体到切片的对应位置
		if err := binary.Read(reader, binary.LittleEndian, &stats[i]); err != nil {
			return fmt.Errorf("failed to read mmap data for stat index %d: %v", i, err)
		}
	}
	log.Printf("user %d, system %d", stats[0].User, stats[0].System)

	// 循环现在是安全的
	for i := 0; i < len(stats); i++ {
		stat := stats[i]
        if (stat.Online == 0) {
            continue
        }
        cpuStatNumbers.WithLabelValues("User", strconv.Itoa(i), "111").Set(float64(stat.User))
		cpuStatNumbers.WithLabelValues("System", strconv.Itoa(i), "111").Set(float64(stat.System))
        cpuStatNumbers.WithLabelValues("Nice", strconv.Itoa(i), "111").Set(float64(stat.Nice))
        cpuStatNumbers.WithLabelValues("Idle", strconv.Itoa(i), "111").Set(float64(stat.Idle))
        cpuStatNumbers.WithLabelValues("Iowait", strconv.Itoa(i),"111").Set(float64(stat.Iowait))
        cpuStatNumbers.WithLabelValues("Irq", strconv.Itoa(i), "111").Set(float64(stat.Irq))
        cpuStatNumbers.WithLabelValues("Softirq", strconv.Itoa(i), "111").Set(float64(stat.Softirq))
        cpuStatNumbers.WithLabelValues("Steal", strconv.Itoa(i), "111").Set(float64(stat.Steal))
        cpuStatNumbers.WithLabelValues("Guest", strconv.Itoa(i), "111").Set(float64(stat.Guest))
        cpuStatNumbers.WithLabelValues("Guest_nice", strconv.Itoa(i), "111").Set(float64(stat.Guest_nice))
	}

    return nil
}

func (m *MetricUpdater) UpdateTcpStatMetrics() error {
    if m == nil {
        return fmt.Errorf("MetricUpdater为nil")
    }
    if m.tcpStatMap == nil {
        return fmt.Errorf("TcpStatMap为nil")
    }

    fmt.Println("[UpdateTcpStatMetrics] update once...")
    var key uint32
    var value uint64
    iter := m.tcpStatMap.Iterate()
    for iter.Next(&key, &value) {
        fmt.Printf("current thres: %d, val: %d\n", key, value)
        upperBoundUs := math.Pow(2, float64(key+1)) - 1
		histogram, err := TcpStatMetric.GetMetricWithLabelValues("111")
		if err != nil {
			log.Printf("Error getting metric with label: %v", err)
			continue
		}
		for i := uint64(0); i < value; i++ {
			histogram.Observe(upperBoundUs)
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

func getTrafficName(i uint32) string {
    if i >= 0 || i < uint32(len(TrafficNames)) {
        return TrafficNames[i]
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

