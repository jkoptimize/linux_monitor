package exporter

import (
    "time"
)

var SoftirqNames = []string{
    "HI",        // 0
    "TIMER",     // 1
    "NET_TX",    // 2
    "NET_RX",    // 3
    "BLOCK",     // 4
    "IRQ_POLL",  // 5
    "TASKLET",   // 6
    "SCHED",     // 7
    "HRTIMER",   // 8
    "RCU",       // 9
}

var TrafficNames = []string{
    "ingress",
    "egress",
}

var CpuStatsNames = []string{
    "User",        // 0
    "Nice",     // 1
    "System",    // 2
    "Idle",    // 3
    "Iowait",     // 4
    "Irq",  // 5
    "Softirq",   // 6
    "Steal",     // 7
    "Guest",   // 8
    "Guest_nice",       // 9
}

type SoftirqKey struct {
    Cpu uint32
    Vec uint32
}

type SoftirqStat struct {
    Count       uint64
    TotalTimeNs uint64
    MaxTimeNs   uint64
}

type ip_packet_info struct {
     Snd_rcv_bytes uint64
     Snd_rcv_packets uint64
}

type cpu_stat struct {
     Online uint64
     User   uint64
     Nice   uint64
     System   uint64
     Idle   uint64
     Iowait   uint64
     Irq   uint64
     Softirq   uint64
     Steal   uint64
     Guest   uint64
     Guest_nice   uint64
}


/*   统计类型指标   */
// CPULoadData CPU负载数据
type CPULoadData struct {
    timestamp			time.Time `json:"timestamp"`      // 时间戳
    node_name			string    `json:"node_name"`      // 节点名称
	load_1min		float64		`json:"load_1min"`   // 过去1min平均负载
	load_5min		float64		`json:"load_5min"`   // 过去5min平均负载
	load_15min		float64		`json:"load_15min"`   // 空闲率
}

// MemoryEvent 内存统计数据
type MemoryUsageData struct {
    timestamp		time.Time `json:"timestamp"`    // 时间戳
    node_name		string    `json:"node_name"`    // 节点名称
	mem_total		uint64	  `json:"mem_total"`    // 节点名称
	mem_free		uint64    `json:"mem_free"`    // 节点名称
	mem_available	uint64	  `json:"mem_available"`    // 节点名称
	buffers			uint64	  `json:"buffers"`    // 节点名称
	cached			uint64        `json:"cached"`		// Cached
	swap_total		uint64    `json:"swap_total"`   		// SwapTotal
    swap_free		uint64    `json:"swap_free"`   		// SwapFree
}

// 磁盘性能统计数据
type DiskUsageData struct {
    timestamp				time.Time	`json:"timestamp"`   // 时间戳
    filesystem				string		`json:"filesystem"`  // 文件系统类型
    node_name				string		`json:"node_name"`   // 节点名称
	read_throughput_mb		float64		`json:"read_throughput_mb"`   // 读吞吐
	write_throughput_mb		float64 	`json:"write_throughput_mb"`   // 写吞吐
	total_throughput_mb		float64		`json:"total_throughput_mb"`   // 总吞吐
	read_iops				float64		`json:"read_iops"`   // 读IOPS
	write_iops				float64		`json:"write_iops"`   // 写IOPS
	total_iops				float64		`json:"total_iops"`   // 总IOPS
	avg_read_latency_ms		float64		`json:"avg_read_latency_ms"`   // 平均读时延
	avg_write_latency_ms	float64		`json:"avg_write_latency_ms"`   // 平均写时延
	utilization				float64		`json:"utilization"`   // CPU利用率
}

