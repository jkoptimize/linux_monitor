package exporter

import (
    "time"
)

// NetworkData 网络事件
type NetworkDatastruct struct {
    timestamp		time.Time	`json:"timestamp"` // 时间戳
    node_name		string		`json:"node_name"` // 节点名称
    snd_rcv_bytes		uint64	`json:"snd_rcv_bytes"`
    snd_rcv_packets		uint64	`json:"snd_rcv_packets"`
}

// SoftIRQData 软中断事件
type SoftIRQData struct {
    timestamp		time.Time	`json:"timestamp"` // 时间戳
    node_name		string		`json:"node_name"` // 节点名称
	HI				float64		`json:"HI"` // High-priority tasklets，高优先级任务软中断
	TIMER			float64		`json:"TIMER"` // 定时器软中断
	NET_TX			float64		`json:"NET_TX"` // 网卡发送软中断
	NET_RX			float64		`json:"NET_RX"` // 网卡接收软中断
	BLOCK			float64		`json:"BLOCK"` // 块设备IO软中断
	IRQ_POLL		float64		`json:"IRQ_POLL"` // Interrupt polling softirq，NAPI（New API）网络轮询中断
	TASKLET			float64		`json:"TASKLET"` // tasklets，普通优先级任务软中断
	SCHED			float64		`json:"SCHED"` // 调度相关的软中断
	HRTIMER			float64		`json:"HRTIMER"` // 高精度定时器软中断
	RCU				float64		`json:"RCU"` // RCU 机制的回调处理
}

// // HardIRQEvent 硬中断事件
// type HardIRQEvent struct {
//     Timestamp time.Time `json:"timestamp"` // 时间戳
//     IRQNumber uint32    `json:"irq_number"` // 中断号
//     CPU       string    `json:"cpu"`       // CPU核心
//     Device    string    `json:"device"`    // 设备名称
//     Count     uint64    `json:"count"`     // 中断次数
//     Latency   uint64    `json:"latency"`   // 处理延迟（纳秒）
//     NodeName  string    `json:"node_name"` // 节点名称
// }

type PerCPUData struct {
    user_time		float64   `json:"user_time"`   // 用户态时间
	nice_time		float64   `json:"nice_time"`   // nice进程时间
    system_time		float64   `json:"system_time"` // 系统态时间
    idle_time		float64   `json:"idle_time"`   // 空闲率
    iowait_time		float64   `json:"iowait_time"` // IO等待率
    steal_time		float64   `json:"steal_time"`  // 窃取时间（虚拟化）
	guest_time		float64   `json:"guest_time"`  // 运行虚拟机时间（虚拟化）
	guest_nic_time	float64   `json:"guest_nic_time"`	//运行低优先级虚拟机时间 (虚拟化)
}

// CPUUsageData CPU使用率数据
type CPUUsageData struct {
    timestamp		time.Time `json:"timestamp"`      // 时间戳
    node_name		string    `json:"node_name"`      // 节点名称
	core_list			[]uint32    `json:"core_list"`		// CPU核心编号
	per_cpu_data		[]PerCPUData `json:"per_cpu_data"`    // CPU核心数据
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

