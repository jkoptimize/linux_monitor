package main

import (
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "os/exec"
    "os/signal"
    "syscall"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/perf"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// 事件数据结构（必须与C代码中的struct event匹配）
type Event struct {
    Pid       uint32
    Tid       uint32
    Timestamp uint64
    Latency   uint64
    Comm      [16]byte
    CpuID     uint32
}

type EBPFManager struct {
    collection *ebpf.Collection
    perfReader *perf.Reader
    stopChan   chan struct{}
    
    // Prometheus指标
    schedulerLatency *prometheus.HistogramVec
    contextSwitches  *prometheus.CounterVec
}

func NewEBPFManager() (*EBPFManager, error) {
    // 启动C加载器（生产环境应该用systemd管理）
    cmd := exec.Command("./cpuslatency")
    if err := cmd.Start(); err != nil {
        return nil, fmt.Errorf("failed to start eBPF loader: %w", err)
    }
    
    // 等待eBPF程序加载
    time.Sleep(2 * time.Second)
    
    // 打开eBPF映射
    coll, err := ebpf.LoadPinnedCollection("/sys/fs/bpf/cpuslatency", nil)
    if err != nil {
        return nil, fmt.Errorf("loading pinned collection: %w", err)
    }
    
    // 打开perf事件映射
    eventsMap, ok := coll.Maps["events"]
    if !ok {
        return nil, fmt.Errorf("events map not found")
    }
    
    perfReader, err := perf.NewReader(eventsMap, os.Getpagesize()*64)
    if err != nil {
        return nil, fmt.Errorf("creating perf reader: %w", err)
    }
    
    manager := &EBPFManager{
        collection: coll,
        perfReader: perfReader,
        stopChan:   make(chan struct{}),
    }
    
    // 初始化Prometheus指标
    manager.initMetrics()
    
    return manager, nil
}

func (m *EBPFManager) initMetrics() {
    m.schedulerLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "ebpf_scheduler_latency_nanoseconds",
        Help:    "Process scheduling latency measured by eBPF",
        Buckets: prometheus.ExponentialBuckets(1000, 2, 16), // 1us to 32ms
    }, []string{"comm", "cpu"})
    
    m.contextSwitches = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "ebpf_context_switches_total",
        Help: "Total context switches counted by eBPF",
    }, []string{"cpu"})
    
    prometheus.MustRegister(m.schedulerLatency)
    prometheus.MustRegister(m.contextSwitches)
}

func (m *EBPFManager) Start() {
    go m.processEvents()
    log.Println("eBPF manager started")
}

func (m *EBPFManager) processEvents() {
    for {
        select {
        case <-m.stopChan:
            return
        default:
            record, err := m.perfReader.Read()
            if err != nil {
                if perf.IsClosed(err) {
                    return
                }
                log.Printf("Error reading perf event: %v", err)
                continue
            }
            
            if record.LostSamples > 0 {
                log.Printf("Lost %d samples", record.LostSamples)
                continue
            }
            
            // 解析事件数据
            var event Event
            if err := binary.Read(record, binary.LittleEndian, &event); err != nil {
                log.Printf("Error parsing event: %v", err)
                continue
            }
            
            m.handleEvent(&event)
        }
    }
}

func (m *EBPFManager) handleEvent(event *Event) {
    // 转换进程名
    comm := string(event.Comm[:])
    for i, c := range comm {
        if c == 0 {
            comm = comm[:i]
            break
        }
    }
    
    cpu := fmt.Sprintf("%d", event.CpuID)
    
    // 更新Prometheus指标
    m.schedulerLatency.WithLabelValues(comm, cpu).Observe(float64(event.Latency))
    m.contextSwitches.WithLabelValues(cpu).Inc()
    
    // 调试输出（生产环境可关闭）
    if event.Latency > 1000000 { // > 1ms
        log.Printf("High latency: %s (pid=%d) on CPU %d: %.2fms", 
            comm, event.Pid, event.CpuID, float64(event.Latency)/1000000)
    }
}

func (m *EBPFManager) Stop() {
    close(m.stopChan)
    if m.perfReader != nil {
        m.perfReader.Close()
    }
    if m.collection != nil {
        m.collection.Close()
    }
    log.Println("eBPF manager stopped")
}

func main() {
    manager, err := NewEBPFManager()
    if err != nil {
        log.Fatalf("Failed to create eBPF manager: %v", err)
    }
    defer manager.Stop()
    
    manager.Start()
    
    // 启动Prometheus HTTP服务器
    http.Handle("/metrics", promhttp.Handler())
    go func() {
        log.Println("Starting metrics server on :8080")
        if err := http.ListenAndServe(":8080", nil); err != nil {
            log.Fatal(err)
        }
    }()
    
    // 等待中断信号
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    <-sigCh
    log.Println("Received interrupt signal, shutting down...")
}