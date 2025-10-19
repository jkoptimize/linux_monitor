package exporter

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "github.com/prometheus/client_golang/prometheus/collectors"
)

// EBPFExporter 主exporter结构
type EBPFExporter struct {
    registry *prometheus.Registry
    server   *http.Server
    config   *Config
    
    // 指标收集器
    collectors []prometheus.Collector
    
    // 同步控制
    mu       sync.RWMutex
    isRunning bool
}

// Config 配置结构
type Config struct {
    ListenAddress string
    MetricsPath   string
    EnableProfiling bool
    ReadTimeout   time.Duration
    WriteTimeout  time.Duration
}

// NewEBPFExporter 创建新的exporter实例
func  NewEBPFExporter(config *Config) *EBPFExporter {
    // 创建自定义注册表（避免与默认注册表冲突）
    registry := prometheus.NewRegistry()
    
    exporter := &EBPFExporter{
        registry: registry,
        config:   config,
    }
    
    // 注册内置收集器
    exporter.registerBuiltinCollectors()
    
    return exporter
}

// registerBuiltinCollectors 注册内置收集器
func (e *EBPFExporter) registerBuiltinCollectors() {
    // // 注册Go运行时指标（可选）
    // e.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
    // e.registry.MustRegister(collectors.NewGoCollector())
    
    // 注册exporter自身指标
    e.registry.MustRegister(collectors.NewBuildInfoCollector())
    
    // 注册自定义业务指标
    e.registerCustomMetrics()
}

// registerCustomMetrics 注册自定义eBPF指标
func (e *EBPFExporter) registerCustomMetrics() {
    // 这里注册所有eBPF相关的指标
    metrics := createEBPFMetrics()
    for _, metric := range metrics {
        if err := e.registry.Register(metric); err != nil {
            log.Printf("Failed to register metric softirq: %v", err)
        } else {
            e.collectors = append(e.collectors, metric)
        }
    }
}

// Start 启动exporter
func (e *EBPFExporter) Start() error {
    e.mu.Lock()
    defer e.mu.Unlock()
    
    if e.isRunning {
        return fmt.Errorf("exporter is already running")
    }
    
    // 设置HTTP路由
    mux := http.NewServeMux()
    mux.Handle(e.config.MetricsPath, e.metricsHandler())
    mux.Handle("/health", e.healthHandler())
    mux.Handle("/", e.rootHandler())
    
    if e.config.EnableProfiling {
        mux.Handle("/debug/pprof/", http.DefaultServeMux)
    }
    
    // 创建HTTP服务器
    e.server = &http.Server{
        Addr:         e.config.ListenAddress,
        Handler:      mux,
        ReadTimeout:  e.config.ReadTimeout,
        WriteTimeout: e.config.WriteTimeout,
    }
    
    // 启动服务器
    go func() {
        log.Printf("Starting Prometheus exporter on %s", e.config.ListenAddress)
        log.Printf("Metrics available at http://%s%s", e.config.ListenAddress, e.config.MetricsPath)
        
        if err := e.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("Failed to start exporter: %v", err)
        }
    }()
    
    e.isRunning = true
    return nil
}

// Stop 优雅停止exporter
func (e *EBPFExporter) Stop() error {
    e.mu.Lock()
    defer e.mu.Unlock()
    
    if !e.isRunning {
        return nil
    }
    
    log.Println("Shutting down Prometheus exporter...")
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    if err := e.server.Shutdown(ctx); err != nil {
        return fmt.Errorf("failed to shutdown exporter: %w", err)
    }
    
    e.isRunning = false
    log.Println("Prometheus exporter stopped")
    return nil
}

// metricsHandler 指标端点处理器
func (e *EBPFExporter) metricsHandler() http.Handler {
    return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{
        Timeout:           10 * time.Second,
        EnableOpenMetrics: true, // 支持OpenMetrics格式
        ErrorLog:          log.Default(),
        ErrorHandling:     promhttp.ContinueOnError,
    })
}

// healthHandler 健康检查端点
func (e *EBPFExporter) healthHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, `{"status": "healthy", "timestamp": "%s"}`, time.Now().Format(time.RFC3339))
    })
}

// rootHandler 根路径处理器
func (e *EBPFExporter) rootHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
            http.NotFound(w, r)
            return
        }
        
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `
        <html>
            <head><title>eBPF Monitoring Exporter</title></head>
            <body>
                <h1>eBPF Monitoring Exporter</h1>
                <p><a href="%s">Metrics</a></p>
                <p><a href="/health">Health Check</a></p>
                <p><a href="/debug/pprof/">Profiling</a></p>
            </body>
        </html>`, e.config.MetricsPath)
    })
}

// GetRegistry 获取指标注册表（用于外部注册指标）
func (e *EBPFExporter) GetRegistry() *prometheus.Registry {
    return e.registry
}

// IsRunning 检查exporter是否在运行
func (e *EBPFExporter) IsRunning() bool {
    e.mu.RLock()
    defer e.mu.RUnlock()
    return e.isRunning
}