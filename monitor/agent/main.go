package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    "context"

    // "linux_monitor/agent"
    "linux_monitor/exporter"
    // "ebpf-monitoring/ebpf"
)

// 构建信息（可以通过构建参数注入）
var (
    version   = "dev"
    revision  = "unknown"
    branch    = "unknown"
    goVersion = "unknown"
)

func main() {
    log.Printf("Starting eBPF Monitoring Exporter %s", version)
    
    // 加载配置
    cfg := LoadConfig()
    
    // 创建并启动exporter
    expConfig := &exporter.Config{
        ListenAddress:   cfg.ListenAddress,
        MetricsPath:     cfg.MetricsPath,
        EnableProfiling: cfg.EnableProfiling,
        ReadTimeout:     cfg.ReadTimeout,
        WriteTimeout:    cfg.WriteTimeout,
    }
    
    export := exporter.NewEBPFExporter(expConfig)
    
    // 设置构建信息
    exporter.SetBuildInfo(version, revision, branch, goVersion)
    
    // 启动exporter
    if err := export.Start(); err != nil {
        log.Fatalf("Failed to start exporter: %v", err)
    }
    
    // // 初始化eBPF监控
    // ebpfManager, err := ebpf.NewEBPFManager(cfg.NodeName)
    // if err != nil {
    //     log.Fatalf("Failed to initialize eBPF manager: %v", err)
    // }
    
    // // 启动eBPF数据收集
    // if err := ebpfManager.Start(); err != nil {
    //     log.Fatalf("Failed to start eBPF manager: %v", err)
    // }

    // 定期更新指标
    go func() {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()
        metricsUpdater, _ := exporter.NewMetricUpdater();
        

        for {
            select {
            case <-ticker.C:
                if err := metricsUpdater.UpdateSoftirqMetrics(); err != nil {
                    log.Printf("Failed to update metrics: %v", err)
                }
            }
        }
    }()
    
    // // 设置指标更新回调
    // metricUpdater := exporter.NewMetricUpdater()
    // ebpfManager.SetMetricUpdater(metricUpdater)
    
    log.Println("eBPF monitoring system is fully operational")
    
    // 等待中断信号
    waitForShutdown(export)
}

func waitForShutdown(export *exporter.EBPFExporter) {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
    
    sig := <-sigCh
    log.Printf("Received signal %v, initiating shutdown...", sig)
    
    // 优雅关闭
    _, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // // 停止eBPF监控
    // if err := ebpfManager.Stop(); err != nil {
    //     log.Printf("Error stopping eBPF manager: %v", err)
    // }
    
    // 停止exporter
    if err := export.Stop(); err != nil {
        log.Printf("Error stopping exporter: %v", err)
    }
    
    log.Println("Shutdown completed")
}