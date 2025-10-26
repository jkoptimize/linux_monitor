package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    "context"

    // "linux_monitor/agent"
    "monitor/exporter"
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
    // log.Printf("Starting eBPF Monitoring Exporter %s", version)
    // logFile, err := os.OpenFile("monitor.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    // if err != nil {
    //     log.Fatalf("无法打开日志文件: %v", err)
    // }
    // defer logFile.Close()
    // log.SetOutput(logFile)

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
    
    // 定期更新指标
    go func() {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()
        metricsUpdater, err := exporter.NewMetricUpdater();
        if err != nil {
            log.Fatalf("Failed to NewMetricUpdater: %v", err)
        }

        for {
            select {
            case <-ticker.C:
                if err := metricsUpdater.UpdateSoftirqMetrics(); err != nil {
                    log.Printf("Failed to update Softirq metrics: ", err)
                }
                if err := metricsUpdater.UpdateCpuStatMetrics(); err != nil {
                    log.Printf("Failed to update CpuStat metrics: ", err)
                }
                if err := metricsUpdater.UpdateTrafficMetrics(); err != nil {
                    log.Printf("Failed to update Traffic metrics: ", err)
                }
                if err := metricsUpdater.UpdateTcpStatMetrics(); err != nil {
                    log.Printf("Failed to update TCP metrics: ", err)
                }
            }
        }
    }()

    
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
    
    // 停止exporter
    if err := export.Stop(); err != nil {
        log.Printf("Error stopping exporter: %v", err)
    }
    
    log.Println("Shutdown completed")
}