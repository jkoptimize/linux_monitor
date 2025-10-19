package main

import (
    "os"
    "strconv"
    "time"
)

type ExporterConfig struct {
    ListenAddress   string
    MetricsPath     string
    EnableProfiling bool
    ReadTimeout     time.Duration
    WriteTimeout    time.Duration
    NodeName        string
    LogLevel        string
}

func LoadConfig() *ExporterConfig {
    return &ExporterConfig{
        ListenAddress:   getEnv("LISTEN_ADDRESS", ":8080"),
        MetricsPath:     getEnv("METRICS_PATH", "/metrics"),
        EnableProfiling: getEnvBool("ENABLE_PPROF", false),
        ReadTimeout:     getEnvDuration("READ_TIMEOUT", 10*time.Second),
        WriteTimeout:    getEnvDuration("WRITE_TIMEOUT", 30*time.Second),
        NodeName:        getEnv("NODE_NAME", getHostname()),
        LogLevel:        getEnv("LOG_LEVEL", "info"),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
    if value := os.Getenv(key); value != "" {
        if parsed, err := strconv.ParseBool(value); err == nil {
            return parsed
        }
    }
    return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if parsed, err := time.ParseDuration(value); err == nil {
            return parsed
        }
    }
    return defaultValue
}

func getHostname() string {
    if hostname, err := os.Hostname(); err == nil {
        return hostname
    }
    return "unknown"
}