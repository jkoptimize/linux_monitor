#!/bin/bash

set -e

echo "=== Starting Monitoring Demo Deployment ==="

# 创建必要的目录
mkdir -p prometheus/config
mkdir -p grafana/provisioning/datasources

# 生成Grafana配置文件
cat > prometheus/config/prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'linux_monitor'
    static_configs:
      - targets: ['linux_monitor:8080']
EOF

cat > grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
EOF

# 启动基础设施
echo "Starting Docker containers..."
docker-compose down
docker-compose up -d

# 等待服务启动
echo "Waiting for services to start..."
sleep 30

# 检查服务状态
echo "Checking services status..."
docker ps

# echo "=== Deployment Complete ==="
# echo "Grafana: http://localhost:3000 (admin/admin123)"
# echo "InfluxDB: http://localhost:8086 (admin/admin123)"
# echo "Monitoring API: http://localhost:8080"
# echo ""
# echo "Next steps:"
# echo "1. Run the monitoring service: go run server/main.go"
# echo "2. Open Grafana and create your dashboard"