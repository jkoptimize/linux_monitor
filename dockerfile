FROM golang:1.23

WORKDIR /app
COPY . /app/linux_monitor
RUN apt update && apt install  ca-certificates clang libelf1 libelf-dev zlib1g-dev libcap-dev binutils-dev -y

RUN cd /app/linux_monitor && go mod download

# RUN go build -o monitor_agent ./agent/main.go

RUN make -C /app/linux_monitor/monitor/ebpf -j2
RUN chmod +x /app/linux_monitor/entrypoint.sh

# 配置暴露端口和启动命令
EXPOSE 8080
# ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/linux_monitor/monitor/ebpf/.output
# ENTRYPOINT ["/bin/sh", "/app/linux_monitor/entrypoint.sh"]

CMD ["/app/linux_monitor/monitor/ebpf/monitor"]
