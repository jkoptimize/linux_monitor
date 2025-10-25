FROM golang:1.23

WORKDIR /app
COPY . /app/linux_monitor

RUN \
    # 1. 清理旧的配置，确保一个干净的状态
    rm -f /etc/apt/sources.list && \
    rm -rf /etc/apt/sources.list.d/* && \
    \
    # 2. 【关键修正】从 /etc/os-release 文件中获取版本代号
    # '. /etc/os-release' 的作用是加载该文件中的变量 (如 VERSION_CODENAME)
    DEBIAN_VERSION=$(. /etc/os-release && echo "$VERSION_CODENAME") && \

    echo "deb http://mirrors.aliyun.com/debian/ ${DEBIAN_VERSION} main contrib non-free" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian/ ${DEBIAN_VERSION}-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian/ ${DEBIAN_VERSION}-backports main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/debian-security/ ${DEBIAN_VERSION}-security main contrib non-free" >> /etc/apt/sources.list

RUN apt update && apt install  ca-certificates clang libelf1 libelf-dev zlib1g-dev libcap-dev binutils-dev libssl-dev -y

RUN cd /app/linux_monitor/monitor && go env -w GOPROXY=https://goproxy.cn && go mod init monitor && go mod tidy

# RUN go build -o monitor_agent ./agent/main.go

RUN make -C /app/linux_monitor/monitor/ebpf build-go -j2

# 配置暴露端口和启动命令
EXPOSE 8080

# ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/app/linux_monitor/monitor/ebpf/.output
# export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/syt/linux_monitor/monitor/ebpf/.output
# ENTRYPOINT ["/bin/sh", "/app/linux_monitor/entrypoint.sh"]

CMD ["/app/linux_monitor/monitor/ebpf/monitor"]
