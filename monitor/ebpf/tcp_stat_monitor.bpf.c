// tcplatency.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10

// 【最终 Key 格式】: {Local IP, Peer IP, Local Port, Peer Port}
struct conn_key_t {
    __u16 family; // 2 bytes
    __be16 sport;  // Local Port (skc_num -> sport)
    __be16 dport;  // Peer Port (skc_dport -> dport)
    __u16 pad;     // 2 bytes 填充，确保总大小 40 字节
    __u8 saddr[16]; // Local Address (skc_rcv_saddr -> saddr)
    __u8 daddr[16]; // Peer Address (skc_daddr -> daddr)
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct conn_key_t);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 24);
    __type(key, u32);
    __type(value, u64);
} hist SEC(".maps");


static __always_inline __u16 my_ntohs(__u16 net_val) {
    return __builtin_bswap16(net_val);
}

static __always_inline u32 log2_impl(u64 n) {
    u32 log = 0;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (n > 1) {
            n >>= 1;
            log++;
        } else {
            break;
        }
    }
    return log;
}


static __always_inline
int get_conn_key_from_req(struct request_sock *req, struct conn_key_t *key, __u16 family) {
    __builtin_memset(key, 0, sizeof(struct conn_key_t));
    __u16 host_port_num;

    // 端口信息对于 IPv4 和 IPv6 的读取方式是相同的
    bpf_probe_read_kernel(&host_port_num, sizeof(host_port_num), &req->__req_common.skc_num);
    key->sport = __builtin_bswap16(host_port_num);
    bpf_probe_read_kernel(&key->dport, sizeof(key->dport), &req->__req_common.skc_dport);

    if (family == AF_INET) {
        // --- 这是关键的修改部分 ---
        // 策略：即使是 IPv4 连接，也将其规范化为 IPv4 映射的 IPv6 地址格式存储
        // 这样就能和后续 tcp_set_state 中从双栈套接字里读出的格式保持一致

        key->family = AF_INET6; // 1. 统一将 Family 设置为 AF_INET6

        __be32 temp_saddr, temp_daddr;
        bpf_probe_read_kernel(&temp_saddr, sizeof(temp_saddr), &req->__req_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&temp_daddr, sizeof(temp_daddr), &req->__req_common.skc_daddr);

        // 2. 手动构建 IPv4-mapped-IPv6 地址 (::ffff:xxx.xxx.xxx.xxx)
        // saddr
        key->saddr[10] = 0xff;
        key->saddr[11] = 0xff;
        __builtin_memcpy(key->saddr + 12, &temp_saddr, sizeof(temp_saddr));

        // daddr
        key->daddr[10] = 0xff;
        key->daddr[11] = 0xff;
        __builtin_memcpy(key->daddr + 12, &temp_daddr, sizeof(temp_daddr));

    } else if (family == AF_INET6) {
        // 对于纯 IPv6 连接，逻辑保持不变
        key->family = AF_INET6;
        bpf_probe_read_kernel(key->saddr, sizeof(key->saddr), &req->__req_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(key->daddr, sizeof(key->daddr), &req->__req_common.skc_v6_daddr);

    } else {
        return -1;
    }

    // --- 日志打印部分可以保持不变，用于调试 ---
    bpf_printk("[KEY REQ] (Normalized) FAMILY: %x SPORT: %x DPORT: %x",
            key->family, my_ntohs(key->sport), my_ntohs(key->dport));
    bpf_printk("[KEY REQ] SADDR (0-7): %llx", *(__u64*)key->saddr);
    bpf_printk("[KEY REQ] SADDR (8-15): %llx", *(__u64*)(key->saddr + 8));
    bpf_printk("[KEY REQ] DADDR (0-7): %llx", *(__u64*)key->daddr);
    bpf_printk("[KEY REQ] DADDR (8-15): %llx", *(__u64*)(key->daddr + 8));

    return 0;
}


static __always_inline
int get_conn_key_from_sock(struct sock *sk, struct conn_key_t *key) {
    __builtin_memset(key, 0, sizeof(struct conn_key_t));
    __u16 host_port_num;
    __u16 family; 
    
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

    if (family == AF_INET) {
        key->family = AF_INET6; 
        __be32 temp_saddr, temp_daddr;

        bpf_probe_read_kernel(&temp_saddr, sizeof(temp_saddr), &sk->__sk_common.skc_rcv_saddr); 
        bpf_probe_read_kernel(&temp_daddr, sizeof(temp_daddr), &sk->__sk_common.skc_daddr); 
        key->saddr[10] = 0xff;
        key->saddr[11] = 0xff;
        __builtin_memcpy(key->saddr + 12, &temp_saddr, sizeof(temp_saddr));
        key->daddr[10] = 0xff;
        key->daddr[11] = 0xff;
        __builtin_memcpy(key->daddr + 12, &temp_daddr, sizeof(temp_daddr));
        
        bpf_probe_read_kernel(&host_port_num, sizeof(host_port_num), &sk->__sk_common.skc_num);
        key->sport = __builtin_bswap16(host_port_num);         
        bpf_probe_read_kernel(&key->dport, sizeof(key->dport), &sk->__sk_common.skc_dport);
    } else if (family == AF_INET6) {
        key->family = AF_INET6;
        bpf_probe_read_kernel(key->saddr, sizeof(key->saddr), &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_probe_read_kernel(key->daddr, sizeof(key->daddr), &sk->__sk_common.skc_v6_daddr);

        bpf_probe_read_kernel(&host_port_num, sizeof(host_port_num), &sk->__sk_common.skc_num);
        key->sport = __builtin_bswap16(host_port_num); 
        bpf_probe_read_kernel(&key->dport, sizeof(key->dport), &sk->__sk_common.skc_dport);
    } else {
        return -1;
    }
    
    bpf_printk("[KEY SOCK] FAMILY: %x SPORT: %x DPORT: %x PAD: %x", 
            key->family, key->sport, key->dport, key->pad);
    bpf_printk("[KEY REQ] SADDR (0-7): %llx", 
            *(__u64*)key->saddr);
    bpf_printk("[KEY REQ] SADDR (8-15): %llx", 
            *(__u64*)(key->saddr + 8));
    bpf_printk("[KEY REQ] DADDR (0-7): %llx", 
            *(__u64*)key->daddr);
    bpf_printk("[KEY REQ] DADDR (8-15): %llx", 
            *(__u64*)(key->daddr + 8));
    return 0;
}




SEC("kprobe/inet_csk_reqsk_queue_hash_add")
int BPF_KPROBE(kp_inet_csk_reqsk_queue_hash_add, struct sock *sk, struct request_sock *req, unsigned short state) {
    struct conn_key_t key = {};
    if (get_conn_key_from_req(req, &key, AF_INET) != 0) {
        bpf_printk("[kp_inet_csk_reqsk_queue_hash_add] FAILED TO GET KEY! RET");
        return 0;
    }
    u64 ts = bpf_ktime_get_ns();
    
    int ret = bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    if (ret != 0) {
        bpf_printk("[kp_inet_csk_reqsk_queue_hash_add] FAILED TO UPDATE MAP! RET: %d", ret);
    }
    return 0;
}

SEC("kprobe/inet6_csk_reqsk_queue_hash_add")
int BPF_KPROBE(kp_inet6_csk_reqsk_queue_hash_add, struct sock *sk, struct request_sock *req, unsigned short state) {
    struct conn_key_t key = {};
    if (get_conn_key_from_req(req, &key, AF_INET6) != 0) {
        bpf_printk("[kp_inet6_csk_reqsk_queue_hash_add] FAILED TO GET KEY! RET");
        return 0;
    }

    u64 ts = bpf_ktime_get_ns();
    int ret = bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
    if (ret != 0) {
        bpf_printk("[kp_inet6_csk_reqsk_queue_hash_add] FAILED TO UPDATE MAP! RET: %d", ret);
    }
    return 0;
}


SEC("kprobe/tcp_set_state")
int BPF_KPROBE(kp_tcp_set_state, struct sock *sk, int state) {
    if (state != TCP_ESTABLISHED) {
        return 0;
    }
    
    struct conn_key_t key = {};
    if (get_conn_key_from_sock(sk, &key) != 0) {
        return 0;
    }
    bpf_printk("[tcp_set_state] %s: %pI:%u -> %pI:%u", 
                (key.family == AF_INET) ? "IPv4" : "IPv6",
                key.saddr, my_ntohs(key.sport), 
                key.daddr, my_ntohs(key.dport));


    u64 *tsp = bpf_map_lookup_elem(&start, &key);
    if (!tsp) {
        bpf_printk("[tcp_set_state] FAILED to find start timestamp for key.");
        return 0;
    }

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    bpf_map_delete_elem(&start, &key);

    u64 delta_us = delta_ns / 1000;
    bpf_printk("TCP Latency: %llu us", delta_us);

    u32 slot = log2_impl(delta_us);
    if (slot >= 24) {
        slot = 23;
    }

    u64 *count = bpf_map_lookup_elem(&hist, &slot);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init_val = 1;
        bpf_map_update_elem(&hist, &slot, &init_val, BPF_NOEXIST);
    }

    return 0;
}