// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "net_monitor.h"

char __license[] SEC("license") = "GPL";

// eBPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, struct ip_packet_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} packetsInfo SEC(".maps");


SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    if (ctx->ifindex != ETH0_IFINDEX) {
        bpf_printk("Got packet not on eth0\n");
        return TC_ACT_OK;
    }

	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;
    bpf_printk("Get IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);

    u32 key = 0; // ingress
    struct ip_packet_info *pinfo = bpf_map_lookup_elem(&packetsInfo, &key);
    if (pinfo) {
        pinfo->snd_rcv_bytes += ctx->len;
        pinfo->snd_rcv_packets += 1;
    } else {
        struct ip_packet_info info = {};
        info.snd_rcv_bytes = ctx->len;
        info.snd_rcv_packets = 1;
        bpf_map_update_elem(&packetsInfo, &key, &info, BPF_NOEXIST);
    }

	return TC_ACT_OK;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx)
{
    if (ctx->ifindex != ETH0_IFINDEX) {
        bpf_printk("Got packet not on eth0\n");
        return TC_ACT_OK;
    }

	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	bpf_printk("SendOut IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);

    u32 key = 1; // egress
    struct ip_packet_info *pinfo = bpf_map_lookup_elem(&packetsInfo, &key);
    if (pinfo) {
        pinfo->snd_rcv_bytes += ctx->len;
        pinfo->snd_rcv_packets += 1;
    } else {
        struct ip_packet_info info = {};
        info.snd_rcv_bytes = ctx->len;
        info.snd_rcv_packets = 1;
        bpf_map_update_elem(&packetsInfo, &key, &info, BPF_NOEXIST);
    }

	return TC_ACT_OK;
}

