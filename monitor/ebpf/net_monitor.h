#ifndef _NET_MONITOR_H
#define _NET_MONITOR_H

typedef unsigned long long __u64;

#define LO_IFINDEX 1
#define ETH0_IFINDEX 2

#define TC_ACT_OK 0
#define ETH_P_IP  0x0800 /* Internet Protocol packet	*/

struct ip_packet_info {
    __u64 snd_rcv_bytes;
    __u64 snd_rcv_packets;
    __u64 err_in_out;
    __u64 drop_in_out;
};


#endif /* _NET_MONITOR_H */