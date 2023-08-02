// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2020 Huai-En Tseng <w180112@gmail.com>
 */

#define KBUILD_MODNAME "get_pkts"
#include "vmlinux.h"
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
    __type(value, long);
	__uint(max_entries, 64);
} stat_map SEC(".maps");

SEC("get_pkts")
int xdp_count(struct xdp_md *ctx) {
    int pkt_len = 0, map_index;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end; 
	struct ethhdr *eth = data;
    struct iphdr *ip;
	long *value;

	pkt_len = sizeof(*eth);
    ip = data + pkt_len;
    pkt_len += sizeof(struct iphdr);
	
	if (data + pkt_len > data_end)
        return XDP_DROP;
	map_index = ip->protocol;
	
	if (ip->protocol == IPPROTO_ICMP) {
		value = bpf_map_lookup_elem(&stat_map, &map_index);
		if (value) {
			__sync_fetch_and_add(value, 1);
		}
		bpf_printk("rcv packet at queue %u, ip = %x\n", ctx->rx_queue_index, bpf_ntohl(ip->daddr));
	}
	else if (ip->protocol == IPPROTO_TCP) {
		value = bpf_map_lookup_elem(&stat_map, &map_index);
		if (value)
			__sync_fetch_and_add(value, 1);
		struct tcphdr *tcp = data + pkt_len;
		pkt_len += sizeof(struct tcphdr);
		if (data + pkt_len > data_end)
        	return XDP_DROP;
		bpf_printk("rcv packet at queue %u, ip = %x\n", ctx->rx_queue_index, bpf_ntohl(ip->daddr));
	}
	else if (ip->protocol == IPPROTO_UDP) {
		value = bpf_map_lookup_elem(&stat_map, &map_index);
		if (value)
			__sync_fetch_and_add(value, 1);
		struct udphdr *udp = data + pkt_len;
		pkt_len += sizeof(struct udphdr);
		if (data + pkt_len > data_end)
        	return XDP_DROP;
		bpf_printk("rcv packet at queue %u, ip = %x\n", ctx->rx_queue_index, bpf_ntohl(ip->daddr));
	}
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
