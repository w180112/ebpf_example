// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2020 Huai-En Tseng <w180112@gmail.com>
 */

#define KBUILD_MODNAME "get_pkts"
#include "libbpf/include/uapi/linux/bpf.h"
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "libbpf/src/bpf_helpers.h"

#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))

#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

struct bpf_map_def SEC("maps") stat_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(long),
	.max_entries = 64,
};

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
			/* if ICMP received count reaches to 5, drop all ICMP pkts */ 
			if (*value > 5)
        		return XDP_DROP;
		}
	}
	else if (ip->protocol == IPPROTO_TCP) {
		value = bpf_map_lookup_elem(&stat_map, &map_index);
		if (value)
			__sync_fetch_and_add(value, 1);
		struct tcphdr *tcp = data + pkt_len;
		pkt_len += sizeof(struct tcphdr);
		if (data + pkt_len > data_end)
        	return XDP_DROP;
		/* drop all OpenVPN pkts */
		if (tcp->dest == htons(1194))
			return XDP_DROP;
	}
	else if (ip->protocol == IPPROTO_UDP) {
		value = bpf_map_lookup_elem(&stat_map, &map_index);
		if (value)
			__sync_fetch_and_add(value, 1);
		struct udphdr *udp = data + pkt_len;
		pkt_len += sizeof(struct udphdr);
		if (data + pkt_len > data_end)
        	return XDP_DROP;
		/* drop all OpenVPN pkts */
		if (udp->dest == htons(1194))
			return XDP_DROP;
	}
    return XDP_PASS;
}

char _license[] SEC("license") = "BSD";
