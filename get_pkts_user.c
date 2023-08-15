// SPDX-License-Identifier: BSD-3-Clause
/* Copyright (c) 2020 Huai-En Tseng <w180112@gmail.com>
 */

#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <bpf.h>
#include <libbpf.h>
#include <arpa/inet.h>
#include <assert.h>
#include <sys/resource.h>

int 				ifindex_list;
struct bpf_object 	*obj;
uint32_t 			xdp_flags;

static void int_exit(int sig)
{
	bpf_xdp_detach(ifindex_list, xdp_flags, NULL);
	exit(0);
}

int load_bpf_object_file__simple(const char *filename)
{
	int prog_fd = -1;
	int err;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		printf("open object file failed: %s\n", strerror(errno));
		return -1;
	}
	struct bpf_program *prog = bpf_object__next_program(obj, NULL);
	if (prog == NULL) {
		printf("find program in object failed: %s\n", strerror(errno));
		return -1;
	}
	if (bpf_program__set_type(prog, BPF_PROG_TYPE_XDP) < 0) {
		printf("set bpf type to xdp failed: %s\n", strerror(errno));
		return -1;
	}
	err = bpf_object__load(obj);
	if (err) {
		printf("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	prog_fd = bpf_program__fd(prog);

	if (!prog_fd) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n", filename, err, strerror(-err));
		return -1;
	}

	return prog_fd;
}

int main(int argc, char **argv)
{
	int i, err;
	int prog_fd, map_fd;
	int attach = 1;
	int ret = 0;
	struct bpf_map *map;

	if (argc != 3) {
		printf("Usage: ./get_pkts <interface name> <--skb-mode | --drv-mode>\n");
		return -1;
	}

	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if ((err = setrlimit(RLIMIT_MEMLOCK, &rlim_new))) {
		fprintf(stderr, "failed to increase rlimit: %d", err);
		return 1;
	}

	prog_fd = load_bpf_object_file__simple("get_pkts_kern.o");
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: loading file: %s\n", "get_pkts_kern.o");
		return -1;
	}

	if (attach) {
		ifindex_list = if_nametoindex(argv[1]);
		xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
		if (strncmp(argv[2], "--skb-mode", strlen(argv[2])) == 0)
			xdp_flags |= XDP_FLAGS_SKB_MODE;
		else
			xdp_flags |= XDP_FLAGS_DRV_MODE;
		
		err = bpf_xdp_attach(ifindex_list, prog_fd, xdp_flags, NULL);
		if (ret == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
			uint32_t old_flags = xdp_flags;

			xdp_flags &= ~XDP_FLAGS_MODES;
			xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
			if (bpf_xdp_detach(ifindex_list, xdp_flags, NULL) == 0) {
				printf("try to attach xdp again...\n");
				err = bpf_xdp_attach(ifindex_list, prog_fd, old_flags, NULL);
			}
		}
		if (err < 0) {
			fprintf(stderr, "ERR: ifindex(%d) link set xdp fd failed (%d): %s\n", ifindex_list, -err, strerror(-err));
			switch (-err) {
			case EBUSY:
			case EEXIST:
				fprintf(stderr, "XDP already loaded on the device %s\n", argv[1]);
				break;
			case ENOMEM:
			case EOPNOTSUPP:
				fprintf(stderr, "Native-XDP not supported on the device %s, try using --skb-mode\n", argv[1]);
				break;
			default:
				break;
			}
			goto cleanup;
		}
		map = bpf_object__find_map_by_name(obj, "stat_map");
        if (!map) {
			fprintf(stderr, "ERR: cannot find map by name: %s\n", "stat_map");
			goto cleanup;
		}
		map_fd = bpf_map__fd(map);
	}

	signal(SIGINT, int_exit);
	long val = 0;
	if (attach) {
		long cnt;
		for (i=0; i<64; i++) {
			assert(bpf_map_lookup_elem(map_fd, &i, &cnt) == 0);
			if (cnt != 0) {
				if (bpf_map_update_elem(map_fd, &i, &val, BPF_ANY) < 0)
					perror("update elem failed");
			}
		}
	}
	for(;;) {
		long tcp_cnt, udp_cnt, icmp_cnt;
		int key;

		key = IPPROTO_TCP;
		assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

		key = IPPROTO_UDP;
		assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

		key = IPPROTO_ICMP;
		assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

		printf("TCP %ld UDP %ld ICMP %ld bytes\n", tcp_cnt, udp_cnt, icmp_cnt);
		sleep(1);
	}
	return ret;
cleanup:
	bpf_xdp_detach(ifindex_list, xdp_flags, NULL);
	return 1;
}
