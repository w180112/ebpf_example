# eBPF / XDP example application using CO-RE

[![BSD license](https://img.shields.io/badge/License-BSD-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

This is an eBPF / XDP example application using CO-RE in C.

## Purpose

1. Using XDP to statistic received packets and print result in user space application.
2. Only C language and libbpf are used.
3. After compiled, there is a get_pkts user space applicaiton, it will load get_pkts_kern.o elf files to kernel and hook to network device.

## System required:

1. Linux OS
2. Kernel version newer than 5.0

## How to use:

Git clone this repository

	# git clone https://github.com/w180112/ebpf_example.git

Type

	# cd ebpf_example

Run

	# make

to compile

Then

	# ./get_pkts

To remove the binary files

	# make clean