// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, unsigned long);
} packet_count SEC(".maps");

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    int key = 0;
    unsigned long *value;

    value = bpf_map_lookup_elem(&packet_count, &key);
    if (value)
        __sync_fetch_and_add(value, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
