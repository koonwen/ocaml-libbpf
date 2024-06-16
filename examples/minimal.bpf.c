// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include "bpf/bpf_helpers.h" /* This is from our libbpf library */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Globals implemented as an array */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 5);
  __type(key, int);
  __type(value, long);
} globals SEC(".maps");

int my_pid_index = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx) {
  int pid = bpf_get_current_pid_tgid() >> 32;

  long *my_pid;
  my_pid = bpf_map_lookup_elem(&globals, &my_pid_index);
  if (my_pid == NULL) {
    bpf_printk("Error got NULL");
    return 1;
  };

  if (pid != *my_pid)
    return 0;

  bpf_printk("Hello, BPF triggered from PID %d", pid);

  return 0;
}
