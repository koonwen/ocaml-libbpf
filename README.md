[![OCaml-CI Build Status](https://img.shields.io/endpoint?url=https://ocaml.ci.dev/badge/koonwen/ocaml-libbpf/main&logo=ocaml)](https://ocaml.ci.dev/github/koonwen/ocaml-libbpf)

# ocaml-libbpf
Libbpf C-bindings for eBPF userspace programs.

Writing eBPF programs consist of two distinct parts. Implementing the
code that executes in-kernel **and** user-level code responsible for
loading/initializing/linking/teardown of the in-kernel code. This
OCaml library provides the latter via binding the C
[libbpf](https://github.com/libbpf/libbpf) library. It exposes both
the raw low-level bindings as well as a set of high-level API's for
handling your eBPF objects. As of now, the kernel part must still be
written in [restricted
C](https://stackoverflow.com/questions/57688344/what-is-not-allowed-in-restricted-c-for-ebpf)
and compiled to eBPF bytecode.

The full API set of Libbpf is quite large, see [supported](supported.json) for the list
of currently bound API's. Contributions are welcome.

# Usage
See `examples` directory on how ocaml\_libbpf can be used to interact
with eBPF kernel programs defined in *.bpf.c source files. The
high-level API's provided in ocaml\_libbpf make it easy to perform
repetitive tasks like open/load/linking/initializing/teardown.

To run these examples, clone this repository and set up the package with
```bash
git clone git@github.com:koonwen/ocaml-libbpf.git
cd ocaml_libbpf
opam install . --deps-only
eval $(opam env)
```

then use `make <minimal/kprobe/bootstrap>`. These examples are taken
from [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
repository and rewritten in OCaml.

### Open/Load/Link
Now let's run through an example of how we would use
ocaml\_libbpf. This usage tutorial assumes some knowledge of how to
write eBPF programs in C. If not, you can check out this
[resource](https://nakryiko.com/posts/libbpf-bootstrap/#the-bpf-side). ocaml\_libbpf
provides an easy API to install your eBPF program into the kernel. Say
your eBPF kernel program looks like this.

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include "bpf/bpf_helpers.h" /* This is from our libbpf library */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Globals implemented as an array */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
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

```

Users just need to provide the path to the compiled bpf
object, the name of the program and optionally an initialization
function.

```ocaml
let obj_path = "minimal.bpf.o"
let program_names = [ "handle_tp" ]
let map = "globals"

(* Load PID into BPF map*)
let before_link obj =
  let pid = Unix.getpid () |> Signed.Long.of_int in
  let global_map = bpf_object_find_map_by_name obj map in
  bpf_map_update_elem ~key_ty:Ctypes.int ~val_ty:Ctypes.long global_map 0 pid

let () =
  with_bpf_object_open_load_link ~obj_path ~program_names ~before_link
    (fun _obj _link ->
      let exitting = ref true in
      let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
      Sys.(set_signal sigint sig_handler);
      Sys.(set_signal sigterm sig_handler);

      Printf.printf
        "Successfully started! Please run `sudo cat \
         /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF \
         programs.\n\
         %!";

      (* Loop until Ctrl-C is called *)
      while !exitting do
        Printf.eprintf ".%!";
        Unix.sleepf 1.0
      done)
```

### Maps
`ocaml_libbpf_maps` is an optional convenience package that provides
wrappers for BPF maps. Currently only Ringbuffer maps are added. An
example usage of them can be found in
[examples/bootstrap.ml](./examples/bootstrap.ml). This has been
packaged separately since it drags in `libffi` dependency.

### Would be nice to support
- [ ] Integration with bpftool & bindings for generated skel code

# Developer Notes
## Build
libbpf API's provide both userland and kernel API's. Typically,
bpf_helpers.h, bpf_core_read.h, bpf_tracing.h define the
kernel API's. Userland API definitions are found in libbpf.h

## Kernel compatibility
No ties to any specific kernel, transparent handling of older
kernels. Libbpf is designed to be kernel-agnostic and work across
multitude of kernel versions. It has built-in mechanisms to gracefully
handle older kernels, that are missing some of the features, by
working around or gracefully degrading functionality. Thus libbpf is
not tied to a specific kernel version and can/should be packaged and
versioned independently.
