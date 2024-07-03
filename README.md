[![OCaml-CI Build Status](https://img.shields.io/endpoint?url=https://ocaml.ci.dev/badge/koonwen/ocaml-libbpf/main&logo=ocaml)](https://ocaml.ci.dev/github/koonwen/ocaml-libbpf)
- [API documentation](https://koonwen.github.io/ocaml-libbpf/)

# ocaml-libbpf
Libbpf C-bindings for loading eBPF ELF files into the kernel with OCaml.

Writing eBPF programs consist of two distinct parts. Implementing the
code that executes in-kernel **and** user-level code responsible for
loading/initializing/linking/teardown of the in-kernel code. This
OCaml library provides the latter via binding the C
[libbpf](https://github.com/libbpf/libbpf) library. It exposes both
the raw low-level bindings as well as a set of high-level API's for
handling your eBPF objects. As of now, the kernel part must still be
written in [restricted
C](https://stackoverflow.com/questions/57688344/what-is-not-allowed-in-restricted-c-for-ebpf)
and compiled with llvm to eBPF bytecode.

The full API set of Libbpf is quite large, see [supported](supported.json) for the list
of currently bound API's. Contributions are welcome.

### External dependencies
ocaml-libbpf depends on the system package of `libbpf`.

# Usage
> ⚠️ **Disambiguation:** The name of this repository and
> references to it will be "ocaml-libbpf". However, the library's
> entry module and package name is **Libbpf**. To install it, you
> would use `opam install libbpf`. To access it's High-level API's use
> `Libbpf.<api>`. To use the raw bindings, they are exposed in
> `Libbpf.C.<api>` namespace.

See `examples` directory on how ocaml-libbpf can be used to load eBPF
ELF files into the kernel and interact with the loaded kernel program.
The eBPF kernel programs are defined in *.bpf.c source files and are
compiled with clang as specified in the `dune` rules. ocaml-libbpf
exposes some high-level API's exposed by the toplevel `Libbpf` module
to make it easy to perform repetitive tasks such as
open/load/linking/initializing/teardown of bpf programs.

To run these examples, clone this repository and set up the package with
```bash
git clone git@github.com:koonwen/ocaml-libbpf.git
cd ocaml-libbpf
opam install . --deps-only
eval $(opam env)
```

then run `make < minimal | kprobe | bootstrap | tc >` to try out the
different bpf programs. These examples are all taken from
[libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
repository and rewritten in OCaml.

### Open/Load/Link
Now let's run through an example of how we would use
ocaml-libbpf. This usage tutorial assumes some knowledge of how to
write eBPF kernel programs in C compile them to ELF files. If not, you
can check out this
[resource](https://nakryiko.com/posts/libbpf-bootstrap/#the-bpf-side). ocaml-libbpf
provides an easy API to install your eBPF program into the kernel. Say
your eBPF kernel program looks like this where we print something
whenever the syscall `write` event occurs. We also want to implement a
filtering mechanism to only print on `write` calls for our process. To
do this, we initialize a BPF array map with a single entry that works
like a holder for our global variable. The BPF map is neccessary to
because it allows us to communicate values between user and kernel
space.

> The libbpf C library in fact already supports declarations of global
> variables in the usual form with the ability to manage them in user
> space. However for various technical reasons, ocaml-libbpf does not
> enable that feature yet. So we use the old style of working with
> global variables here.

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

After compilation to eBPF ELF file as `minimal.o`. Users just need to
provide the path to this ELF file along with the name of the program
and optionally an initialization function. Note that the name of the
program refers to the function identifier under the SEC(...)
attribute, in this case it is "handle_tp".

```ocaml
open Libbpf

let obj_path = "minimal.bpf.o"
let program_names = [ "handle_tp" ]

let () =
  with_bpf_object_open_load_link ~obj_path ~program_names ~before_link
    (fun obj link ->

	< user code to interact with bpf program running in kernel >

	)
```

The API provided by ocaml-libbpf `with_bpf_object_open_load_link` is
a context manager that ensures the proper cleanup of resources if a
failure is encountered. Right now our loaded kernel program is
attached to the kernel and then immediately unloaded, users are
responsible for keeping the bpf program alive by looping within the
function block.

> Users may also pin the bpf program to persist after user code
> exits. Do note that if pinning is desired, users should not use the
> `with_bpf_object_open_load_link` API and instead manually load and
> attach their bpf program since the context manager shutdowns all
> resources on exit.

Now let's add some looping logic to keep the loaded bpf program alive.

```ocaml
let obj_path = "minimal.bpf.o"
let program_names = [ "handle_tp" ]

let () =
  with_bpf_object_open_load_link ~obj_path ~program_names ~before_link
    (fun obj link ->

	(* Set up signal handlers *)
      let exitting = ref true in
      let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
      Sys.(set_signal sigint sig_handler);
      Sys.(set_signal sigterm sig_handler);

      Printf.printf
        "Successfully started! Please run `sudo cat \
         /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF \
         programs.\n\
         %!"

    (* Loop until Ctrl-C is called *)
      while !exitting do
        Printf.eprintf ".%!";
        Unix.sleepf 1.0
      done)
```

Our bpf program is now running in the kernel until we decide to
interrupt it. However, it doesn't do exactly what we want. In
particular, it doesn't filter for our process PID. This is because we
haven't loaded our process PID into the BPF map. To do this, we need
the name of the map we declared in the `minimal.bpf.c` program. In
this case, our BPF array map was named `globals`.

```ocaml
let map = "globals"

(* Load PID into BPF map *)
let before_link obj =
  let pid = Unix.getpid () |> Signed.Long.of_int in
  let global_map = bpf_object_find_map_by_name obj map in
  (* When updating an element, users need to specify the type of the key and value
     declared by the map which checks that the key and value size are consistent. *)
  bpf_map_update_elem ~key_ty:Ctypes.int ~val_ty:Ctypes.long global_map 0 pid
```

Put together in [minimal.ml](./examples/minimal.ml), your bpf program
runs in kernel and print to the trace pipe every second.

### Maps
`libbpf_maps` is an optional convenience package that provides
wrappers for BPF maps. Currently only Ringbuffer maps are added. An
example usage of them can be found in
[examples/bootstrap.ml](./examples/bootstrap.ml). This has been
packaged separately since it drags in `libffi` dependency.

## Notes on compatibility
> The libbpf C library is designed to be kernel-agnostic and work
> across multitude of kernel versions. It has built-in mechanisms to
> gracefully handle older kernels, that are missing some of the
> features, by working around or gracefully degrading functionality.

Vendoring libbpf was a option. However, since bpf programs require
writing the kernel components that may use libbpf, we made the choice
to use the system's package versioned instead. This avoids users from
knowingly/unknowingly using libbpf API's from two different
versions. As a consequence, this library support operating systems
that package libbpf.v.1.1 and up. Check ocaml-ci for the list of
operating systems that successfully builds.

If so desired, you can also checkout the `vendored` branch in this
repo which builds ocaml-libbpf with the latest libbpf package.
