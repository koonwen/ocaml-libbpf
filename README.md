[![OCaml-CI Build Status](https://img.shields.io/endpoint?url=https://ocaml.ci.dev/badge/koonwen/ocaml-libbpf/main&logo=ocaml)](https://ocaml.ci.dev/github/koonwen/ocaml-libbpf)

# ocaml-libbpf
Libbpf C-bindings for type-safe eBPF user programs.

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

## TODO
- [X] Generate vmlinux
- [ ] BPF CORE bindings?

## Would be nice to support
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
