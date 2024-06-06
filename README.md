# ocaml-libbpf
C-bindings for libbpf for writing type-safe eBPF user programs.

# TODO
- [X] Add more low level bindings
- [X] Add higher level abstraction for interacting with API's
- [ ] Fix to libbpf.1.0 version (Now 1.4)
- [X] Package properly and find good names
  - [X] Add dependencies
  - [X] Prune useless things

- [ ] Write integration with bpftool
- [X] Write proper examples
- [ ] Write tests for bindings
- [ ] Write high level apis for ring buffer usage

# Notes
libbpf API's provide both userland and kernel API's, when writing
kernel bpf code, bpf/bpf_helpers.h, bpf/bpf_core_read.h,
bpf/bpf_tracing provides the kernel bpf API's and most of the other
important includes are in linux/bpf*.h headers. Typically, userland
code will export bpf/libbpf.h code to get the API's you want along
with the other bpf* group headers

# Kernel compatibility
No ties to any specific kernel, transparent handling of older
kernels. Libbpf is designed to be kernel-agnostic and work across
multitude of kernel versions. It has built-in mechanisms to gracefully
handle older kernels, that are missing some of the features, by
working around or gracefully degrading functionality. Thus libbpf is
not tied to a specific kernel version and can/should be packaged and
versioned independently.
