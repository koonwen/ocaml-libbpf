# ocaml-libbpf
C-bindings for libbpf for writing type-safe eBPF user programs.

# TODO
- [X] Add more low level bindings
- [ ] Add higher level abstraction for interacting with API's
- [ ] Fix to libbpf.1.0 version
- [ ] Package properly and find good names
  - [ ] Add dependencies
  - [ ] Prune useless things

- [ ] Write integration with bpftool
- [ ] Write proper examples
- [ ] Write tests for bindings

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

# Questions
- Is it possible to hid the other dependencies of ocaml_libbpf?
