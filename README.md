# OCaml-Libbpf
OCaml Libbpf bindings for writing type-safe eBPF user programs.

# TODO
- [ ] Add more low level bindings
- [ ] Add higher level abstraction for interacting with API's
- [ ] Fix to libbpf.1.0 version
- [ ] Package properly and find good names
  - [ ] Add dependencies
  - [ ] Prune useless things

- [ ] Write integration with bpftool
- [ ] Write bindings for kernel side bpf
- [ ] Write proper examples
- [ ] Write tests for bindings

# Notes
libbpf API's provide both userland and kernel API's, when writing
kernel bpf code, bpf/bpf_helpers.h, bpf/bpf_core_read.h,
bpf/bpf_tracing provides the kernel bpf API's and most of the other
important includes are in linux/bpf*.h headers. Typically, userland
code will export bpf/libbpf.h code to get the API's you want along
with the other bpf* group headers
