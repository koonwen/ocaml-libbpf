open! Ctypes

module Types (F : Ctypes.TYPE) = struct
  open F

  let c ?(prefix = "") label = constant (prefix ^ label) int64_t

  module Errno = struct
    type t =
      [ `LIBELF (* Something wrong in libelf *)
      | `FORMAT (* BPF object format invalid *)
      | `KVERSION (* Incorrect or no 'version' section *)
      | `ENDIAN (* Endian mismatch *)
      | `INTERNAL (* Internal error in libbpf *)
      | `RELOC (* Relocation failed *)
      | `LOAD (* Load program failure for unknown reason *)
      | `VERIFY (* Kernel verifier blocks program loading *)
      | `PROG2BIG (* Program too big *)
      | `KVER (* Incorrect kernel version *)
      | `PROGTYPE (* Kernel doesn't support this program type *)
      | `WRNGPID (* Wrong pid in netlink message *)
      | `INVSEQ (* Invalid netlink sequence *)
      | `NLPARSE (* netlink parsing error *)
      | `UNKNOWN ]

    let def = c ~prefix:"LIBBPF_ERRNO__"

    let t : t typ =
      enum "libbpf_errno"
        ~unexpected:(fun _ -> `UNKNOWN)
        [
          (`LIBELF, def "LIBELF");
          (`FORMAT, def "FORMAT");
          (`KVERSION, def "KVERSION");
          (`ENDIAN, def "ENDIAN");
          (`INTERNAL, def "INTERNAL");
          (`RELOC, def "RELOC");
          (`LOAD, def "LOAD");
          (`VERIFY, def "VERIFY");
          (`PROG2BIG, def "PROG2BIG");
          (`KVER, def "KVER");
          (`PROGTYPE, def "PROGTYPE");
          (`WRNGPID, def "WRNGPID");
          (`INVSEQ, def "INVSEQ");
          (`NLPARSE, def "NLPARSE");
        ]
  end

  module Bpf_attach_type = struct
    type cgroup =
      [ `BPF_CGROUP_INET_INGRESS
      | `BPF_CGROUP_INET_EGRESS
      | `BPF_CGROUP_INET_SOCK_CREATE
      | `BPF_CGROUP_SOCK_OPS
      | `BPF_CGROUP_DEVICE
      | `BPF_CGROUP_INET4_BIND
      | `BPF_CGROUP_INET6_BIND
      | `BPF_CGROUP_INET4_CONNECT
      | `BPF_CGROUP_INET6_CONNECT
      | `BPF_CGROUP_INET4_POST_BIND
      | `BPF_CGROUP_INET6_POST_BIND
      | `BPF_CGROUP_UDP4_SENDMSG
      | `BPF_CGROUP_UDP6_SENDMSG
      | `BPF_CGROUP_SYSCTL
      | `BPF_CGROUP_UDP4_RECVMSG
      | `BPF_CGROUP_UDP6_RECVMSG
      | `BPF_CGROUP_GETSOCKOPT
      | `BPF_CGROUP_SETSOCKOPT
      | `BPF_CGROUP_INET4_GETPEERNAME
      | `BPF_CGROUP_INET6_GETPEERNAME
      | `BPF_CGROUP_INET4_GETSOCKNAME
      | `BPF_CGROUP_INET6_GETSOCKNAME
      | `BPF_CGROUP_INET_SOCK_RELEASE ]

    type sk =
      [ `BPF_SK_SKB_STREAM_PARSER
      | `BPF_SK_SKB_STREAM_VERDICT
      | `BPF_SK_MSG_VERDICT
      | `BPF_SK_LOOKUP
      | `BPF_SK_SKB_VERDICT
      | `BPF_SK_REUSEPORT_SELECT
      | `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE ]

    type trace =
      [ `BPF_TRACE_RAW_TP
      | `BPF_TRACE_FENTRY
      | `BPF_TRACE_FEXIT
      | `BPF_TRACE_ITER
      | `BPF_TRACE_KPROBE_MULTI ]

    type xdp = [ `BPF_XDP_DEVMAP | `BPF_XDP_CPUMAP | `BPF_XDP ]

    type other =
      [ `BPF_LIRC_MODE2
      | `BPF_FLOW_DISSECTOR
      | `BPF_MODIFY_RETURN
      | `BPF_PERF_EVENT
      | `BPF_LSM_MAC
      | `BPF_LSM_CGROUP ]

    type t = [ cgroup | sk | trace | xdp | other | `UNKNOWN ]

    let cgroup = c ~prefix:"BPF_CGROUP_"
    let sk = c ~prefix:"BPF_SK_"
    let trace = c ~prefix:"BPF_TRACE_"
    let xdp = c ~prefix:"BPF_XDP_"

    let t : t typ =
      enum "bpf_attach_type"
        ~unexpected:(fun _ -> `UNKNOWN)
        [
          (`BPF_CGROUP_INET_INGRESS, cgroup "INET_INGRESS");
          (`BPF_CGROUP_INET_EGRESS, cgroup "INET_EGRESS");
          (`BPF_CGROUP_INET_SOCK_CREATE, cgroup "INET_SOCK_CREATE");
          (`BPF_CGROUP_SOCK_OPS, cgroup "SOCK_OPS");
          (`BPF_CGROUP_DEVICE, cgroup "DEVICE");
          (`BPF_CGROUP_INET4_BIND, cgroup "INET4_BIND");
          (`BPF_CGROUP_INET6_BIND, cgroup "INET6_BIND");
          (`BPF_CGROUP_INET4_CONNECT, cgroup "INET4_CONNECT");
          (`BPF_CGROUP_INET6_CONNECT, cgroup "INET6_CONNECT");
          (`BPF_CGROUP_INET4_POST_BIND, cgroup "INET4_POST_BIND");
          (`BPF_CGROUP_INET6_POST_BIND, cgroup "INET6_POST_BIND");
          (`BPF_CGROUP_UDP4_SENDMSG, cgroup "UDP4_SENDMSG");
          (`BPF_CGROUP_UDP6_SENDMSG, cgroup "UDP6_SENDMSG");
          (`BPF_CGROUP_SYSCTL, cgroup "SYSCTL");
          (`BPF_CGROUP_UDP4_RECVMSG, cgroup "UDP4_RECVMSG");
          (`BPF_CGROUP_UDP6_RECVMSG, cgroup "UDP6_RECVMSG");
          (`BPF_CGROUP_GETSOCKOPT, cgroup "GETSOCKOPT");
          (`BPF_CGROUP_SETSOCKOPT, cgroup "SETSOCKOPT");
          (`BPF_CGROUP_INET4_GETPEERNAME, cgroup "INET4_GETPEERNAME");
          (`BPF_CGROUP_INET6_GETPEERNAME, cgroup "INET6_GETPEERNAME");
          (`BPF_CGROUP_INET4_GETSOCKNAME, cgroup "INET4_GETSOCKNAME");
          (`BPF_CGROUP_INET6_GETSOCKNAME, cgroup "INET6_GETSOCKNAME");
          (`BPF_CGROUP_INET_SOCK_RELEASE, cgroup "INET_SOCK_RELEASE");
          (`BPF_SK_SKB_STREAM_PARSER, sk "SKB_STREAM_PARSER");
          (`BPF_SK_SKB_STREAM_VERDICT, sk "SKB_STREAM_VERDICT");
          (`BPF_SK_MSG_VERDICT, sk "MSG_VERDICT");
          (`BPF_SK_LOOKUP, sk "LOOKUP");
          (`BPF_SK_SKB_VERDICT, sk "SKB_VERDICT");
          (`BPF_SK_REUSEPORT_SELECT, sk "REUSEPORT_SELECT");
          (`BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, sk "REUSEPORT_SELECT_OR_MIGRATE");
          (`BPF_TRACE_RAW_TP, trace "RAW_TP");
          (`BPF_TRACE_FENTRY, trace "FENTRY");
          (`BPF_TRACE_FEXIT, trace "FEXIT");
          (`BPF_TRACE_ITER, trace "ITER");
          (`BPF_TRACE_KPROBE_MULTI, trace "KPROBE_MULTI");
          (`BPF_XDP_DEVMAP, xdp "DEVMAP");
          (`BPF_XDP_CPUMAP, xdp "CPUMAP");
          (`BPF_XDP, c "BPF_XDP");
          (`BPF_LIRC_MODE2, c "BPF_LIRC_MODE2");
          (`BPF_FLOW_DISSECTOR, c "BPF_FLOW_DISSECTOR");
          (`BPF_MODIFY_RETURN, c "BPF_MODIFY_RETURN");
          (`BPF_PERF_EVENT, c "BPF_PERF_EVENT");
          (`BPF_LSM_MAC, c "BPF_LSM_MAC");
          (`BPF_LSM_CGROUP, c "BPF_LSM_CGROUP");
        ]
  end

  module Bpf_link_type = struct
    type t =
      [ `UNSPEC
      | `RAW_TRACEPOINT
      | `TRACING
      | `CGROUP
      | `ITER
      | `NETNS
      | `XDP
      | `PERF_EVENT
      | `KPROBE_MULTI
      | `STRUCT_OPS
      | `UNKNOWN ]

    let def = c ~prefix:"BPF_LINK_TYPE_"

    let t : t typ =
      enum "bpf_link_type"
        ~unexpected:(fun _ -> `UNKNOWN)
        [
          (`UNSPEC, def "UNSPEC");
          (`RAW_TRACEPOINT, def "RAW_TRACEPOINT");
          (`TRACING, def "TRACING");
          (`CGROUP, def "CGROUP");
          (`ITER, def "ITER");
          (`NETNS, def "NETNS");
          (`XDP, def "XDP");
          (`PERF_EVENT, def "PERF_EVENT");
          (`KPROBE_MULTI, def "KPROBE_MULTI");
          (`STRUCT_OPS, def "STRUCT_OPS");
        ]
  end

  type bpf_object
  type bpf_program
  type bpf_link
  type bpf_map

  let bpf_object : bpf_object structure typ = structure "bpf_object"
  let bpf_program : bpf_program structure typ = structure "bpf_program"
  let bpf_link : bpf_link structure typ = structure "bpf_link"
  let bpf_map : bpf_map structure typ = structure "bpf_map"

  type ring
  type ring_buffer
  type ring_buffer_opts
  type ring_buffer_sample_fn = unit ptr -> unit ptr -> Unsigned.size_t -> int

  let ring_buffer_sample_fn : ring_buffer_sample_fn static_funptr typ =
    typedef
      (static_funptr (ptr void @-> ptr void @-> size_t @-> returning int))
      "ring_buffer_sample_fn"

  let ring : ring structure typ = structure "ring"
  let ring_buffer : ring_buffer structure typ = structure "ring_buffer"

  let ring_buffer_opts : ring_buffer_opts structure typ =
    structure "ring_buffer_opts"
end
