open Ctypes

(** You probably don't mean to be looking into this section, it is
    part of the stub generation process of the bindings.*)

module Types (F : Ctypes.TYPE) = struct
  open F

  let c ?(prefix = "") label = constant (prefix ^ label) int64_t

  let libbpf_print_level : [ `WARN | `INFO | `DEBUG | `UNEXPECTED ] typ =
    let def = c ~prefix:"LIBBPF_" in
    enum "libbpf_print_level"
      ~unexpected:(fun _ -> `UNEXPECTED)
      [ (`WARN, def "WARN"); (`INFO, def "INFO"); (`DEBUG, def "DEBUG") ]

  let libbpf_print_fn_t :
      ([ `WARN | `INFO | `DEBUG | `UNEXPECTED ] -> string -> int) static_funptr
      typ =
    typedef
      (static_funptr (libbpf_print_level @-> string @-> returning int))
      "libbpf_print_fn_t"

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

    let t : t typ =
      let def = c ~prefix:"LIBBPF_ERRNO__" in
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

    let t : t typ =
      let cgroup = c ~prefix:"BPF_CGROUP_" in
      let sk = c ~prefix:"BPF_SK_" in
      let trace = c ~prefix:"BPF_TRACE_" in
      let xdp = c ~prefix:"BPF_XDP_" in
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

    let t : t typ =
      let def = c ~prefix:"BPF_LINK_TYPE_" in
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

  module Bpf_map_type = struct
    type t =
      [ `UNSPEC
      | `HASH
      | `ARRAY
      | `PROG_ARRAY
      | `PERF_EVENT_ARRAY
      | `PERCPU_HASH
      | `PERCPU_ARRAY
      | `STACK_TRACE
      | `CGROUP_ARRAY
      | `LRU_HASH
      | `LRU_PERCPU_HASH
      | `LPM_TRIE
      | `ARRAY_OF_MAPS
      | `HASH_OF_MAPS
      | `DEVMAP
      | `SOCKMAP
      | `CPUMAP
      | `XSKMAP
      | `SOCKHASH
      | `CGROUP_STORAGE
      | `REUSEPORT_SOCKARRAY
      | `PERCPU_CGROUP_STORAGE
      | `QUEUE
      | `STACK
      | `SK_STORAGE
      | `DEVMAP_HASH
      | `STRUCT_OPS
      | `RINGBUF
      | `INODE_STORAGE
      | `TASK_STORAGE
      | `BLOOM_FILTER
      | `USER_RINGBUF
      | `UNKNOWN ]

    let def = c ~prefix:"BPF_MAP_TYPE_"

    let t : t typ =
      enum "bpf_map_type"
        ~unexpected:(fun _ -> `UNKNOWN)
        [
          (`UNSPEC, def "UNSPEC");
          (`HASH, def "HASH");
          (`ARRAY, def "ARRAY");
          (`PROG_ARRAY, def "PROG_ARRAY");
          (`PERF_EVENT_ARRAY, def "PERF_EVENT_ARRAY");
          (`PERCPU_HASH, def "PERCPU_HASH");
          (`PERCPU_ARRAY, def "PERCPU_ARRAY");
          (`STACK_TRACE, def "STACK_TRACE");
          (`CGROUP_ARRAY, def "CGROUP_ARRAY");
          (`LRU_HASH, def "LRU_HASH");
          (`LRU_PERCPU_HASH, def "LRU_PERCPU_HASH");
          (`LPM_TRIE, def "LPM_TRIE");
          (`ARRAY_OF_MAPS, def "ARRAY_OF_MAPS");
          (`HASH_OF_MAPS, def "HASH_OF_MAPS");
          (`DEVMAP, def "DEVMAP");
          (`SOCKMAP, def "SOCKMAP");
          (`CPUMAP, def "CPUMAP");
          (`XSKMAP, def "XSKMAP");
          (`SOCKHASH, def "SOCKHASH");
          (`CGROUP_STORAGE, def "CGROUP_STORAGE");
          (`REUSEPORT_SOCKARRAY, def "REUSEPORT_SOCKARRAY");
          (`PERCPU_CGROUP_STORAGE, def "PERCPU_CGROUP_STORAGE");
          (`QUEUE, def "QUEUE");
          (`STACK, def "STACK");
          (`SK_STORAGE, def "SK_STORAGE");
          (`DEVMAP_HASH, def "DEVMAP_HASH");
          (`STRUCT_OPS, def "STRUCT_OPS");
          (`RINGBUF, def "RINGBUF");
          (`INODE_STORAGE, def "INODE_STORAGE");
          (`TASK_STORAGE, def "TASK_STORAGE");
          (`BLOOM_FILTER, def "BLOOM_FILTER");
          (`USER_RINGBUF, def "USER_RINGBUF");
        ]
  end

  module Bpf_prog_type = struct
    type t =
      [ `UNSPEC
      | `SOCKET_FILTER
      | `KPROBE
      | `SCHED_CLS
      | `SCHED_ACT
      | `TRACEPOINT
      | `XDP
      | `PERF_EVENT
      | `CGROUP_SKB
      | `CGROUP_SOCK
      | `LWT_IN
      | `LWT_OUT
      | `LWT_XMIT
      | `SOCK_OPS
      | `SK_SKB
      | `CGROUP_DEVICE
      | `SK_MSG
      | `RAW_TRACEPOINT
      | `CGROUP_SOCK_ADDR
      | `LWT_SEG6LOCAL
      | `LIRC_MODE2
      | `SK_REUSEPORT
      | `FLOW_DISSECTOR
      | `CGROUP_SYSCTL
      | `RAW_TRACEPOINT_WRITABLE
      | `CGROUP_SOCKOPT
      | `TRACING
      | `STRUCT_OPS
      | `EXT
      | `LSM
      | `SK_LOOKUP
      | `SYSCALL
      | `UNKNOWN ]

    let t : t typ =
      let def = c ~prefix:"BPF_PROG_TYPE_" in
      enum "bpf_prog_type"
        ~unexpected:(fun _ -> `UNKNOWN)
        [
          (`UNSPEC, def "UNSPEC");
          (`SOCKET_FILTER, def "SOCKET_FILTER");
          (`KPROBE, def "KPROBE");
          (`SCHED_CLS, def "SCHED_CLS");
          (`SCHED_ACT, def "SCHED_ACT");
          (`TRACEPOINT, def "TRACEPOINT");
          (`XDP, def "XDP");
          (`PERF_EVENT, def "PERF_EVENT");
          (`CGROUP_SKB, def "CGROUP_SKB");
          (`CGROUP_SOCK, def "CGROUP_SOCK");
          (`LWT_IN, def "LWT_IN");
          (`LWT_OUT, def "LWT_OUT");
          (`LWT_XMIT, def "LWT_XMIT");
          (`SOCK_OPS, def "SOCK_OPS");
          (`SK_SKB, def "SK_SKB");
          (`CGROUP_DEVICE, def "CGROUP_DEVICE");
          (`SK_MSG, def "SK_MSG");
          (`RAW_TRACEPOINT, def "RAW_TRACEPOINT");
          (`CGROUP_SOCK_ADDR, def "CGROUP_SOCK_ADDR");
          (`LWT_SEG6LOCAL, def "LWT_SEG6LOCAL");
          (`LIRC_MODE2, def "LIRC_MODE2");
          (`SK_REUSEPORT, def "SK_REUSEPORT");
          (`FLOW_DISSECTOR, def "FLOW_DISSECTOR");
          (`CGROUP_SYSCTL, def "CGROUP_SYSCTL");
          (`RAW_TRACEPOINT_WRITABLE, def "RAW_TRACEPOINT_WRITABLE");
          (`CGROUP_SOCKOPT, def "CGROUP_SOCKOPT");
          (`TRACING, def "TRACING");
          (`STRUCT_OPS, def "STRUCT_OPS");
          (`EXT, def "EXT");
          (`LSM, def "LSM");
          (`SK_LOOKUP, def "SK_LOOKUP");
          (`SYSCALL, def "SYSCALL");
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

  let ring_buffer_sample_fn :
      (unit ptr -> unit ptr -> Unsigned.size_t -> int) static_funptr typ =
    typedef
      (static_funptr (ptr void @-> ptr void @-> size_t @-> returning int))
      "ring_buffer_sample_fn"

  let ring_buffer : [ `Ring_buffer ] structure typ = structure "ring_buffer"

  let ring_buffer_opts : [ `Ring_buffer_opts ] structure typ =
    structure "ring_buffer_opts"

  module Bpf_tc = struct
    let attach_point : [ `INGRESS | `EGRESS | `CUSTOM ] typ =
      let def = c ~prefix:"BPF_TC_" in
      enum "bpf_tc_attach_point"
        [
          (`INGRESS, def "INGRESS");
          (`EGRESS, def "EGRESS");
          (`CUSTOM, def "CUSTOM");
        ]

    module Opts = struct
      let t : [ `Opts ] structure typ = structure "bpf_tc_opts"
      let ( -: ) ty label = field t label ty
      let sz = size_t -: "sz"
      let prog_fd = int -: "prog_fd"
      let flags = uint32_t -: "flags"
      let prog_id = uint32_t -: "prog_id"
      let handle = uint32_t -: "handle"
      let priority = uint32_t -: "priority"
      let () = seal t
    end

    let hook : [ `Hook ] structure typ = structure "bpf_tc_hook"
    let ( -: ) ty label = field hook label ty
    let sz = size_t -: "sz"
    let ifindex = int -: "ifindex"
    let attach_point = attach_point -: "attach_point"
    let parent = uint32_t -: "parent"
    let () = seal hook
  end
end
