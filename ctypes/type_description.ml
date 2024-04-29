open! Ctypes

module Types (F : Ctypes.TYPE) = struct
  open F

  type libbpf_strict_mode =
    | LIBBPF_STRICT_ALL
    | LIBBPF_STRICT_NONE
    | LIBBPF_STRICT_CLEAN_PTRS
    | LIBBPF_STRICT_DIRECT_ERRS
    | LIBBPF_STRICT_SEC_NAME
    | LIBBPF_STRICT_NO_OBJ_LIST
    | LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK
    | LIBBPF_STRICT_MAP_DEFINITIONS

  let all = constant "LIBBPF_STRICT_ALL" int64_t
  and none = constant "LIBBPF_STRICT_NONE" int64_t
  and clean_ptrs = constant "LIBBPF_STRICT_CLEAN_PTRS" int64_t
  and direct_errs = constant "LIBBPF_STRICT_DIRECT_ERRS" int64_t
  and sec_name = constant "LIBBPF_STRICT_SEC_NAME" int64_t
  and no_obj_list = constant "LIBBPF_STRICT_NO_OBJECT_LIST" int64_t
  and auto_rlimit_memlock = constant "LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK" int64_t
  and map_definitions = constant "LIBBPF_STRICT_MAP_DEFINITIONS" int64_t

  let enum_libbpf_strict_mode =
    enum "libbpf_strict_mode"
      [
        (LIBBPF_STRICT_ALL, all);
        (LIBBPF_STRICT_NONE, none);
        (LIBBPF_STRICT_CLEAN_PTRS, clean_ptrs);
        (LIBBPF_STRICT_DIRECT_ERRS, direct_errs);
        (LIBBPF_STRICT_SEC_NAME, sec_name);
        (LIBBPF_STRICT_NO_OBJ_LIST, no_obj_list);
        (LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK, auto_rlimit_memlock);
        (LIBBPF_STRICT_MAP_DEFINITIONS, map_definitions);
      ]

  type bpf_object
  type bpf_program
  type bpf_link
  type bpf_map

  let bpf_object : bpf_object structure typ = structure "bpf_object"
  let bpf_program : bpf_program structure typ = structure "bpf_program"
  let bpf_link : bpf_link structure typ = structure "bpf_link"
  let bpf_map : bpf_map structure typ = structure "bpf_map"

  type ring_buffer
  type ring_buffer_opts

  (* typedef int (ring_buffer_sample_fn)(void *ctx, void *data, size_t size); *)
  let ring_buffer_sample_fn =
    typedef
      (static_funptr (ptr void @-> ptr void @-> size_t @-> returning int))
      "ring_buffer_sample_fn"

  let ring_buffer : ring_buffer structure typ = structure "ring_buffer"
  let ring_buffer_opts : ring_buffer_opts structure typ = structure "ring_buffer_opts"

  (* let ( -: ) ty label = field bpf_object label ty *)
  (* let name = string -: "name" *)
  (* let () = seal (bpf_object : bpf_object structure typ) *)

  type bpf_attach_type =
    | BPF_CGROUP_INET_INGRESS
    | BPF_CGROUP_INET_EGRESS
    | BPF_CGROUP_INET_SOCK_CREATE
    | BPF_CGROUP_SOCK_OPS
    | BPF_SK_SKB_STREAM_PARSER
    | BPF_SK_SKB_STREAM_VERDICT
    | BPF_CGROUP_DEVICE
    | BPF_SK_MSG_VERDICT
    | BPF_CGROUP_INET4_BIND
    | BPF_CGROUP_INET6_BIND
    | BPF_CGROUP_INET4_CONNECT
    | BPF_CGROUP_INET6_CONNECT
    | BPF_CGROUP_INET4_POST_BIND
    | BPF_CGROUP_INET6_POST_BIND
    | BPF_CGROUP_UDP4_SENDMSG
    | BPF_CGROUP_UDP6_SENDMSG
    | BPF_LIRC_MODE2
    | BPF_FLOW_DISSECTOR
    | BPF_CGROUP_SYSCTL
    | BPF_CGROUP_UDP4_RECVMSG
    | BPF_CGROUP_UDP6_RECVMSG
    | BPF_CGROUP_GETSOCKOPT
    | BPF_CGROUP_SETSOCKOPT
    | BPF_TRACE_RAW_TP
    | BPF_TRACE_FENTRY
    | BPF_TRACE_FEXIT
    | BPF_MODIFY_RETURN
    | BPF_LSM_MAC
    | BPF_TRACE_ITER
    | BPF_CGROUP_INET4_GETPEERNAME
    | BPF_CGROUP_INET6_GETPEERNAME
    | BPF_CGROUP_INET4_GETSOCKNAME
    | BPF_CGROUP_INET6_GETSOCKNAME
    | BPF_XDP_DEVMAP
    | BPF_CGROUP_INET_SOCK_RELEASE
    | BPF_XDP_CPUMAP
    | BPF_SK_LOOKUP
    | BPF_XDP
    | BPF_SK_SKB_VERDICT
    | BPF_SK_REUSEPORT_SELECT
    | BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
    | BPF_PERF_EVENT
    | BPF_TRACE_KPROBE_MULTI
    | BPF_LSM_CGROUP

  let bpf_attach_type =
    enum "bpf_attach_type"
      [
        (BPF_CGROUP_INET_INGRESS, constant "BPF_CGROUP_INET_INGRESS" int64_t);
        (BPF_CGROUP_INET_EGRESS, constant "BPF_CGROUP_INET_EGRESS" int64_t);
        ( BPF_CGROUP_INET_SOCK_CREATE,
          constant "BPF_CGROUP_INET_SOCK_CREATE" int64_t );
        (BPF_CGROUP_SOCK_OPS, constant "BPF_CGROUP_SOCK_OPS" int64_t);
        (BPF_SK_SKB_STREAM_PARSER, constant "BPF_SK_SKB_STREAM_PARSER" int64_t);
        (BPF_SK_SKB_STREAM_VERDICT, constant "BPF_SK_SKB_STREAM_VERDICT" int64_t);
        (BPF_CGROUP_DEVICE, constant "BPF_CGROUP_DEVICE" int64_t);
        (BPF_SK_MSG_VERDICT, constant "BPF_SK_MSG_VERDICT" int64_t);
        (BPF_CGROUP_INET4_BIND, constant "BPF_CGROUP_INET4_BIND" int64_t);
        (BPF_CGROUP_INET6_BIND, constant "BPF_CGROUP_INET6_BIND" int64_t);
        (BPF_CGROUP_INET4_CONNECT, constant "BPF_CGROUP_INET4_CONNECT" int64_t);
        (BPF_CGROUP_INET6_CONNECT, constant "BPF_CGROUP_INET6_CONNECT" int64_t);
        ( BPF_CGROUP_INET4_POST_BIND,
          constant "BPF_CGROUP_INET4_POST_BIND" int64_t );
        ( BPF_CGROUP_INET6_POST_BIND,
          constant "BPF_CGROUP_INET6_POST_BIND" int64_t );
      ]
  (* BPF_CGROUP_UDP4_SENDMSG, constant "" int64_t; *)
  (* BPF_CGROUP_UDP6_SENDMSG, constant "" int64_t; *)
  (* BPF_LIRC_MODE2, constant "" int64_t; *)
  (* BPF_FLOW_DISSECTOR, constant "" int64_t; *)
  (* BPF_CGROUP_SYSCTL, constant "" int64_t; *)
  (* BPF_CGROUP_UDP4_RECVMSG, constant "" int64_t; *)
  (* BPF_CGROUP_UDP6_RECVMSG, constant "" int64_t; *)
  (* BPF_CGROUP_GETSOCKOPT, constant "" int64_t; *)
  (* BPF_CGROUP_SETSOCKOPT, constant "" int64_t; *)
  (* BPF_TRACE_RAW_TP, constant "" int64_t; *)
  (* BPF_TRACE_FENTRY, constant "" int64_t; *)
  (* BPF_TRACE_FEXIT, constant "" int64_t; *)
  (* BPF_MODIFY_RETURN, constant "" int64_t; *)
  (* BPF_LSM_MAC, constant "" int64_t; *)
  (* BPF_TRACE_ITER, constant "" int64_t; *)
  (* BPF_CGROUP_INET4_GETPEERNAME, constant "" int64_t; *)
  (* BPF_CGROUP_INET6_GETPEERNAME, constant "" int64_t; *)
  (* BPF_CGROUP_INET4_GETSOCKNAME, constant "" int64_t; *)
  (* BPF_CGROUP_INET6_GETSOCKNAME, constant "" int64_t; *)
  (* BPF_XDP_DEVMAP, constant "" int64_t; *)
  (* BPF_CGROUP_INET_SOCK_RELEASE, constant "" int64_t; *)
  (* BPF_XDP_CPUMAP, constant "" int64_t; *)
  (* BPF_SK_LOOKUP, constant "" int64_t; *)
  (* BPF_XDP, constant "" int64_t; *)
  (* BPF_SK_SKB_VERDICT, constant "" int64_t; *)
  (* BPF_SK_REUSEPORT_SELECT, constant "" int64_t; *)
  (* BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, constant "" int64_t; *)
  (* BPF_PERF_EVENT, constant "" int64_t; *)
  (* BPF_TRACE_KPROBE_MULTI, constant "" int64_t; *)
end
(* BPF_LSM_CGROUP, constant "" int64_t; *)
