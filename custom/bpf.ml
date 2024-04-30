external libbpf_major_version : unit -> int32 = "caml_libbpf_major_version"
external libbpf_minor_version : unit -> int32 = "caml_libbpf_minor_version"
external libbpf_version_string : unit -> string = "caml_libbpf_version_string"

type libbpf_errno =
  (* Something wrong in libelf *)
  | LIBBPF_ERRNO__LIBELF [@value 4000]
  | LIBBPF_ERRNO__FORMAT
  | (* BPF object format invalid *)
    LIBBPF_ERRNO__KVERSION
  | (* Incorrect or no 'version' section *)
    LIBBPF_ERRNO__ENDIAN
  | (* Endian mismatch *)
    LIBBPF_ERRNO__INTERNAL
  | (* Internal error in libbpf *)
    LIBBPF_ERRNO__RELOC
  | (* Relocation failed *)
    LIBBPF_ERRNO__LOAD
  | (* Load program failure for unknown reason *)
    LIBBPF_ERRNO__VERIFY
  | (* Kernel verifier blocks program loading *)
    LIBBPF_ERRNO__PROG2BIG
  | (* Program too big *)
    LIBBPF_ERRNO__KVER
  | (* Incorrect kernel version *)
    LIBBPF_ERRNO__PROGTYPE
  | (* Kernel doesn't support this program type *)
    LIBBPF_ERRNO__WRNGPID
  | (* Wrong pid in netlink message *)
    LIBBPF_ERRNO__INVSEQ
  | (* Invalid netlink sequence *)
    LIBBPF_ERRNO__NLPARSE
  (* netlink parsing error *)
[@@deriving enum, show { with_path = false }]

let%expect_test "enums" =
  for i = 4000 to 4013 do
    let errno = libbpf_errno_of_enum i |> Option.get |> show_libbpf_errno in
    Printf.printf "%s = %d\n" errno i
  done;
  [%expect "
    LIBBPF_ERRNO__LIBELF = 4000
    LIBBPF_ERRNO__FORMAT = 4001
    LIBBPF_ERRNO__KVERSION = 4002
    LIBBPF_ERRNO__ENDIAN = 4003
    LIBBPF_ERRNO__INTERNAL = 4004
    LIBBPF_ERRNO__RELOC = 4005
    LIBBPF_ERRNO__LOAD = 4006
    LIBBPF_ERRNO__VERIFY = 4007
    LIBBPF_ERRNO__PROG2BIG = 4008
    LIBBPF_ERRNO__KVER = 4009
    LIBBPF_ERRNO__PROGTYPE = 4010
    LIBBPF_ERRNO__WRNGPID = 4011
    LIBBPF_ERRNO__INVSEQ = 4012
    LIBBPF_ERRNO__NLPARSE = 4013"]

external libbpf_strerror : int -> Buffer.t -> nativeint -> int  = "caml_libbpf_strerror"
(* external libbpf_version_string : unit -> string = "caml_libbpf_version_string" *)
(* external libbpf_version_string : unit -> string = "caml_libbpf_version_string" *)
