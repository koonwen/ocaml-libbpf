open Ocaml_libbpf
open Ctypes

module type Conv = sig
  type t

  val empty : t
  val ty : t typ
end

module IntConv : Conv with type t = int = struct
  type t = int

  let empty = 0
  let ty = int
end

module LongConv : Conv with type t = Signed.Long.t = struct
  type t = Signed.Long.t

  let empty = Signed.Long.zero
  let ty = long
end

module Make (Key : Conv) (Val : Conv) = struct
  let bpf_map_lookup_value bpf_map key (* flags *) =
    let key = allocate Key.ty key in
    let sz_key = sizeof Key.ty |> Unsigned.Size_t.of_int in
    let value = allocate Val.ty Val.empty in
    let sz_val = sizeof Val.ty |> Unsigned.Size_t.of_int in
    let err =
      C.Functions.bpf_map__lookup_elem bpf_map.ptr (to_voidp key) sz_key
        (to_voidp value) sz_val Unsigned.UInt64.zero
    in
    if err = 0 then !@value
    else
      let err = Printf.sprintf "bpf_map_lookup_value got %d" err in
      raise (Sys_error err)

  let bpf_map_update_elem bpf_map key value (* flags *) =
    let key = allocate Key.ty key in
    let sz_key = sizeof Key.ty |> Unsigned.Size_t.of_int in
    let value = allocate Val.ty value in
    let sz_val = sizeof Val.ty |> Unsigned.Size_t.of_int in
    let err =
      C.Functions.bpf_map__update_elem bpf_map.ptr (to_voidp key) sz_key
        (to_voidp value) sz_val Unsigned.UInt64.zero
    in
    if err = 0 then ()
    else
      let err = Printf.sprintf "bpf_map_update_elem got %d" err in
      raise (Sys_error err)
end

module RingBuffer = struct
  type t = C.Types.ring_buffer structure ptr
  type callback = C.Types.ring_buffer_sample_fn

  let init bpf_map ~callback f =
    (* Coerce it to the static_funptr so it can be passed to the C function *)
    let callback_c =
      coerce
        (Foreign.funptr ~runtime_lock:false ~check_errno:true
           (ptr void @-> ptr void @-> size_t @-> returning int))
        C.Types.ring_buffer_sample_fn callback
    in
    let rb =
      match
        C.Functions.ring_buffer__new bpf_map.fd callback_c null
          (from_voidp C.Types.ring_buffer_opts null)
      with
      | None -> failwith "Failed to create ring buffer\n"
      | Some rb -> rb
    in
    Fun.protect
      ~finally:(fun () -> C.Functions.ring_buffer__free rb)
      (fun () -> f rb)

  let poll t ~timeout =
    let ret = C.Functions.ring_buffer__poll t timeout in
    if ret >= 0 then ret
    else
      let err = Printf.sprintf "ring_buffer__poll got %d" ret in
      raise (Sys_error err)

  let consume t =
    let ret = C.Functions.ring_buffer__consume t in
    if ret >= 0 then ret
    else
      let err = Printf.sprintf "ring_buffer__consume got %d" ret in
      raise (Sys_error err)
end
