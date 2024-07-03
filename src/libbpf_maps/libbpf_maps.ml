open Libbpf
open Ctypes

module RingBuffer = struct
  type t = [ `Ring_buffer ] structure ptr

  type callback =
    unit Ctypes_static.ptr -> unit Ctypes_static.ptr -> Unsigned.size_t -> int

  let init bpf_map ~callback f =
    (* Coerce it to the static_funptr so it can be passed to the C function *)
    let callback_c =
      coerce
        (Foreign.funptr ~runtime_lock:true ~check_errno:true
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
    try f rb
    with e ->
      C.Functions.ring_buffer__free rb;
      raise e

  let poll t ~timeout = C.Functions.ring_buffer__poll t timeout
  let consume t = C.Functions.ring_buffer__consume t
  let get_epoll_fd t = C.Functions.ring_buffer__epoll_fd t
end
