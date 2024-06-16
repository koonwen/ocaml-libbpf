open Ctypes

module C = struct
  module Types = Libbpf_bindings.Types
  module Functions = Libbpf_bindings.Functions
end

type bpf_object = C.Types.bpf_object structure ptr
type bpf_program = { name : string; ptr : C.Types.bpf_program structure ptr }
type bpf_map = { fd : int; ptr : C.Types.bpf_map structure ptr }
type bpf_link = C.Types.bpf_link structure ptr

let failwith_f fmt =
  let fails s = failwith s in
  Printf.ksprintf fails fmt

let bpf_object_open obj_file =
  match C.Functions.bpf_object__open obj_file with
  | Some obj -> obj
  | None -> failwith_f "Error opening object file at %s" obj_file

let bpf_object_load bpf_object =
  let ret = C.Functions.bpf_object__load bpf_object in
  if ret = 0 then ()
  else failwith_f "Could not load bpf_object, got exit %d" ret

let bpf_object_find_program_by_name bpf_object name =
  match C.Functions.bpf_object__find_program_by_name bpf_object name with
  | Some prog -> { name; ptr = prog }
  | None -> failwith_f "Program name %s not found" name

let bpf_program_attach ({ name; ptr } : bpf_program) =
  match C.Functions.bpf_program__attach ptr with
  | Some link -> link
  | None -> failwith_f "Error attaching program %s" name

let bpf_object_find_map_by_name bpf_object name =
  match C.Functions.bpf_object__find_map_by_name bpf_object name with
  | Some ptr -> { fd = C.Functions.bpf_map__fd ptr; ptr }
  | None -> failwith_f "Map %s not found" name

let bpf_map_fd { fd; _ } = fd

let bpf_link_destroy bpf_link =
  match C.Functions.bpf_link__destroy bpf_link with
  | e when e <> 0 -> Printf.eprintf "Failed to destroy link %d\n" e
  | _ -> ()

let bpf_object_close bpf_object = C.Functions.bpf_object__close bpf_object

let with_bpf_object_open_load_link ~obj_path ~program_names
    ?(before_link = Stdlib.ignore) fn =
  (* Implicitly bump RLIMIT_MEMLOCK to create BPF maps *)
  C.Functions.libbpf_set_strict_mode
    C.Types.Libbpf_legacy.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK;

  let obj = bpf_object_open obj_path in
  bpf_object_load obj;

  let cleanup ?links obj =
    Option.iter (List.iter bpf_link_destroy) links;
    bpf_object_close obj
  in

  (* Programs to load cannot be zero *)
  if program_names = [] then (
    cleanup obj;
    failwith "Need to specify at least one program to load");

  (* Get list of programs *)
  let programs, not_found =
    List.fold_left
      (fun (succ, fail) name ->
        match C.Functions.bpf_object__find_program_by_name obj name with
        | None -> (succ, name :: fail)
        | Some prog -> ((prog, name) :: succ, fail))
      ([], []) program_names
  in
  if not_found <> [] then (
    cleanup obj;
    failwith_f "Failed to find %s programs" (String.concat "," not_found));

  (* Run before_link user initialization code *)
  (try before_link obj
   with e ->
     bpf_object_close obj;
     raise e);

  (* Get list of links *)
  let links, not_attached =
    List.fold_left
      (fun (succ, fail) (prog, name) ->
        match C.Functions.bpf_program__attach prog with
        | None -> (succ, name :: fail)
        | Some prog -> (prog :: succ, fail))
      ([], []) programs
  in
  if not_attached <> [] then (
    (* Detached successfully attached before shutdown *)
    cleanup ~links obj;
    failwith_f "Failed to link %s programs" (String.concat "," not_attached));

  (* Run user program *)
  (try fn obj links
   with e ->
     cleanup ~links obj;
     raise e);

  (* Ensure proper shutdown *)
  cleanup ~links obj

module Bpf_maps = struct
  module type Conv = sig
    type t

    val empty : t
    val ty : t Ctypes.typ
  end

  module IntConv : Conv with type t = int = struct
    type t = int

    let empty = 0
    let ty = Ctypes.int
  end

  module LongConv : Conv with type t = Signed.Long.t = struct
    type t = Signed.Long.t

    let empty = Signed.Long.zero
    let ty = Ctypes.long
  end

  module Make (Key : Conv) (Val : Conv) = struct
    let bpf_map_lookup_value bpf_map key (* flags *) =
      let open Ctypes in
      let key = allocate Key.ty key in
      let sz_key = sizeof Key.ty |> Unsigned.Size_t.of_int in
      let value = allocate Val.ty Val.empty in
      let sz_val = sizeof Val.ty |> Unsigned.Size_t.of_int in
      let err =
        C.Functions.bpf_map__lookup_elem bpf_map.ptr (to_voidp key) sz_key
          (to_voidp value) sz_val Unsigned.UInt64.zero
      in
      if err <> 0 then Result.error err else Result.ok !@value

    let bpf_map_update_elem bpf_map key value (* flags *) =
      let open Ctypes in
      let key = allocate Key.ty key in
      let sz_key = sizeof Key.ty |> Unsigned.Size_t.of_int in
      let value = allocate Val.ty value in
      let sz_val = sizeof Val.ty |> Unsigned.Size_t.of_int in
      let err =
        C.Functions.bpf_map__update_elem bpf_map.ptr (to_voidp key) sz_key
          (to_voidp value) sz_val Unsigned.UInt64.zero
      in
      if err <> 0 then Result.error err else Result.ok ()
  end

  module RingBuffer = struct
    type t = C.Types.ring_buffer structure ptr
    type callback = C.Types.ring_buffer_sample_fn

    let init bpf_map ~callback : t =
      (* Coerce it to the static_funptr so it can be passed to the C function *)
      let callback_c =
        let open Ctypes in
        coerce
          (Foreign.funptr ~runtime_lock:false ~check_errno:true
             (ptr void @-> ptr void @-> size_t @-> returning int))
          C.Types.ring_buffer_sample_fn callback
      in
      let rb =
        match
          C.Functions.ring_buffer__new bpf_map.fd callback_c Ctypes.null
            Ctypes.(from_voidp C.Types.ring_buffer_opts null)
        with
        | None -> failwith "Failed to create ring buffer\n"
        | Some rb -> rb
      in
      at_exit (fun () -> C.Functions.ring_buffer__free rb);
      rb

    let poll t ~timeout =
      let ret = C.Functions.ring_buffer__poll t timeout in
      if ret < 0 then Result.error ret else Result.ok ret

    let consume t =
      let ret = C.Functions.ring_buffer__consume t in
      if ret < 0 then Result.error ret else Result.ok ret
  end
end
