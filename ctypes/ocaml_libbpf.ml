open Ctypes

module C = struct
  module Types = Libbpf_bindings.Types
  module Functions = Libbpf_bindings.Functions
end

type bpf_object = C.Types.bpf_object structure ptr
type bpf_program = C.Types.bpf_program structure ptr

type bpf_map = { fd : int; ptr : C.Types.bpf_map structure ptr }
[@@warning "-69"]

type bpf_link = C.Types.bpf_link structure ptr

let bpf_object_open obj_file =
  match C.Functions.bpf_object__open obj_file with
  | None -> failwith "Error opening object file"
  | Some ptr -> ptr

let bpf_object_load bpf_object =
  let ret = C.Functions.bpf_object__load bpf_object in
  if ret <> 0 then exit ret else ()

let bpf_object_find_program_by_name bpf_object name =
  C.Functions.bpf_object__find_program_by_name bpf_object name

let bpf_program_attach bpf_program =
  match C.Functions.bpf_program__attach bpf_program with
  | None -> failwith "Error attaching program"
  | Some ptr -> ptr

let bpf_object_find_map_by_name bpf_object name =
  match C.Functions.bpf_object__find_map_by_name bpf_object name with
  | None as n -> n
  | Some ptr ->
      let fd = C.Functions.bpf_map__fd ptr in
      Some { fd; ptr }

let bpf_link_destroy bpf_link =
  match C.Functions.bpf_link__destroy bpf_link with
  | 0 -> ()
  | e -> Printf.eprintf "Failed to destroy link %d\n" e

let bpf_object_close bpf_object = C.Functions.bpf_object__close bpf_object

let with_bpf_object_open_load_link ~obj_path ~program_names ?(before_link=Stdlib.ignore) fn =
  let obj = bpf_object_open obj_path in
  bpf_object_load obj;
  at_exit (fun () -> bpf_object_close obj); (* Ensure closed when program exits *)
  let n_progs = List.length program_names in
  if n_progs < 1 then failwith "Need to specify at least one program to load";
  let programs = List.filter_map (bpf_object_find_program_by_name obj) program_names in
  if List.length programs <> n_progs then failwith "Some program was not found";
  before_link obj;
  let program_links = List.filter_map C.Functions.bpf_program__attach programs in
  at_exit (fun () -> List.iter bpf_link_destroy program_links); (* Ensure links are destroyed on exit *)
  if List.length program_links <> n_progs then failwith "failed to attach some program(s)";
  fn obj program_links

module type Conv = sig
  type t

  val c_type : t typ
  val empty : t
end

(* module Bpf_maps = struct *)
(*   module Make (Key : Conv) (Val : Conv) = struct *)
(*     let bpf_map_lookup_value_op bpf_map key = *)
(*       let open Ctypes in *)
(*       let key = allocate Key.c_type key in *)
(*       let value = allocate Val.c_type Val.empty in *)
(*       let err = *)
(*         C.Functions.Bpf.bpf_map_lookup_elem bpf_map.fd (to_voidp key) *)
(*           (to_voidp value) *)
(*       in *)
(*       if err <> 0 then Result.error err else Result.ok !@value *)

(*     let bpf_map_update_elem_op bpf_map key value _flags = *)
(*       let open Ctypes in *)
(*       let key = allocate Key.c_type key in *)
(*       (\* This might be garbage collected to soon *\) *)
(*       let value = allocate Val.c_type value in *)
(*       let err = *)
(*         C.Functions.Bpf.bpf_map_update_elem bpf_map.fd (to_voidp key) *)
(*           (to_voidp value) Unsigned.UInt64.zero *)
(*       in *)
(*       if err <> 0 then Result.error err else Result.ok () *)
(*   end *)
(* end *)
