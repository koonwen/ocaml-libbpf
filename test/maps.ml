open Ocaml_libbpf

module CInt : Conv with type t = int = struct
  type t = int

  let c_type = Ctypes.int
  let empty = 0
end

module CLong : Conv with type t = Signed.Long.t = struct
  type t = Signed.Long.t

  let c_type = Ctypes.long
  let empty = Signed.Long.zero
end

module M = Bpf_maps.Make (CInt) (CLong)

let () =
  let obj = bpf_object_open "minimal.bpf.o" in
  bpf_object_load obj;
  let global_map =bpf_object_find_map_by_name obj "globals" |> Option.get in
  let before = M.bpf_map_lookup_value_op global_map 0 |> Result.get_ok in
  let _ = M.bpf_map_update_elem_op global_map 0 (Signed.Long.of_int 10) Int64.zero |> Result.get_ok in
  let after = M.bpf_map_lookup_value_op global_map 0 |> Result.get_ok in
  let bef = Ctypes_value_printing.string_of CLong.c_type before in
  let aft = Ctypes_value_printing.string_of CLong.c_type after in
  Printf.printf "Map initialized with %s and updated to %s\n" bef aft
