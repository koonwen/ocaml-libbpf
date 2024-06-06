open Ocaml_libbpf
module M = Bpf_maps.Make (Bpf_maps.IntConv) (Bpf_maps.LongConv)

let () =
  let obj = bpf_object_open "minimal.bpf.o" in
  bpf_object_load obj;
  let global_map = bpf_object_find_map_by_name obj "globals" in
  let before = M.bpf_map_lookup_value global_map 0 |> Result.get_ok in
  let _ =
    M.bpf_map_update_elem global_map 0 (Signed.Long.of_int 10) |> Result.get_ok
  in
  let after = M.bpf_map_lookup_value global_map 0 |> Result.get_ok in
  let show_slong = Ctypes_value_printing.string_of Ctypes.long in
  Printf.printf "Map initialized with %s and updated to %s\n"
    (show_slong before) (show_slong after)
