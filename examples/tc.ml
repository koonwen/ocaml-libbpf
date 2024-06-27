open Ocaml_libbpf

let obj_path = "tc.bpf.o"
let program_names = [ "tc_ingress" ]

let () =
  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  (* Use auto open/load/link helper *)
  with_bpf_object_open_load_link ~obj_path ~program_names (fun _obj _links ->
      failwith "Not implemented")
