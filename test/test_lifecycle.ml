open Ocaml_libbpf
module M = Bpf_maps.Make (Bpf_maps.IntConv) (Bpf_maps.LongConv)

let () =
  (* Implicitly bump RLIMIT_MEMLOCK to create BPF maps *)
  C.Functions.libbpf_set_strict_mode C.Types.Libbpf_legacy.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK;

  (* (\* Set signal handlers *\) *)
  (* let exitting = ref true in *)
  (* let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in *)
  (* Sys.(set_signal sigint sig_handler); *)
  (* Sys.(set_signal sigterm sig_handler); *)

  (* Open *)
  let obj = bpf_object_open "minimal.bpf.o" in
  (* Load *)
  let _ = bpf_object_load obj in

  let pid = Unix.getpid () in
  let index = 0 in
  let before = Signed.Long.zero in
  let after = Signed.Long.of_int pid in
  (* Retrieve globals & test get/set *)
  let global_map = bpf_object_find_map_by_name obj "globals" in
  assert ((M.bpf_map_lookup_value global_map index |> Result.get_ok) = before);
  assert (M.bpf_map_update_elem global_map index after |> Result.is_ok);
  assert ((M.bpf_map_lookup_value global_map index |> Result.get_ok) = after);

  (* Attach programs *)
  let prog = bpf_object_find_program_by_name obj "handle_tp" in
  let link =  bpf_program_attach prog in

  (* Test bpf response *)
  let _, oc = Filename.open_temp_file "ocaml_libbpf" "test_lifecycle" in
  Out_channel.output_string oc "Test";

  (* Close *)
  let _ = bpf_link_destroy link in
  let _ = bpf_object_close obj in
  ()
