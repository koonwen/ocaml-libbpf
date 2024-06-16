open Ocaml_libbpf
module M = Bpf_maps.Make (Bpf_maps.IntConv) (Bpf_maps.LongConv)

let obj_path = "minimal.bpf.o"
let prog_name = "handle_tp"
let map = "globals"

let () =
  (* Implicitly bump RLIMIT_MEMLOCK to create BPF maps *)
  C.Functions.libbpf_set_strict_mode
    C.Types.Libbpf_legacy.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK;

  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  (* Open *)
  let obj = bpf_object_open obj_path in
  (* Load *)
  let _ = bpf_object_load obj in

  (* Load PID *)
  let pid = Unix.getpid () |> Signed.Long.of_int in
  let global_map = bpf_object_find_map_by_name obj map in
  assert (M.bpf_map_update_elem global_map 0 pid |> Result.is_ok);

  (* Attach programs *)
  let prog = bpf_object_find_program_by_name obj prog_name in
  let link = bpf_program_attach prog in

  (* Test bpf response *)
  while !exitting do
    print_endline "...";
    Unix.sleepf 1.0
  done;

  (* Close *)
  let _ = bpf_link_destroy link in
  let _ = bpf_object_close obj in

  Printf.printf
    "\nrun 'sudo cat /sys/kernel/tracing/trace_pipe' for trace output\n"
