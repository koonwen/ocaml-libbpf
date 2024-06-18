open Ocaml_libbpf
module M = Bpf_maps.Make (Bpf_maps.IntConv) (Bpf_maps.LongConv)

let obj_path = "minimal.bpf.o"
let program_names = [ "handle_tp" ]
let map = "globals"

let () =
  with_bpf_object_open_load_link ~obj_path ~program_names
    ~before_link:(fun obj ->
      (* Load PID into BPF map*)
      let pid = Unix.getpid () |> Signed.Long.of_int in
      let global_map = bpf_object_find_map_by_name obj map in
      assert (M.bpf_map_update_elem global_map 0 pid |> Result.is_ok))
    (fun _obj _link ->
      let exitting = ref true in
      let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
      Sys.(set_signal sigint sig_handler);
      Sys.(set_signal sigterm sig_handler);

      Printf.printf
        "Successfully started! Please run `sudo cat \
         /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF \
         programs.\n\
         %!";

      while !exitting do
        Printf.eprintf ".%!";
        Unix.sleepf 1.0
      done)
