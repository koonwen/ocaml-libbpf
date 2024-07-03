open Libbpf

let obj_path = "kprobe.bpf.o"
let program_names = [ "do_unlinkat"; "do_unlinkat_exit" ]

let () =
  with_bpf_object_open_load_link ~obj_path ~program_names (fun _obj _links ->
      (* Set signal handlers *)
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
        Unix.sleepf 1.0;
        Printf.eprintf ".%!"
      done)
