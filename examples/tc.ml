(* This program monitors the traffic going through your loopback
   interface, once this program is run, check your trace pipe with
   `sudo cat /sys/kernel/debug/tracing/trace_pipe` and run `ping
   127.0.0.1` to see the output *)
open Ctypes
open Libbpf

let obj_path = "tc.bpf.o"
let program_name = "tc_ingress"

let () =
  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  let hook_created = ref false in

  let tc_hook = make C.Types.Bpf_tc.hook in
  setf tc_hook C.Types.Bpf_tc.ifindex 1;
  setf tc_hook C.Types.Bpf_tc.attach_point `INGRESS;
  let sz = Ctypes.sizeof C.Types.Bpf_tc.hook in
  setf tc_hook C.Types.Bpf_tc.sz (Unsigned.Size_t.of_int sz);

  let tc_opts = make C.Types.Bpf_tc.Opts.t in
  setf tc_opts C.Types.Bpf_tc.Opts.handle (Unsigned.UInt32.of_int 1);
  setf tc_opts C.Types.Bpf_tc.Opts.priority (Unsigned.UInt32.of_int 1);
  let sz = Ctypes.sizeof C.Types.Bpf_tc.Opts.t in
  setf tc_opts C.Types.Bpf_tc.Opts.sz (Unsigned.Size_t.of_int sz);

  (* Open and load bpf object *)
  let obj = bpf_object_open obj_path in
  bpf_object_load obj;
  let prog = bpf_object_find_program_by_name obj program_name in

  (* Try to create hook *)
  (*  The hook (i.e. qdisc) may already exists because: *)
  (*  1. it is created by other processes or users *)
  (*  2. or since we are attaching to the TC ingress ONLY, *)
  (*     bpf_tc_hook_destroy does NOT really remove the qdisc, *)
  (*     there may be an egress filter on the qdisc *)
  let err = C.Functions.bpf_tc_hook_create (addr tc_hook) in
  if err = 0 then hook_created := true;

  if err <> 0 && err <> -17 (*EEXIST*) then (
    Printf.eprintf "Failed to create tc hook: %d\n" err;
    exit 1);

  setf tc_opts C.Types.Bpf_tc.Opts.prog_fd prog.fd;
  let err = C.Functions.bpf_tc_attach (addr tc_hook) (addr tc_opts) in
  if err = 1 then (
    Printf.eprintf "Failed to attach TC: %d\n" err;
    C.Functions.bpf_tc_hook_destroy (addr tc_hook) |> ignore;
    exit 1);

  Printf.printf
    "Successfully started! Please run `sudo cat \
     /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.\n\
     %!";

  while !exitting do
    Printf.eprintf ".%!";
    Unix.sleepf 1.0
  done;

  let err = C.Functions.bpf_tc_detach (addr tc_hook) (addr tc_opts) in
  if err = 1 then Printf.eprintf "Failed to detach TC: %d\n" err;
  C.Functions.bpf_tc_hook_destroy (addr tc_hook) |> ignore;
  bpf_object_close obj
