[@@@warning "-26"]

(* let () = *)
(*   let major = Libbpf.Functions.libbpf_major_version () in *)
(*   let minor = Libbpf.Functions.libbpf_minor_version () in *)
(*   Libbpf.Functions.libbpf_set_strict_mode LIBBPF_STRICT_ALL; *)
(*   let attach_typ = *)
(*     Libbpf.Functions.libbpf_bpf_attach_type_str *)
(*       Types_generated.BPF_CGROUP_DEVICE *)
(*   in *)
(*   Printf.printf "version %s.%s %s\n" *)
(*     (Ctypes_value_printing.string_of Ctypes.uint32_t major) *)
(*     (Ctypes_value_printing.string_of Ctypes.uint32_t minor) *)
(*     attach_typ; *)
(*   match Libbpf.Functions.bpf_object__open "minimal.bpf.o" with *)
(*   | None -> failwith "Got NULL" *)
(*   | Some obj_ptr -> *)
(*       print_endline "Open successful"; *)
(*       if Libbpf.Functions.bpf_object__load obj_ptr = 0 then *)
(*         print_endline "Load success" else print_endline "Load failed" *)

module F = Libbpf.Functions
module T = Libbpf.Types

let main () =
  (* Implicitly bump RLIMIT_MEMLOCK to create BPF maps *)
  F.libbpf_set_strict_mode T.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK;

  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  (* Read BPF object *)
  let obj =
    match F.bpf_object__open "trace_uring_primative.bpf.o" with
    | None ->
        Printf.eprintf "Failed to open BPF object\n";
        exit 1
    | Some obj -> obj
  in

  at_exit (fun () -> F.bpf_object__close obj);

  (* Load BPF object *)
  if F.bpf_object__load obj = 1 then (
    Printf.eprintf "Failed to load BPF object\n";
    exit 1);

  (* Find program by name *)
  let prog =
    match F.bpf_object__find_program_by_name obj "handle_complete" with
    | None ->
        Printf.eprintf "Failed to find bpf program\n";
        exit 1
    | Some p -> p
  in

  (* Attach tracepoint *)
  let link = F.bpf_program__attach prog in
  if F.libbpf_get_error (Ctypes.to_voidp link) <> Signed.Long.zero then (
    Printf.eprintf "Failed to attach BPF program\n";
    exit 1);

  at_exit (fun () -> F.bpf_link__destroy link |> ignore);

  (* Load maps *)
  let map =
    match F.bpf_object__find_map_by_name obj "rb" with
    | None ->
        Printf.eprintf "Failed to find map";
        exit 1
    | Some m -> m
  in
  let rb_fd = F.bpf_map__fd map in

  (* Describe event handler *)
  let handle_event _ctx _data _sz =
    Printf.printf "Handle_event called\n%!";
    0
  in

  (* Coerce it to the static_funptr *)
  let handle_event_f =
    let open Ctypes in
    coerce
      (Foreign.funptr ~runtime_lock:true
         (ptr void @-> ptr void @-> size_t @-> returning int))
      T.ring_buffer_sample_fn handle_event
  in

  (* Set up ring buffer polling *)
  let rb =
    match
      F.ring_buffer__new rb_fd handle_event_f Ctypes.null
        Ctypes.(from_voidp T.ring_buffer_opts null)
    with
    | None ->
        Printf.eprintf "Failed to create ring buffer\n";
        exit 1
    | Some rb -> rb
  in

  at_exit (fun () -> F.ring_buffer__free rb);

  while !exitting do
    let err = F.ring_buffer__poll rb 100 in
    match err with
    | e when e = Sys.sighup -> exit 0
    | e when e < 0 ->
        Printf.printf "Error polling ring buffer, %d\n" e;
        exit 1
    | _ -> ()
  done

let () = main ()
