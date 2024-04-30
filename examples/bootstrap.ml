module F = Ocaml_libbpf.Libbpf.Functions
module T = Ocaml_libbpf.Libbpf.Types

exception Exit of int

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
    match F.bpf_object__open "minimal.bpf.o" with
    | None ->
        Printf.eprintf "Failed to open BPF object\n";
        raise (Exit 1)
    | Some obj -> obj
  in

  at_exit (fun () -> F.bpf_object__close obj);

  (* Load BPF object *)
  if F.bpf_object__load obj = 1 then (
    Printf.eprintf "Failed to load BPF object\n";
    raise (Exit 1));

  (* Find program by name *)
  let prog =
    match F.bpf_object__find_program_by_name obj "handle_tp" with
    | None ->
        Printf.eprintf "Failed to find bpf program\n";
        raise (Exit 1)
    | Some p -> p
  in

  (* Attach tracepoint *)
  let link = F.bpf_program__attach prog in
  if F.libbpf_get_error (Ctypes.to_voidp link) <> Signed.Long.zero then (
    Printf.eprintf "Failed to attach BPF program\n";
    raise (Exit 1));

  at_exit (fun () -> F.bpf_link__destroy link |> ignore);

  (* Load maps *)
  let map =
    match F.bpf_object__find_map_by_name obj "rb" with
    | None ->
        Printf.eprintf "Failed to find map\n";
        raise (Exit 1)
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
        raise (Exit 1)
    | Some rb -> rb
  in

  at_exit (fun () -> F.ring_buffer__free rb);

  while !exitting do
    let err = F.ring_buffer__poll rb 100 in
    match err with
    | e when e = Sys.sighup -> raise (Exit 0)
    | e when e < 0 ->
        Printf.eprintf "Error polling ring buffer, %d\n" e;
        raise (Exit 1)
    | _ -> ()
  done

let () = try main () with Exit i when i <> 0 -> Printf.eprintf "[Exit %d]" i
