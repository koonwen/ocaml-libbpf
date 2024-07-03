module F = Libbpf.C.Functions
module T = Libbpf.C.Types

let bpf_obj_path = "bootstrap.bpf.o"
let program_names = [ "handle_exec"; "handle_exit" ]
let rb_name = "rb"

exception Exit of int

let main () =
  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  (* Read BPF object *)
  let obj =
    match F.bpf_object__open bpf_obj_path with
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

  let progs =
    let find_exn name =
      match F.bpf_object__find_program_by_name obj name with
      | None ->
          Printf.eprintf "Failed to find bpf program: %s\n" name;
          raise (Exit 1)
      | Some p -> p
    in
    List.map find_exn program_names
  in

  (* Attach tracepoint *)
  let links =
    let attach_exn prog =
      match F.bpf_program__attach prog with
      | Some linkp -> linkp
      | None ->
          Printf.eprintf "Failed to attach BPF program\n";
          raise (Exit 1)
    in
    List.map attach_exn progs
  in

  at_exit (fun () ->
      List.iter (fun link -> F.bpf_link__destroy link |> ignore) links);

  (* Load maps *)
  let map =
    match F.bpf_object__find_map_by_name obj rb_name with
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
    Ctypes.(
      coerce
        (Foreign.funptr ~runtime_lock:false ~check_errno:true
           (ptr void @-> ptr void @-> size_t @-> returning int))
        T.ring_buffer_sample_fn handle_event)
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
    Printf.printf "polling\n%!";
    let err = F.ring_buffer__poll rb 100 in
    match err with
    | e when e = Sys.sighup -> raise (Exit 0)
    | e when e < 0 ->
        Printf.eprintf "Error polling ring buffer, %d\n" e;
        raise (Exit 1)
    | _ -> ()
  done

let () = try main () with Exit i when i <> 0 -> Printf.eprintf "[Exit %d]" i
