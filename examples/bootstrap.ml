open Ocaml_libbpf

let () =
  (* Implicitly bump RLIMIT_MEMLOCK to create BPF maps *)
  C.Functions.libbpf_set_strict_mode
    C.Types.Libbpf_legacy.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK;

  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  with_bpf_object_open_load_link ~obj_path:"minimal.bpf.o"
    ~program_names:[ "handle_tp" ] (fun obj _links ->
      (* Load maps *)
      let rb = bpf_object_find_map_by_name obj "rb" |> bpf_map_fd in

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
          C.Types.ring_buffer_sample_fn handle_event
      in

      (* Set up ring buffer polling *)
      let rb =
        match
          C.Functions.ring_buffer__new rb handle_event_f Ctypes.null
            Ctypes.(from_voidp C.Types.ring_buffer_opts null)
        with
        | None -> failwith "Failed to create ring buffer\n"
        | Some rb -> rb
      in
      at_exit (fun () -> C.Functions.ring_buffer__free rb);

      while !exitting do
        let err = C.Functions.ring_buffer__poll rb 100 in
        match err with
        | e when e = Sys.sighup -> failwith "Hangup"
        | e when e < 0 ->
            let e_str = Printf.sprintf "Error polling ring buffer, %d\n" e in
            failwith e_str
        | _ -> ()
      done)
