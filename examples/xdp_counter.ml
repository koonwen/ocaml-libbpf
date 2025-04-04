open Libbpf

let obj_path = "xdp_counter.bpf.o"
let program_name = "count_packets"
let map = "packet_count"
let ifindex = 1 (* Usually localhost *)

let load_and_attach_xdp ifindex =
  (* Load the compiled eBPF object *)
  let obj = bpf_object_open obj_path in
  let program = bpf_object_find_program_by_name obj program_name in
  let fd = bpf_program_fd program in

  let opts = Ctypes.from_voidp C.Types.Bpf_xdp.Attach_opts.t Ctypes.null in

  (match C.Functions.bpf_xdp_attach ifindex fd Unsigned.UInt32.zero opts with
  | 0 -> ()
  | _ ->
      bpf_object_close obj;
      failwith "Failed to attach xdp program");

  (obj, opts)

let teardown_xdp (obj, link) =
  let _ = C.Functions.bpf_xdp_detach 0 Unsigned.UInt32.zero link in
  bpf_object_close obj

let () =
  let obj, link = load_and_attach_xdp ifindex in
  (* Initialize bpf_map with value, if not the lookup will fail *)
  let counter = bpf_object_find_map_by_name obj map in

  let exitting = ref false in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := true) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  let rec loop () =
    if !exitting then ()
    else (
      Unix.sleep 1;
      let count =
        bpf_map_lookup_value ~key_ty:Ctypes.int ~val_ty:Ctypes.ulong
          ~val_zero:Unsigned.ULong.zero counter 0
      in
      Printf.printf "Packet count %d\n%!" (Unsigned.ULong.to_int count);

      loop ())
  in
  loop ();

  teardown_xdp (obj, link)
