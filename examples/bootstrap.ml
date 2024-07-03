open Libbpf
open Libbpf_maps
open Ctypes

let obj_path = "bootstrap.bpf.o"
let program_names = [ "handle_exec"; "handle_exit" ]
let rb_name = "rb"

(* event structure layout from bootstrap.h *)
let event : [ `Event ] structure typ = Ctypes.structure "event"
let ( -: ) ty label = field event label ty
let pid = int -: "pid"
let ppid = int -: "ppid"
let exit_code = uint -: "exit_code"
let duration = ullong -: "duration_ns"
let comm = array 16 char -: "comm"
let filename = array 127 char -: "filename"
let exit_event = bool -: "exit_event"
let _ = seal event

let char_array_as_string a =
  let len = CArray.length a in
  let b = Buffer.create len in
  try
    for i = 0 to len - 1 do
      let c = CArray.get a i in
      if c = '\x00' then raise Exit else Buffer.add_char b c
    done;
    Buffer.contents b
  with Exit -> Buffer.contents b

(* Describe User callback event handler *)
let handle_event _ctx data _sz =
  let ev = !@(from_voidp event data) in
  let pid = getf ev pid in
  let ppid = getf ev ppid in
  let exit_code = getf ev exit_code |> Unsigned.UInt.to_string in
  let duration = getf ev duration |> Unsigned.ULLong.to_int64 in
  let comm = getf ev comm |> char_array_as_string in
  let filename = getf ev filename |> char_array_as_string in
  let exit_event = getf ev exit_event in
  let tm = Unix.time () |> Unix.localtime in
  let ts = Printf.sprintf "%d:%d:%d" tm.tm_hour tm.tm_min tm.tm_sec in
  if exit_event then (
    Printf.printf "%-8s %-5s %-16s %-7d %-7d [%s]" ts "EXIT" comm pid ppid
      exit_code;
    if duration >= 0L then
      Printf.printf " (%Lums)" (Int64.div duration 1000000L);
    print_newline ())
  else
    Printf.printf "%-8s %-5s %-16s %-7d %-7d %s\n" ts "EXEC" comm pid ppid
      filename;
  0

let () =
  (* Set signal handlers *)
  let exitting = ref true in
  let sig_handler = Sys.Signal_handle (fun _ -> exitting := false) in
  Sys.(set_signal sigint sig_handler);
  Sys.(set_signal sigterm sig_handler);

  (* Use auto open/load/link helper *)
  with_bpf_object_open_load_link ~obj_path ~program_names (fun obj _links ->
      (* Load ringbuffer map *)
      let map = bpf_object_find_map_by_name obj rb_name in

      (* Set up ring buffer *)
      RingBuffer.init map ~callback:handle_event (fun rb ->
          Printf.printf "%-8s %-5s %-16s %-7s %-7s %s\n%!" "TIME" "EVENT" "COMM"
            "PID" "PPID" "FILENAME/EXIT CODE";

          while !exitting do
            ignore
              (try RingBuffer.poll rb ~timeout:100
               with _ ->
                 exitting := false;
                 -1)
          done))
