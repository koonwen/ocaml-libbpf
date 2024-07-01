open Ctypes
module C = C

let major_version =
  C.Functions.libbpf_major_version () |> Unsigned.UInt32.to_int

let minor_version =
  C.Functions.libbpf_minor_version () |> Unsigned.UInt32.to_int

let version_string = C.Functions.libbpf_version_string ()

let bpf_attach_type_str attach_type =
  C.Functions.libbpf_bpf_attach_type_str attach_type

let bpf_link_type_str link_type = C.Functions.libbpf_bpf_link_type_str link_type
let bpf_map_type_str map_type = C.Functions.libbpf_bpf_map_type_str map_type
let bpf_prog_type_str prog_type = C.Functions.libbpf_bpf_prog_type_str prog_type

type bpf_object = C.Types.bpf_object structure ptr

type bpf_program = {
  name : string;
  fd : int;
  ptr : C.Types.bpf_program structure ptr;
}

type bpf_map = { fd : int; ptr : C.Types.bpf_map structure ptr }
type bpf_link = C.Types.bpf_link structure ptr

let failwith_f fmt =
  let fails s = failwith s in
  Printf.ksprintf fails fmt

let bpf_object_open obj_file =
  match C.Functions.bpf_object__open obj_file with
  | Some obj -> obj
  | None -> failwith_f "Error opening object file at %s" obj_file

let bpf_object_load bpf_object =
  let ret = C.Functions.bpf_object__load bpf_object in
  if ret = 0 then ()
  else failwith_f "Could not load bpf_object, got exit %d" ret

let bpf_object_find_program_by_name bpf_object name =
  match C.Functions.bpf_object__find_program_by_name bpf_object name with
  | Some prog -> { name; fd = C.Functions.bpf_program__fd prog; ptr = prog }
  | None -> failwith_f "Program name %s not found" name

let bpf_program_attach ({ name; ptr; _ } : bpf_program) =
  match C.Functions.bpf_program__attach ptr with
  | Some link -> link
  | None -> failwith_f "Error attaching program %s" name

let bpf_program_fd (prog : bpf_program) = prog.fd

let bpf_object_find_map_by_name bpf_object name =
  match C.Functions.bpf_object__find_map_by_name bpf_object name with
  | Some ptr -> { fd = C.Functions.bpf_map__fd ptr; ptr }
  | None -> failwith_f "Map %s not found" name

let bpf_map_fd (map : bpf_map) = map.fd

let bpf_link_destroy bpf_link =
  match C.Functions.bpf_link__destroy bpf_link with
  | e when e <> 0 -> Printf.eprintf "Failed to destroy link %d\n" e
  | _ -> ()

let bpf_object_close bpf_object = C.Functions.bpf_object__close bpf_object

let with_bpf_object_open_load_link ~obj_path ~program_names
    ?(before_link = Stdlib.ignore) fn =
  let obj = bpf_object_open obj_path in
  bpf_object_load obj;

  let cleanup ?links obj =
    Option.iter (List.iter bpf_link_destroy) links;
    bpf_object_close obj
  in

  (* Programs to load cannot be zero *)
  if program_names = [] then (
    cleanup obj;
    failwith "Need to specify at least one program to load");

  (* Get list of programs *)
  let programs, not_found =
    List.fold_left
      (fun (succ, fail) name ->
        match C.Functions.bpf_object__find_program_by_name obj name with
        | None -> (succ, name :: fail)
        | Some prog -> ((prog, name) :: succ, fail))
      ([], []) program_names
  in
  if not_found <> [] then (
    cleanup obj;
    failwith_f "Failed to find %s programs" (String.concat "," not_found));

  (* Run before_link user initialization code *)
  (try before_link obj
   with e ->
     bpf_object_close obj;
     raise e);

  (* Get list of links *)
  let links, not_attached =
    List.fold_left
      (fun (succ, fail) (prog, name) ->
        match C.Functions.bpf_program__attach prog with
        | None -> (succ, name :: fail)
        | Some prog -> (prog :: succ, fail))
      ([], []) programs
  in
  if not_attached <> [] then (
    (* Detached successfully attached before shutdown *)
    cleanup ~links obj;
    failwith_f "Failed to link %s programs" (String.concat "," not_attached));

  (* Run user program *)
  (try fn obj links
   with e ->
     cleanup ~links obj;
     raise e);

  (* Ensure proper shutdown *)
  cleanup ~links obj

let bpf_map_lookup_value ~key_ty ~val_ty ~val_zero bpf_map key =
  let key = allocate key_ty key in
  let sz_key = sizeof key_ty |> Unsigned.Size_t.of_int in
  let value = allocate val_ty val_zero in
  let sz_val = sizeof val_ty |> Unsigned.Size_t.of_int in
  let err =
    C.Functions.bpf_map__lookup_elem bpf_map.ptr (to_voidp key) sz_key
      (to_voidp value) sz_val Unsigned.UInt64.zero
  in
  if err = 0 then !@value
  else
    let err = Printf.sprintf "bpf_map_lookup_value got %d" err in
    raise (Sys_error err)

let bpf_map_update_elem ~key_ty ~val_ty bpf_map key value =
  let key = allocate key_ty key in
  let sz_key = sizeof key_ty |> Unsigned.Size_t.of_int in
  let value = allocate val_ty value in
  let sz_val = sizeof val_ty |> Unsigned.Size_t.of_int in
  let err =
    C.Functions.bpf_map__update_elem bpf_map.ptr (to_voidp key) sz_key
      (to_voidp value) sz_val Unsigned.UInt64.zero
  in
  if err = 0 then ()
  else
    let err = Printf.sprintf "bpf_map_update_value got %d" err in
    raise (Sys_error err)
