[@@@warning "-26"]

let () =
  let major = Libbpf.Functions.libbpf_major_version () in
  let minor = Libbpf.Functions.libbpf_minor_version () in
  Libbpf.Functions.libbpf_set_strict_mode LIBBPF_STRICT_ALL;
  let attach_typ =
    Libbpf.Functions.libbpf_bpf_attach_type_str
      Types_generated.BPF_CGROUP_DEVICE
  in
  Printf.printf "version %s.%s %s\n"
    (Ctypes_value_printing.string_of Ctypes.uint32_t major)
    (Ctypes_value_printing.string_of Ctypes.uint32_t minor)
    attach_typ;
  match Libbpf.Functions.bpf_object__open "minimal.bpf.o" with
  | None -> failwith "Got NULL"
  | Some obj_ptr ->
      print_endline "Open successful";
      if Libbpf.Functions.bpf_object__load obj_ptr = 0 then
        print_endline "Load success" else print_endline "Load failed"
