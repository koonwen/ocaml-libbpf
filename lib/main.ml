let () =
  let major = Libbpf.Functions.libbpf_major_version () in
  let minor = Libbpf.Functions.libbpf_minor_version () in
  Printf.printf "version %s.%s\n"
    (Ctypes_value_printing.string_of Ctypes.uint32_t major)
    (Ctypes_value_printing.string_of Ctypes.uint32_t minor)
