let () =
  print_endline "#include <bpf/libbpf.h>";
  Cstubs_structs.write_c Format.std_formatter (module C_type_description.Types)
