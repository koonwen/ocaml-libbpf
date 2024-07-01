let c_headers = "#include \"libbpf.h\""

let main () =
  let stubs_out = open_out "gen_type_bindings.c" in
  let stubs_fmt = Format.formatter_of_out_channel stubs_out in
  Format.fprintf stubs_fmt "%s@\n" c_headers;
  Cstubs_structs.write_c stubs_fmt (module C_type_description.Types);
  Format.pp_print_flush stubs_fmt ();
  close_out stubs_out

let () = main ()
