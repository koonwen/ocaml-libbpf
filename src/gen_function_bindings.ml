(*
 * Copyright (c) 2014 Jeremy Yallop.
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 *)

let c_headers = "#include \"libbpf.h\""

let main () =
  let ml_out = open_out "libbpf_c_generated_functions.ml"
  and c_out = open_out "libbpf_stubs.c" in
  let ml_fmt = Format.formatter_of_out_channel ml_out
  and c_fmt = Format.formatter_of_out_channel c_out in
  Format.fprintf c_fmt "%s@\n" c_headers;
  Cstubs.write_c c_fmt ~prefix:""
    (module Libbpf_c_function_descriptions.Functions);
  Cstubs.write_ml ml_fmt ~prefix:""
    (module Libbpf_c_function_descriptions.Functions);
  Format.pp_print_flush ml_fmt ();
  Format.pp_print_flush c_fmt ();
  close_out ml_out;
  close_out c_out

let () = main ()
