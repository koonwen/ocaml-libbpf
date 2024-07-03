let () =
  let concurrency = Cstubs.unlocked in
  let errno = Cstubs.ignore_errno in
  match Sys.argv.(1) with
  | "ml" ->
      Cstubs.write_ml ~concurrency Format.std_formatter ~prefix:"" ~errno
        (module C_function_description.Functions)
  | "c" ->
      print_endline "#include <bpf/libbpf.h>";
      Cstubs.write_c ~concurrency Format.std_formatter ~prefix:"" ~errno
        (module C_function_description.Functions)
  | s -> failwith ("unknown functions " ^ s)
