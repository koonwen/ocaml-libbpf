let () =
  let open Ocaml_libbpf in
  Printf.printf "Major:%d, Minor:%d, Libbpf.%s" major_version minor_version
    version_string
