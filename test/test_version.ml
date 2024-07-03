let () =
  let open Libbpf in
  Printf.printf "Major:%d, Minor:%d, Libbpf.%s" major_version minor_version
    version_string
