module F = Ocaml_libbpf.C.Functions
module T = Ocaml_libbpf.C.Types

let () =
  let major = Ocaml_libbpf.major () in
  let minor = Ocaml_libbpf.minor () in
  let version = Ocaml_libbpf.version () in
  Printf.printf "Major:%d, Minor:%d, Libbpf.%s" major minor version
