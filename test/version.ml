module F = Ocaml_libbpf.Primative.Functions
module T = Ocaml_libbpf.Primative.Types

let () =
  let major = F.libbpf_major_version () |> Unsigned.UInt32.to_string in
  let minor = F.libbpf_minor_version () |> Unsigned.UInt32.to_string in
  Printf.printf "Libbpf.v.%s.%s\n" major minor
