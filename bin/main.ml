let () =
  let major = Bpf.libbpf_major_version () in
  let minor = Bpf.libbpf_minor_version () in
  let version_s = Bpf.libbpf_version_string () in
  Printf.printf "Version %ld.%ld = %s\n" major minor version_s
