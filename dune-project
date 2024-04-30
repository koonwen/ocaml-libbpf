(lang dune 3.13)

(using ctypes 0.3)

(name ocaml_libbpf)

(generate_opam_files true)

(source
 (github koonwen/ocaml-libbpf))

(authors "Lee Koon Wen")

(maintainers "Lee Koon Wen")

(license LICENSE)

(documentation https://url/to/documentation)

(package
 (name ocaml_libbpf)
 (synopsis "Libbpf bindings")
 (description "Wrapped libbpf api's for writing BPF user programs in OCaml")
 (depends ocaml dune)
 (tags
  (bindings bpf libbpf)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project
