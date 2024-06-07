(lang dune 3.13)

(using ctypes 0.3)

(name ocaml_libbpf)

(generate_opam_files true)

(source
 (github koonwen/ocaml-libbpf))

(authors "Lee Koon Wen")

(maintainers "Lee Koon Wen")

(license LGPL-2.1-only)

(documentation https://url/to/documentation)

(package
 (name ocaml_libbpf)
 (synopsis "Libbpf bindings")
 (description "Wrapped libbpf api's for writing BPF user programs in OCaml")
 (depends ocaml dune ctypes ctypes-foreign ppx_deriving ppx_expect conf-zlib)
 (tags
  (bindings bpf libbpf)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project
