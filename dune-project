(lang dune 3.13)

(name libbpf)

(generate_opam_files true)

(source
 (github koonwen/ocaml-libbpf))

(authors "Lee Koon Wen")

(maintainers "Lee Koon Wen")

(license ISC BSD-3-Clause)

(documentation https://koonwen.github.io/ocaml-libbpf)

(package
 (allow_empty)
 (name conf-libbpf)
 (synopsis "System installation of libbpf"))

(package
 (name libbpf)
 (synopsis "Libbpf bindings")
 (description "Wrapped libbpf api's for writing BPF user programs in OCaml")
 (depends
  (ocaml
   (>= 4.08))
  dune
  (ctypes
   (>= 0.22.0))
  ppx_deriving
  ppx_expect
  conf-zlib
  conf-clang)
 (tags
  (bindings bpf libbpf)))

(package
 (name libbpf_maps)
 (synopsis "Libbpf maps API")
 (description "High level API's for interacting with BPF maps in OCaml")
 (depends
  (ctypes
   (>= 0.22.0))
  (ctypes-foreign
   (>= 0.22.0))
  (ocaml_libbpf
   (= :version)))
 (tags
  (bindings bpf libbpf)))
