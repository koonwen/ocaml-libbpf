(lang dune 3.13)

(name ocaml_libbpf)

(generate_opam_files true)

(source
 (github koonwen/ocaml-libbpf))

(authors "Lee Koon Wen")

(maintainers "Lee Koon Wen")

(license ISC BSD-3-Clause)

(documentation "https://koonwen.github.io/ocaml-libbpf")

(package
 (name ocaml_libbpf)
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
  conf-zlib                     ; Should be able to remove this because we install libbpf
  conf-clang)
 ; We should be able to remove this / make this optional since it is used for building the c bpf programs
 (tags
  (bindings bpf libbpf)))

(package
 (name ocaml_libbpf_maps)
 (synopsis "Libbpf maps API")
 (description "High level API's for interacting with BPF maps in OCaml")
 (depends
  (ocaml_libbpf
   (= :version))
  ctypes-foreign)
 (tags
  (bindings bpf libbpf)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project
