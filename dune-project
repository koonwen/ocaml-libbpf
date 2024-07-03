(lang dune 3.13)

(name libbpf)
(source
 (github koonwen/ocaml-libbpf))
(authors "Lee Koon Wen")
(maintainers "Lee Koon Wen")
(license ISC BSD-3-Clause)
(documentation https://koonwen.github.io/ocaml-libbpf)

(package
 (allow_empty)
 (name conf-libbpf)
 (synopsis "Virtual package for system installation of libbpf"))

(package
 (allow_empty)
 (name conf-bpftool)
 (synopsis "Virtual package for system installation of bpftool"))

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
  conf-libbpf
  conf-bpftool
  conf-clang)
 ; This is only a dependency for the examples directory
 ; to show how to use dune to build bpf programs, it is
 ; not part of the library bindings, however, we can't
 ; remove it since it builds alongside the library
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
  (libbpf
   (= :version)))
 (tags
  (bindings bpf libbpf)))
