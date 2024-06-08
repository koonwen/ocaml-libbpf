(* This extra level of indirection is so that the ocaml_libbpf.mli
   interface can infer the types of the Functions module, Functors
   cannot be used in the mli file *)
module Types = Libbpf_c_function_descriptions.Types

module Functions =
  Libbpf_c_function_descriptions.Functions (Libbpf_c_generated_functions)
