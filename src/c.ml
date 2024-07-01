(* This extra level of indirection is so that the ocaml_libbpf.mli
   interface can infer the types of the Functions module, Functors
   cannot be used in the mli file *)
module Types = C_function_description.Types
module Functions = C_function_description.Functions (C_generated_functions)
