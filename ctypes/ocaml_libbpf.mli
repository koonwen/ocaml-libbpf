module Primative : sig
  module Types = C.Types
  module Functions = C.Functions
end

type bpf_object
type bpf_program
type bpf_map
type bpf_link

val bpf_object_open : string -> bpf_object
val bpf_object_load : bpf_object -> unit
val bpf_object_find_program_by_name : bpf_object -> string -> bpf_program option
val bpf_program_attach : bpf_program -> bpf_link
val bpf_object_find_map_by_name : bpf_object -> string -> bpf_map option
val bpf_link_destroy : bpf_link -> unit
val bpf_object_close : bpf_object -> unit

module type Conv = sig
  type t

  val c_type : t Ctypes.typ
  val empty : t
end

module Bpf_maps : sig
  module Make : functor (Key : Conv) (Val : Conv) -> sig
    val bpf_map_lookup_value_op : bpf_map -> Key.t -> (Val.t, int) Result.t

    val bpf_map_update_elem_op :
      bpf_map -> Key.t -> Val.t -> int64 -> (unit, int) Result.t
  end
end
