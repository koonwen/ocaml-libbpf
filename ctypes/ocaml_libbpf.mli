module C : sig
  module Types = Libbpf_bindings.Types
  module Functions = Libbpf_bindings.Functions
end

(* How do I mix these abstract types with the underlying C types so
   that experienced users can mix the low-level C calls the
   high and low level API's? *)
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

val with_bpf_object_open_load_link :
  obj_path:string ->
  program_names:string list ->
  ?before_link:(bpf_object -> unit) ->
  (bpf_object -> bpf_link list -> unit) ->
  unit
(** [with_bpf_object_open_load_link obj_path program_names
    ?before_link fn] performs opening and loading of the provided
    filesystem path to the bpf_object [obj_path]. This helper runs
    [before_link] before the program attaches the bpf programs
    specified in [program_names]. Initialization code should go
    here. [fn] is passed the bpf_object and the list of program links
    if all steps were successful. *)

module type Conv = sig
  type t

  val c_type : t Ctypes.typ
  val empty : t
end

(* module Bpf_maps : sig *)
(*   module Make : functor (Key : Conv) (Val : Conv) -> sig *)
(*     val bpf_map_lookup_value_op : bpf_map -> Key.t -> (Val.t, int) Result.t *)

(*     val bpf_map_update_elem_op : *)
(*       bpf_map -> Key.t -> Val.t -> int64 -> (unit, int) Result.t *)
(*   end *)
(* end *)
