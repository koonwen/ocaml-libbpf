open Ocaml_libbpf
(** Ocaml_libbpf_maps provide a convenient Make functor interface for
    interacting with your maps. Users just need to provide the
    underlying c types of their map key and values, *)

module type Conv = sig
  type t
  (** The OCaml type mapping the underlying c type in [ty]. Users
        cannot define arbritrary OCaml types but instead use the
        appropriate Ctypes interfaces to construct this OCaml type *)

  val empty : t
  (** Used for initializing memory during memory allocation. This is
        a requirement by Ctypes library to have memory initialized to
        some value *)

  val ty : t Ctypes.typ
  (** The C value representing the underlying custom c type *)
end

(* Support flags in the future, Need to get kernel headers for
   this *)
(* type flags = *)
(*   | BPF_NOEXIST *)
(*   | BPF_EXIST *)
(*   | BPF_ANY *)
(*   (\* Flag value BPF_NOEXIST cannot be used for maps of types *)
(*      BPF_MAP_TYPE_ARRAY or BPF_MAP_TYPE_PERCPU_ARRAY (all elements *)
(*      always exist), the helper would return an error *\) *)

module IntConv : Conv with type t = int
module LongConv : Conv with type t = Signed.Long.t

module Make : functor (Key : Conv) (Val : Conv) -> sig
  val bpf_map_lookup_value : bpf_map -> Key.t (* -> flags *) -> Val.t
  (** [bpf_map_lookup_value map k flags] looks up the value
        associated with the key [k]. If key is invalid, no value is found or the size
        of key/value is not in sync, it will return an error *)

  val bpf_map_update_elem : bpf_map -> Key.t -> Val.t (* -> flags *) -> unit
  (** [bpf_map_update_elem map k v flags] updates the value
        associated the key [k] to [v]. If key is invalid or the size
        of key/value is not in sync, it will return an error *)
end

module RingBuffer : sig
  type t

  type callback =
    unit Ctypes_static.ptr -> unit Ctypes_static.ptr -> Unsigned.size_t -> int

  val init : bpf_map -> callback:callback -> (t -> unit) -> unit
  (** [init bpf_map callback] loads [callback] into the ring buffer
        map provided by [bpf_map]. bpf map is freed by default when
        the OCaml process exits

        TO BE ADDED [ctx_ptr] allows the callback function to access
        user provided context. *)

  val poll : t -> timeout:int -> int
  (** [poll t timeout] polls the ringbuffer to execute the loaded
        callbacks on any pending entries, The function returns if
        there are no entries in the given timeout,

        Error code is returned if something went wrong, Ctrl-C will
        cause -EINTR *)

  val consume : t -> int
  (** [consume t] runs callbacks on all entries in the ringbuffer
        without event polling. Use this only if trying to squeeze
        extra performance with busy-waiting.

        Error code is returned if something went wrong Ctrl-C will
        cause -EINTR *)
end
