module C : sig
  module Types = Libbpf_bindings.Types
  module Functions = Libbpf_bindings.Functions
end

(* How do I mix these abstract types with the underlying C types so
   that experienced users can mix the low-level C calls the
   high and low level API's? *)
type bpf_object = C.Types.bpf_object Ctypes.structure Ctypes.ptr

type bpf_program = {
  name : string;
  ptr : C.Types.bpf_program Ctypes.structure Ctypes.ptr;
}

type bpf_map = { fd : int; ptr : C.Types.bpf_map Ctypes.structure Ctypes.ptr }
type bpf_link = C.Types.bpf_link Ctypes.structure Ctypes.ptr

val bpf_object_open : string -> bpf_object
(** [bpf_object_open path] opens and tries to read the bpf_object
    found at path [path] in the filesystem. Libbpf parses the BPF
    object file and discovers BPF maps, BPF programs, and global
    variables. After a BPF app is opened, user space apps can make
    additional adjustments (setting BPF program types, if necessary;
    pre-setting initial values for global variables, etc.) before all
    the entities are created and loaded.

    Fails if object file is in invalid format or path does not exist *)

val bpf_object_load : bpf_object -> unit
(** [bpf_object_load obj] tries to load [obj]. Libbpf parses
    the BPF object file and discovers BPF maps, BPF programs, and
    global variables. After a BPF app is opened, user space apps can
    make additional adjustments (setting BPF program types, if
    necessary; pre-setting initial values for global variables, etc.)
    before all the entities are created and loaded. *)

val bpf_object_find_program_by_name : bpf_object -> string -> bpf_program
(** [bpf_object_find_program_by_name obj name] locates the
    program identifier [name] within the [obj].

    Fails if [name] is not found *)

val bpf_program_attach : bpf_program -> bpf_link
(** [bpf_program_attach prog] attaches the [prog] in the
    kernel to start respond to events. Libbpf attaches BPF programs to
    various BPF hook points (e.g., tracepoints, kprobes, cgroup hooks,
    network packet processing pipeline, etc.). During this phase, BPF
    programs perform useful work such as processing packets, or
    updating BPF maps and global variables that can be read from user
    space

    Fails if link could not be attached *)

val bpf_object_find_map_by_name : bpf_object -> string -> bpf_map
(** [bpf_object_find_map_by_name obj name] locates the bpf_map
    identifier [name] within [obj].

    Fails if map is not found *)

val bpf_map_fd : bpf_map -> int
(** [bpf_map_fd map] returns the fd of the [map] *)

val bpf_link_destroy : bpf_link -> unit
(** [bpf_link_destroy link] detaches and unloads the bpf program
    associated to [link] from the kernel *)

val bpf_object_close : bpf_object -> unit
(** [bpf_object_close obj] tearsdown [obj]. BPF maps are destroyed,
    and all the resources used by the BPF app are freed. *)

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
    if all steps were successful. Ensures all the proper shutdown and
    cleanup of bpf_object resources and links *)

(** Bpf_maps provide a convenient Make functor interface for
    interacting with your maps. Users just need to provide the
    underlying c types of their map key and values, *)
module Bpf_maps : sig
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
    val bpf_map_lookup_value :
      bpf_map -> Key.t (* -> flags *) -> (Val.t, int) Result.t
    (** [bpf_map_lookup_value map k flags] looks up the value
        associated with the key [k]. If key is invalid, no value is found or the size
        of key/value is not in sync, it will return an error *)

    val bpf_map_update_elem :
      bpf_map -> Key.t -> Val.t (* -> flags *) -> (unit, int) Result.t
    (** [bpf_map_update_elem map k v flags] updates the value
        associated the key [k] to [v]. If key is invalid or the size
        of key/value is not in sync, it will return an error *)
  end

  module RingBuffer : sig
    type t

    type callback =
      unit Ctypes_static.ptr -> unit Ctypes_static.ptr -> Unsigned.size_t -> int

    val init : bpf_map -> callback:callback -> t
    (** [init bpf_map callback] loads [callback] into the ring buffer
        map provided by [bpf_map]. bpf map is freed by default when
        the OCaml process exits

        TO BE ADDED [ctx_ptr] allows the callback function to access
        user provided context. *)

    val poll : t -> timeout:int -> (int, int) Result.t
    (** [poll t timeout] polls the ringbuffer to execute the loaded
        callbacks on any pending entries, The function returns if
        there are no entries in the given timeout,

        Error code is returned if soemthing went wrong, Ctrl-C will
        cause -EINTR *)

    val consume : t -> (int, int) Result.t
    (** [consume t] runs callbacks on all entries in the ringbuffer
        without event polling. Use this only if trying to squeeze
        extra performance with busy-waiting.

        Error code is returned if soemthing went wrong Ctrl-C will
        cause -EINTR *)
  end
end
