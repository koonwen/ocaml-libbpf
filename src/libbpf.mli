(** See {!page-index} for example usage *)

open Ctypes

module C : module type of C
(** Entry point for the underlying C primatives *)

val major_version : int
val minor_version : int
val version_string : string
val bpf_attach_type_str : C.Types.Bpf_attach_type.t -> string
val bpf_link_type_str : C.Types.Bpf_link_type.t -> string
val bpf_map_type_str : C.Types.Bpf_map_type.t -> string
val bpf_prog_type_str : C.Types.Bpf_prog_type.t -> string

type bpf_object = C.Types.bpf_object structure ptr

type bpf_program = {
  name : string;
  fd : int;
  ptr : C.Types.bpf_program structure ptr;
}

type bpf_map = { fd : int; ptr : C.Types.bpf_map structure ptr }
type bpf_link = C.Types.bpf_link structure ptr

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

val bpf_program_fd : bpf_program -> int
(** [bpf_map_fd prog] returns the fd of the [prog] *)

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

val bpf_map_lookup_value :
  key_ty:'a typ -> val_ty:'b typ -> val_zero:'b -> bpf_map -> 'a -> 'b
(** [bpf_map_lookup_value key_ty val_ty val_zero map k flags] Looks
      up the value associated with the key [k]. If key is invalid, no
      value is found or the size of key/value is not in sync, it will
      return an error. [bpf_map_lookup_value] expects [key_ty] and
      [val_ty] to verify the types are coherent in your bpf map
      declaration. [val_zero] is merely an initialization value that
      will be overwritten.  *)

val bpf_map_update_elem :
  key_ty:'a typ -> val_ty:'b typ -> bpf_map -> 'a -> 'b (* -> flags *) -> unit
(** [bpf_map_update_elem key_ty val_ty map k v flags] updates the
      value associated the key [k] to [v]. If key is invalid or the
      size of key/value is not in sync, it will return an
      error. [bpf_map_update_elem] expects [key_ty] and [val_ty] to
      verify the types are coherent in your bpf map declaration. *)
