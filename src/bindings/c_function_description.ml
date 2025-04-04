open Ctypes

(** You probably don't mean to be looking into this section, it is
    part of the stub generation process of the bindings.*)

(* The C_types_generated module is generated by the build system to
    grab the type definitions from the header files in C to ensure
    that offsets and structs are aligned. *)
module Types = C_type_description.Types (C_types_generated)

module Functions (F : Ctypes.FOREIGN) = struct
  open F

  (* ======================================== Generics ======================================== *)
  let libbpf_major_version =
    foreign "libbpf_major_version" (void @-> returning uint32_t)

  let libbpf_minor_version =
    foreign "libbpf_minor_version" (void @-> returning uint32_t)

  let libbpf_version_string =
    foreign "libbpf_version_string" (void @-> returning string)

  let libbpf_strerror =
    foreign "libbpf_strerror" (int @-> ptr char @-> size_t @-> returning int)

  let libbpf_bpf_attach_type_str =
    foreign "libbpf_bpf_attach_type_str"
      (Types.Bpf_attach_type.t @-> returning string)

  let libbpf_bpf_link_type_str =
    foreign "libbpf_bpf_link_type_str"
      (Types.Bpf_link_type.t @-> returning string)

  let libbpf_bpf_map_type_str =
    foreign "libbpf_bpf_map_type_str" (Types.Bpf_map_type.t @-> returning string)

  let libbpf_bpf_prog_type_str =
    foreign "libbpf_bpf_prog_type_str"
      (Types.Bpf_prog_type.t @-> returning string)

  let libbpf_set_print =
    foreign "libbpf_set_print"
      (Types.libbpf_print_fn_t @-> returning Types.libbpf_print_fn_t)

  (* ================================= Open / Load / Close  =================================== *)

  (** [bpf_object__open path] creates a bpf_object by opening the BPF
      ELF object file pointed to by the passed [path] and loading it
      into memory.

      Returns pointer to the new bpf_object; or NULL is returned on
      error, error code is stored in errno. *)
  let bpf_object__open =
    foreign "bpf_object__open" (string @-> returning (ptr_opt Types.bpf_object))

  (** [bpf_object__load obj_ptr] loads the BPF object into the
      kernel. [obj_ptr] must be a valid BPF object instance returned
      by a successful call to [bpf_object__open].

      Returns 0, on success; negative error code, otherwise, error code is stored in errno *)
  let bpf_object__load =
    foreign "bpf_object__load" (ptr Types.bpf_object @-> returning int)

  (** [bpf_object__find_program_by_name name] returns the BPF program
      of the given [name], if it exists within the passed BPF object

      Returns the pointer to the BPF program instance, if such program
      exists within the BPF object; or NULL otherwise.  *)
  let bpf_object__find_program_by_name =
    foreign "bpf_object__find_program_by_name"
      (ptr Types.bpf_object @-> string @-> returning (ptr_opt Types.bpf_program))

  (** [bpf_object__next_program obj_ptr prog_ptr] returns the next
      program after [prog_ptr] found in the passed BPF object *)
  let bpf_object__next_program =
    foreign "bpf_object__next_program"
      (ptr Types.bpf_object @-> ptr Types.bpf_program
      @-> returning (ptr Types.bpf_program))

  (** [bpf_program__pin prog path] pins the BPF program to a file in
      the BPF FS specified by a [path]. This increments the programs
      reference count, allowing it to stay loaded after the process
      which loaded it has exited.

      @param prog BPF program to pin, must already be loaded
      @param path file path in a BPF file system
      @return 0, on success; negative error code, otherwise *)
  let bpf_program__pin =
    foreign "bpf_program__pin"
      (ptr Types.bpf_program @-> ptr char @-> returning int)

  (** [bpf_program__unpin prog path] unpins the BPF program from a file in the
      BPFFS specified by a path. This decrements the programs
      reference count. The file pinning the BPF program can also be
      unlinked by a different process in which case this function will
      return an error.

      @param prog BPF program to unpin
      @param path file path to the pin in a BPF file system
      @return 0, on success; negative error code, otherwise  *)
  let bpf_program__unpin =
    foreign "bpf_program__unpin"
      (ptr Types.bpf_program @-> ptr char @-> returning int)

  (** [bpf_program__attach prog] is a generic function for
      attaching a BPF program based on auto-detection of program type,
      attach type, and extra paremeters, where applicable.

      This is supported for:
      - kprobe/kretprobe (depends on SEC() definition)
      - uprobe/uretprobe (depends on SEC() definition)
      - tracepoint
      - raw tracepoint
      - tracing programs (typed raw TP/fentry/fexit/fmod_ret)

      Returns pointer to the newly created BPF link; or NULL is
      returned on error, error code is stored in errno *)
  let bpf_program__attach =
    foreign "bpf_program__attach"
      (ptr Types.bpf_program @-> returning (ptr_opt Types.bpf_link))

  let bpf_program__fd =
    foreign "bpf_program__fd" (ptr Types.bpf_program @-> returning int)

  (** [bpf_link__pin link path] pins the BPF link to a file in the
      BPF FS specified by a path. This increments the links reference
      count, allowing it to stay loaded after the process which loaded
      it has exited.

      @param link BPF link to pin, must already be loaded
      @param path file path in a BPF file system
      @return 0, on success; negative error code, otherwise *)
  let bpf_link__pin =
    foreign "bpf_link__pin" (ptr Types.bpf_link @-> ptr char @-> returning int)

  (** [bpf_link__unpin link path] unpins the BPF link from a file in
      the BPFFS specified by a path. This decrements the links
      reference count. The file pinning the BPF link can also be
      unlinked by a different process in which case this function will
      return an error.

      @param prog BPF program to unpin
      @param path file path to the pin in a BPF file system
      @return 0, on success; negative error code, otherwise *)
  let bpf_link__unpin =
    foreign "bpf_link__unpin" (ptr Types.bpf_link @-> returning int)

  (** [bpf_link__destroy link_ptr] Removes the link to the BPF program.
      Returns 0 on success or -errno *)
  let bpf_link__destroy =
    foreign "bpf_link__destroy" (ptr Types.bpf_link @-> returning int)

  (** [bpf_object__close obj_ptr] closes a BPF object and releases all
      resources. *)
  let bpf_object__close =
    foreign "bpf_object__close" (ptr Types.bpf_object @-> returning void)

  (* ======================================== Maps ======================================== *)
  (* Not explicitly mentioned in the documentation but keys and values look
     like they're copied into the internal bpf map structure, so we
     don't need to be worried about keeping references around. *)

  (** [bpf_object__find_map_by_name obj_ptr name] returns BPF map of the given
      [name], if it exists within the passed BPF object.

      Returns the pointer to the BPF map instance, if such map exists
      within the BPF object; or NULL otherwise.  *)
  let bpf_object__find_map_by_name =
    foreign "bpf_object__find_map_by_name"
      (ptr Types.bpf_object @-> string @-> returning (ptr_opt Types.bpf_map))

  (** [bpf_map__fd map_ptr] gets the file descriptor of the passed BPF
      map

      Returns the file descriptor; or -EINVAL in case of an error  *)
  let bpf_map__fd = foreign "bpf_map__fd" (ptr Types.bpf_map @-> returning int)

  (** [bpf_map__lookup_elem map_ptr key_ptr key_sz val_ptr val_sz
      flags] allows to lookup BPF map value corresponding to provided
      key.

     [bpf_map__lookup_elem] is high-level equivalent of
     [bpf_map_lookup_elem] API with added check for key and value
      size.

      sizes are in bytes of key and value data. For per-CPU BPF maps
      value size has to be a product of BPF map value size and number
      of possible CPUs in the system (could be fetched with
      libbpf_num_possible_cpus()). Note also that for per-CPU values
      value size has to be aligned up to closest 8 bytes for alignment
      reasons, so expected size is: round_up(value_size, 8)

      Returns 0, on success; negative error, otherwise *)
  let bpf_map__lookup_elem =
    foreign "bpf_map__lookup_elem"
      (ptr Types.bpf_map @-> ptr void @-> size_t @-> ptr void @-> size_t
     @-> uint64_t @-> returning int)

  (** [bpf_map__update_elem map_ptr key_ptr key_sz val_ptr val_sz
      flags] allows to insert or update value in BPF map that
      corresponds to provided key.

      [bpf_map__update_elem] is high-level equivalent of
      [bpf_map_update_elem] API with added check for key and value
      size.

      Check [bpf_map__lookup_elem] for details on sizes.
      Returns 0, on success; negative error, otherwise *)
  let bpf_map__update_elem =
    foreign "bpf_map__update_elem"
      (ptr Types.bpf_map @-> ptr void @-> size_t @-> ptr void @-> size_t
     @-> uint64_t @-> returning int)

  (** [bpf_map__delete_elem map_ptr key_ptr key_sz flags] allows to
      delete element in BPF map that corresponds to provided key.

      [bpf_map__delete_elem] is high-level equivalent of
      [bpf_map_delete_elem] API with added check for key size.

      Returns 0, on success; negative error, otherwise *)
  let bpf_map__delete_elem =
    foreign "bpf_map__delete_elem"
      (ptr Types.bpf_map @-> ptr void @-> size_t @-> uint64_t @-> returning int)

  (* ================================== Xdp ================================== *)
  let bpf_xdp_attach =
    foreign "bpf_xdp_attach"
      (int @-> int @-> uint32_t
      @-> ptr Types.Bpf_xdp.Attach_opts.t
      @-> returning int)

  let bpf_xdp_detach =
    foreign "bpf_xdp_detach"
      (int @-> uint32_t @-> ptr Types.Bpf_xdp.Attach_opts.t @-> returning int)

  (* ================================== Traffic control ================================== *)

  let bpf_tc_hook_create =
    foreign "bpf_tc_hook_create" (ptr Types.Bpf_tc.hook @-> returning int)

  let bpf_tc_hook_destroy =
    foreign "bpf_tc_hook_destroy" (ptr Types.Bpf_tc.hook @-> returning int)

  let bpf_tc_attach =
    foreign "bpf_tc_attach"
      (ptr Types.Bpf_tc.hook @-> ptr Types.Bpf_tc.Opts.t @-> returning int)

  let bpf_tc_detach =
    foreign "bpf_tc_detach"
      (ptr Types.Bpf_tc.hook @-> ptr Types.Bpf_tc.Opts.t @-> returning int)

  (* ====================================== RingBuf ===================================== *)

  (** [ring_buffer__new map_fd fn ctx_ptr opts] loads the callback
      function [fn] into the ring buffer map provided by the file
      descriptor [map_fd]. [ctx_ptr] allows the callback function to
      access user provided context.

      Returns pointer to the ring_buffer manager instance or NULL
      otherwise *)
  let ring_buffer__new =
    foreign "ring_buffer__new"
      (int @-> Types.ring_buffer_sample_fn @-> ptr void
     @-> ptr Types.ring_buffer_opts
      @-> returning (ptr_opt Types.ring_buffer))

  (** [ring_buffer__poll ring_buf_ptr timeout] poll for available
      data and consume records, if any are available.

      Returns number of records consumed (or INT_MAX, whichever is
      less), or negative number, if any of the registered callbacks
      returned error. *)
  let ring_buffer__poll =
    foreign "ring_buffer__poll" (ptr Types.ring_buffer @-> int @-> returning int)

  (** [ring_buffer__free ring_buf_ptr] Frees resources of the ring
      buffer manager *)
  let ring_buffer__free =
    foreign "ring_buffer__free" (ptr Types.ring_buffer @-> returning void)

  (** [ring_buffer__consume ring_buf_ptr] Consume available ring
      buffer(s) data without event polling.

      Returns number of records consumed across all registered ring
      buffers (or INT_MAX, whichever is less), or negative number if
      any of the callbacks return error.  *)
  let ring_buffer__consume =
    foreign "ring_buffer__consume" (ptr Types.ring_buffer @-> returning int)

  (** [ring_buffer__epoll_fd ring_buf_ptr] Gets an fd that can be used
      to sleep until data is available in the ring(s) *)
  let ring_buffer__epoll_fd =
    foreign "ring_buffer__epoll_fd" (ptr Types.ring_buffer @-> returning int)
end
