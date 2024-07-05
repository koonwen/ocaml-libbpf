open Libbpf
(** Libbpf_maps provide a convenient API's for handling maps,
    currently only Ringbuffers are supported *)

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

  val get_epoll_fd : t -> int
  (** [get_epoll_fd t] returns a file descriptor that can be used
          to sleep until data is available in the ring(s) *)
end
