module Primatives = struct
  module Types = C.Types
  module Functions = C.Functions
end

module Wrappers = struct
  module type Conv = sig
    val c_type : 'a Ctypes.typ
    val empty : 'a
  end

  module Bpf_maps (Key : Conv) (Val : Conv) = struct
    type bpf_map = { fd : int; bpf_map : C.Types.bpf_map }

    let bpf_map_lookup_value_op bpf_map key =
      let open Ctypes in
      let key = allocate Key.c_type key in
      let value = allocate Val.c_type Val.empty in
      let err =
        C.Functions.Bpf.bpf_map_lookup_elem bpf_map.fd (to_voidp key)
          (to_voidp value)
      in
      if err <> 0 then Result.error err else Result.ok !@value

    let bpf_map_update_elem_op bpf_map key value _flags =
      let open Ctypes in
      let key = allocate Key.c_type key in
      (* This might be garbage collected to soon *)
      let value = allocate Val.c_type value in
      let err =
        C.Functions.Bpf.bpf_map_update_elem bpf_map.fd (to_voidp key)
          (to_voidp value) Unsigned.UInt64.zero
      in
      if err <> 0 then Result.error err else Result.ok ()
  end
end
