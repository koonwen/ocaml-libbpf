module type HELPERS = sig
  (* open Format *)
  (* (\* long bpf_trace_printk(const char *fmt, u32 fmt_size, ...) *\) *)
  (* val bpf_trace_printk: ('a, formatter, unit) format -> 'a *)

  (* u64 bpf_get_current_pid_tgid(void) *)
  val bpf_get_current_pid_tgid: unit -> int * int
end

module Helpers : HELPERS = struct
  let bpf_get_current_pif_tgid

end
