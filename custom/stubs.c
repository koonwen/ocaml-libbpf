#include "caml/mlvalues.h"
#include "caml/alloc.h"
#include "caml/memory.h"
#include "bpf/libbpf.h"
#include <sys/types.h>

/* LIBBPF_API __u32 libbpf_major_version (void) */
CAMLprim value caml_libbpf_major_version(void) {

    CAMLparam0();
    __u32 version = libbpf_major_version();
    CAMLreturn (caml_copy_int32(version));
};

/* LIBBPF_API __u32 libbpf_minor_version (void) */
CAMLprim value caml_libbpf_minor_version(void) {

    CAMLparam0();
    __u32 version = libbpf_minor_version();
    CAMLreturn (caml_copy_int32(version));
};

CAMLprim value caml_libbpf_version_string(value unit) {
    CAMLparam1(unit);
    CAMLreturn(caml_copy_string(libbpf_version_string()));
}

CAMLprim value caml_libbpf_strerror(value err, value buf, value size) {
    CAMLparam3(err, buf, size);

    int res = libbpf_strerror(err, buf, Nativeint_val(size));
    CAMLreturn(res);
}
