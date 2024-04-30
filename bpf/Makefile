CLANG ?= clang
CFLAGS := -g -Wall
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
	| sed 's/arm.*/arm/' \
	| sed 's/aarch64/arm64/' \
	| sed 's/ppc64le/powerpc/' \
	| sed 's/mips.*/mips/' \
	| sed 's/riscv64/riscv/' \
	| sed 's/loongarch64/loongarch/')

APPS = minimal

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
	"$(1)"						\
	"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
	"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
minimal.bpf.o : minimal.bpf.c
	$(call msg,BPF,$@)
	$(CLANG) -O2 -target bpf -c minimal.bpf.c

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS).bpf.o
