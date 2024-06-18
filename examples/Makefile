CWD=../_build/default/examples

all: vmlinux build

build:
	dune build

vmlinux:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

minimal: all
	sudo $(CWD)/minimal.exe

kprobe: all
	sudo $(CWD)/kprobe.exe

bootstrap: all
	sudo $(CWD)/bootstrap.exe

bootstrap_c: all
	sudo $(CWD)/bootstrap_c.exe

clean:
	dune clean
	rm vmlinux.h
