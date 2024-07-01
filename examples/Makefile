CWD=../_build/default/examples

build:
	dune build

minimal: build
	sudo $(CWD)/minimal.exe

kprobe: build
	sudo $(CWD)/kprobe.exe

tc: build
	sudo $(CWD)/tc.exe

bootstrap: build
	sudo $(CWD)/bootstrap.exe

bootstrap_c: build
	sudo $(CWD)/bootstrap_c.exe

clean:
	dune clean
	rm vmlinux.h
