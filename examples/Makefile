CWD=../_build/default/examples

all: build

bootstrap_c: build
	sudo $(CWD)/bootstrap_c.exe

bootstrap: build
	sudo $(CWD)/bootstrap.exe

build:
	dune build
