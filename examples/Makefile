CWD=../_build/default/examples

all: build

minimal: build
	sudo $(CWD)/minimal.exe

bootstrap: build
	sudo $(CWD)/bootstrap.exe

bootstrap_c: build
	sudo $(CWD)/bootstrap_c.exe

build:
	dune build
