all: $(target)

go_executables = \
	helloworld

exec_target = \
	$(go_executables)

manifests = \
	$(addsuffix .manifest,$(executables)) \
	manifests

level = ../
include ../Makefile

%: %.go
	go build $^
