all: $(target)

go_executables = \
	exec \
	execing-process \
	goroutines-list \
	goroutines-stress \
	goroutines \
	helloworld \
	many-goroutines \
	signal

exec_target = \
	$(go_executables)

manifests = \
	$(addsuffix .manifest,$(executables)) \
	manifests

level = ../
include ../Makefile

%: %.go
	go build $^
