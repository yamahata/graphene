#GOROOT ?= $(shell go env GOROOT)
GOROOT ?= /home/yamahata/graphene/devel/go/go
GO = $(GOROOT)/bin/go

all: $(target)

go_executables = \
	channel \
	exec \
	execing-process \
	goroutines-list \
	goroutines-stress \
	goroutine \
	goroutines \
	helloworld \
	many-goroutines \
	signal \
	sleep \
	sleep-go

exec_target = \
	$(go_executables)

manifests = \
	$(addsuffix .manifest,$(executables)) \
	manifests

level = ../
include ../Makefile

%: %.go
	$(GO) build $^
