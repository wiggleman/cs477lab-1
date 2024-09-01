CLANG ?= clang
BPFTOOL ?= bpftool

CFLAGS := -O2 -g --target=bpf -Wno-compare-distinct-pointer-types
INCLUDES := -Iinclude -I. -I../libbpf/src

all: bpfnic.bpf.o bpfnic.skel.h

%.bpf.o: %.bpf.c vmlinux.h
	@$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

bpfnic.skel.h: bpfnic.bpf.o
	@$(BPFTOOL) gen skeleton bpfnic.bpf.o name bpfnic > bpfnic.skel.h

vmlinux.h:
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	@rm -rf *.bpf.o *.skel.h
