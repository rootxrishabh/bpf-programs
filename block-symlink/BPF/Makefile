CLANG ?= clang
BPFTOOL ?= bpftool

PROG := protect_symlink
BPF_OBJ := $(PROG).bpf.o

all: $(BPF_OBJ)

%.bpf.o: %.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c $< -o $@

clean:
	rm -f *.o *.skel.h *.bpf.c

.PHONY: all clean
