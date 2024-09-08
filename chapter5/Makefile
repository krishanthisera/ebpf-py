TARGET = hello-buffer-config
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}
USER_C = ${TARGET:=.c}
USER_SKEL = ${TARGET:=.skel.h}

all: $(TARGET) $(BPF_OBJ) find-map
.PHONY: all 

$(TARGET): $(USER_C) $(USER_SKEL) 
	gcc -Wall -o $(TARGET) $(USER_C) -L../libbpf/src -l:libbpf.a -lelf -lz


# The -g flag also adds DWARF debugging information to the output object file, 
#  but that’s not needed by eBPF programs, so you can reduce the size of 
#  the object by running the llvm-strip utility on it
# The -O2 optimization flag (level 2 or higher) is required for Clang to produce 
#  BPF bytecode that will pass the verifier. One example of this being necessary is that, by default, 
#  Clang will output callx <register> to call helper functions, but eBPF doesn’t support calling addresses from registers.
# The argument to a kprobe is a pt_regs structure that holds a copy of the contents of the CPU registers. 
#  Since registers are architecture specific, the pt_regs structure defi‐ nition depends on the architecture you’re running on. 
#  This means that if you want to use these macros, you’ll need to also tell the compiler what the target architecture is. 
#  You can do this by setting -D __TARGET_ARCH_($ARCH) where $ARCH is an architecture name like arm64, amd64, and so on.
%.bpf.o: %.bpf.c vmlinux.h
	clang \
	    -target bpf \
        -D __TARGET_ARCH_$(ARCH) \
	    -Wall \
	    -O2 -g -o $@ -c $<
	llvm-strip -g $@

$(USER_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	- rm $(BPF_OBJ)
	- rm $(TARGET)
	- rm find-map

find-map: find-map.c
	gcc -Wall -o find-map find-map.c -L../libbpf/src -l:libbpf.a -lelf -lz
