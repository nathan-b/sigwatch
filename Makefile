CFLAGS := -g -Wall -Werror
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
OUTPUT := build
INCLUDES := -I. -I$(OUTPUT)

LIBS := -lbpf -lelf -lz

# Binaries and libraries
BPFTOOL ?= bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

# We need to pull in clang's default includes for bpf builds
# to get some definitions used by the code
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Build everything
all: $(OUTPUT)/probe_read

clean:
	-rm $(OUTPUT)/probe_read
	-rm $(OUTPUT)/*.o
	-rm $(OUTPUT)/vmlinux.h
	-rm $(OUTPUT)/probe.skel.h

build:
	mkdir build

# Build the eBPF probe
$(OUTPUT)/probe.o: probe.c probe.h $(OUTPUT)/vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c probe.c -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

## libbpf magic and shenanigans below here

# Consolidated Linux header file for BTF / CO-RE
$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# BPF skeletons
$(OUTPUT)/probe.skel.h: $(OUTPUT)/probe.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

## End libbpf shenanigans

# Build the userspace application
$(OUTPUT)/userspace.o: userspace.c probe.h $(OUTPUT)/probe.skel.h | $(OUTPUT)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(OUTPUT)/probe_read: $(OUTPUT)/userspace.o | $(OUTPUT)
	$(CLANG) $(CFLAGS) $^ $(LIBS) -o $@

# Preserve build products
.SECONDARY:

# Delete failed targets
.DELETE_ON_ERROR:
