DEST_DIR=out
LINUX_HEADERS="/usr/lib/modules/$(shell uname -r)/build"

build:
	mkdir -p out
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
			-O2 -emit-llvm -c bpf/cgroup-tracer-bpf.c \
			$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
			-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/ebpf.o"
	go build
