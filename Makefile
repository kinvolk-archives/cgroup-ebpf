DEST_DIR=out
LINUX_HEADERS=$(shell pacman -Q linux-headers | awk '{print "/usr/lib/modules/"$$2"-ARCH/build"}')

build:
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
			-O2 -emit-llvm -c cgroup-tracer-bpf.c \
			$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
			-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/ebpf.o"
