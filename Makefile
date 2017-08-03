DEST_DIR=out

build:
	mkdir -p out
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
	-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
			-fno-stack-protector \
			-O2 -emit-llvm -c bpf/cgroup-tracer-bpf.c \
			-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/ebpf.o"
	go build
