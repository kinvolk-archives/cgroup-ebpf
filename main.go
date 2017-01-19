package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

/*
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <strings.h>
#include <unistd.h>

struct bpf_attr_attach {
	__u32		target_fd;
	__u32		attach_bpf_fd;
	__u32		attach_type;
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	__MAX_BPF_ATTACH_TYPE
};

int bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type)
{
	struct bpf_attr_attach attr;

	bzero(&attr, sizeof(attr));
	attr.target_fd	   = target_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type   = type;

	// BPF_PROG_ATTACH = 8
	return syscall(__NR_bpf, 8, &attr, sizeof(attr));
}
*/
import "C"

func attachProgram(b *elf.Module, cgroupPath string) error {
	f, err := os.Open(cgroupPath)
	if err != nil {
		return fmt.Errorf("error opening cgroup %q: %v", cgroupPath, err)
	}

	// FIXME: confusing name
	for cg := range b.IterCgroup() {
		progFd := C.int(cg.Fd)
		cgroupFd := C.int(f.Fd())
		ret, err := C.bpf_prog_attach(progFd, cgroupFd, C.BPF_CGROUP_INET_EGRESS)
		if ret < 0 {
			return fmt.Errorf("failed to attach prog to cgroup %q: %v\n", cgroupPath, err)
		}
	}

	return nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s .../ebpf.o cgroup-path\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	b := elf.NewModule(fileName)
	if b == nil {
		fmt.Fprintf(os.Stderr, "System doesn't support BPF\n")
		os.Exit(1)
	}

	err := b.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if err := attachProgram(b, os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	zero := 0
	packets_key := zero
	bytes_key := 1
	mp := b.Map("count")

	if err := b.UpdateElement(mp, unsafe.Pointer(&packets_key), unsafe.Pointer(&zero), 0); err != nil {
		fmt.Fprintf(os.Stderr, "error updating map: %v\n", err)
		os.Exit(1)
	}

	if err := b.UpdateElement(mp, unsafe.Pointer(&bytes_key), unsafe.Pointer(&zero), 0); err != nil {
		fmt.Fprintf(os.Stderr, "error updating map: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Ready.")

	var packets, bytes uint64
	for {
		if err := b.LookupElement(mp, unsafe.Pointer(&packets_key), unsafe.Pointer(&packets)); err != nil {
			fmt.Fprintf(os.Stderr, "error looking up in map: %v\n", err)
			os.Exit(1)
		}

		if err := b.LookupElement(mp, unsafe.Pointer(&bytes_key), unsafe.Pointer(&bytes)); err != nil {
			fmt.Fprintf(os.Stderr, "error looking up in map: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("cgroup received", packets, "packets and", bytes, "bytes")

		time.Sleep(1000 * time.Millisecond)
	}
}
