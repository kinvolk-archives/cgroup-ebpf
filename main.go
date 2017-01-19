package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

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

	for cgProg := range b.IterCgroupProgram() {
		if err := b.AttachProgram(cgProg, os.Args[2], elf.EgressType); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
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
