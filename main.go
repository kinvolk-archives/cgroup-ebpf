// Copyright 2017 Kinvolk GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		fmt.Fprintf(os.Stderr, "Usage: %s out/ebpf.o cgroup-path\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	b := elf.NewModule(fileName)
	if b == nil {
		fmt.Fprintf(os.Stderr, "System doesn't support BPF\n")
		os.Exit(1)
	}

	err := b.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	for cgProg := range b.IterCgroupProgram() {
		if err := elf.AttachCgroupProgram(cgProg, os.Args[2], elf.EgressType); err != nil {
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
