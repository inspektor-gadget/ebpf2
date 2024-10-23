// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf kprobe.c -- -I../headers

const mapKey uint32 = 0

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	type map_test_struct struct {
		a int32
		b int32
		c int8
	}

	expectedVal := int32(42)
	key := map_test_struct{a: 42, b: 42, c: 43}

	m := objs.bpfMaps.TestMap
	err := m.Put(key, expectedVal)
	if err != nil {
		fmt.Printf("error was: %s\n", err)
		return
	}

	// wait for enter
	fmt.Printf("Press enter to stop\n")
	fmt.Scanln()
}
