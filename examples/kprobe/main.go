// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -target $TARGET -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}

	if err := loadBpfObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("error: %+v\n", ve)
		}

		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.SecurityFileOpen,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	// wait for ctrl-c

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}
