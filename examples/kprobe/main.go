// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"C"
)
import (
	"fmt"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-10 KProbeExample ./bpf/kprobe_example.c -- -I../headers

const mapKey uint32 = 0

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	spec, err := LoadKProbeExample()
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	// set global variable to avoid using map
	constants := map[string]interface{}{}
	constants["map_enabled"] = C.int(0)

	if err := spec.RewriteConstants(constants); err != nil {
		log.Fatalf("rewriting constants: %v", err)
	}

	// Create dummy eBPF map to replace the one we aren't going to use.
	dummypec := &ebpf.MapSpec{
		Name:       "dummy",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	dummy, err := ebpf.NewMapWithOptions(dummypec, ebpf.MapOptions{})
	if err != nil {
		log.Fatalf("error creating dummy map: %s", err)
	}

	// replace map we won't use by dummy map
	maps := map[string]*ebpf.Map{}
	maps["kprobe_map"] = dummy

	if err := spec.RewriteMaps(maps); err != nil {
		log.Fatalf("rewriting maps: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.

	for name, _ := range coll.Programs {
		fmt.Printf("name is %s\n", name)
	}

	kp, err := link.Kprobe(fn, coll.Programs["kprobe_execve"] /*objs.KprobeExecve*/)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	//ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	for {
		select {
		//case <-ticker.C:
		//	var value uint64
		//	if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
		//		log.Fatalf("reading map: %v", err)
		//	}
		//	log.Printf("%s called %d times\n", fn, value)
		case <-stopper:
			return
		}
	}
}
