// Copyright 2019-2021 The Inspektor Gadget authors
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
// limitations under the License

package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang IterTCPv4 ./bpf/iter_tcp4.c -- -I../headers

func increaseRlimit() error {
	limit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit)
}

func main() {
	if err := increaseRlimit(); err != nil {
		log.Fatalf("Failed to increase memlock limit: %s", err)
	}

	objs := IterTCPv4Objects{}
	if err := LoadIterTCPv4Objects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTcp4,
	})
	if err != nil {
		log.Fatalf("Failed to attach BPF iterator: %s", err)
	}

	file, err := it.Open()
	if err != nil {
		log.Fatalf("Failed to open BPF iterator: %s", err)
	}
	defer file.Close()

	contents, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Failed to read BPF iterator: %s", err)
	}

	fmt.Printf("%s", string(contents))
}
