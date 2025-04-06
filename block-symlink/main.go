package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ebpfProgram struct {
	Prog *ebpf.Program `ebpf:"protect_binary_symlink"`
}

func RunBPF() error {
	bpf_prog := &ebpfProgram{}

	if err := bpf_prog.loadEBPFProgram(); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	lsm := bpf_prog.attachLSMHook()

	defer lsm.Close()
	defer bpf_prog.Prog.Close()

	log.Println("BPF LSM program attached successfully! Press Ctrl+C to exit...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Exiting. Cleaning up...")

	return nil
}

func (e *ebpfProgram) loadEBPFProgram() error {
	spec, err := ebpf.LoadCollectionSpec("protect_symlink.bpf.o")
	if err != nil {
		return fmt.Errorf("error loading ebpf spec: %w", err)
	}

	if err := spec.LoadAndAssign(e, nil); err != nil {
		return fmt.Errorf("error loading ebpf program: %w", err)
	}

	return nil
}

func (e *ebpfProgram) attachLSMHook() link.Link {
	lsm, err := link.AttachLSM(link.LSMOptions{Program: e.Prog})
	if err != nil {
		fmt.Errorf("error attaching LSM hook: %w", err)
	}
	return lsm
}

func main() {
	if err := RunBPF(); err != nil {
		log.Fatalf("error occured: %v", err)
	}

}
