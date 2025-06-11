# eBPF Signal Blocker

Linux Security Module (LSM) based eBPF program that can selectively block signals to specified processes.

## Prerequisites

 - Linux kernel 5.7+ with LSM eBPF support enabled
 - Root privileges (required for LSM programs)
 - Go 1.19+
 - Clang/LLVM
 - libbpf
 - Kernel BTF

```
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential
```

## Generate vmlinux.h

run ``` bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h``` in pkg dir.

## Usage

```
go build
./block-signals
```