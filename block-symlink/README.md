# 🔒 protect-symlink-lsm-bpf

This project demonstrates a minimal **LSM (Linux Security Module)** eBPF program written in C and Go that **blocks symlink creation targeting `/usr/bin/cat`**. It uses the **Cilium eBPF Go library** to load and attach the LSM BPF program at runtime.

---

## 🧠 What It Does

Whenever a process tries to create a **symbolic link**, this eBPF program intercepts the action using the `path_symlink` LSM hook.

If the target of the symlink is `/usr/bin/cat`, the program blocks the creation by returning `-EPERM` and logs a message using `bpf_printk`.

This is useful as a lightweight way to enforce Mandatory Access Control (MAC) policies in real-time using eBPF.

---

## Instructions

### In the BPF directory run - 

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

```
make
```

### In the main dir run - 

```
sudo go run main.go
```
