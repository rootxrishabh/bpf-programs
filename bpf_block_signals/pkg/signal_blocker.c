#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);    // PID
    __type(value, __u8);
} blocked_pids SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Event structure sent to userspace
struct signal_event {
    __u32 target_pid;
    __u32 source_pid;
    __u32 signal;
    __u32 blocked;
    __u64 timestamp;
};

SEC("lsm/task_kill")
int BPF_PROG(task_kill_hook, struct task_struct *p, struct kernel_siginfo *info, 
             int sig, const struct cred *cred)
{
    __u32 target_pid = BPF_CORE_READ(p, pid);
    __u32 source_pid = bpf_get_current_pid_tgid() >> 32;

    if (target_pid == source_pid)
        return 0;
    
    // Check if target PID is in our blocked list
    __u8 *blocked = bpf_map_lookup_elem(&blocked_pids, &target_pid);
    
    struct signal_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->target_pid = target_pid;
    e->source_pid = source_pid;
    e->signal = sig;
    e->timestamp = bpf_ktime_get_ns();
    
    if (blocked && *blocked == 1) {
        // Block the signal
        e->blocked = 1;
        bpf_ringbuf_submit(e, 0);
        return -EPERM;
    } else {
        // Allow the signal
        e->blocked = 0;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }
}

char LICENSE[] SEC("license") = "GPL";