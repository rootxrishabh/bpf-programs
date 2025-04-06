#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/limits.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EPERM 13

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[PATH_MAX]);
} tmp_path_map SEC(".maps");

SEC("lsm/path_symlink")
int BPF_PROG(protect_binary_symlink, const struct path *dir, struct dentry *dentry, const char *old_name) {
    u32 key = 0;
    char *buf = bpf_map_lookup_elem(&tmp_path_map, &key);
    if (!buf)
        return 0;

    bpf_probe_read_str(buf, PATH_MAX, old_name);

    // Match target path
    if (__builtin_memcmp(buf, "/usr/bin/cat", 13) == 0) {
        bpf_printk("Blocked symlink to /usr/bin/cat\n");
        return -EPERM;
    }

    return 0;
}
