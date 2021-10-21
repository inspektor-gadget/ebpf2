#include "common.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 1,
};

struct container {
  char kubernetes_namespaces[64];
  char kubernetes_pod[64];
  char kubernetes_container[64];
};

struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __type(key, u64);
       __type(value, struct container);
       __uint(max_entries, 1);
} containers SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve() {
    u32 key = 0;
    u64 initval = 1, *valp;

    u64 k1 = 0;
    struct container v1 = {};
    v1.kubernetes_namespaces[0] = 'X';
    bpf_map_update_elem(&containers, &k1, &v1, BPF_ANY);

    valp = bpf_map_lookup_elem(&kprobe_map, &key);
    if (!valp) {
        bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);

    return 0;
}
