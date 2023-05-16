//go:build ignore

#include "common.h"

//#include <vmlinux/vmlinux.h>
#include "bpf_helpers.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") heap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = 4096,
	.max_entries = 1,
};



SEC("fentry/security_file_open")
int BPF_PROG(security_file_open, struct file *file, const struct cred *cred)
{
	u32 zero = 0;
	char *p = bpf_map_lookup_elem(&heap, &zero);
	if (!p) {
		return 0;
	}

	bpf_d_path(&file->f_path, p, 4096);
	bpf_printk("current path is %s\n", p);

	return 0;
}
