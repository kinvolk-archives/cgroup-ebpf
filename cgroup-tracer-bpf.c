#include <linux/kconfig.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/count") count_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 1024,
};

int count_packets(struct pt_regs *ctx)
{
	int packets_key = 0;
	u64 *packets = 0;

	packets = bpf_map_lookup_elem(&count_map, &packets_key);
	if (packets == NULL)
		return 0;

	*packets += 1;

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
