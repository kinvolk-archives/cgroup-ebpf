/* Copyright 2017 Kinvolk GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/kconfig.h>
#include <bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/bytes_per_ip") bytes_per_ip_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(__u64),
	.max_entries = 16,
};

SEC("cgroup/skb")
int count_bytes(struct __sk_buff *skb)
{
	u32 daddr = 0;
	u32 *daddrp = 0;
	u64 *bytes = NULL;
	u64 new_bytes = skb->len;
	u8 proto = 0;

	bpf_skb_load_bytes(skb, offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));
	bpf_skb_load_bytes(skb, offsetof(struct iphdr, protocol), &proto, sizeof(proto));

	daddrp = bpf_map_lookup_elem(&bytes_per_ip_map, &daddr);
	if (daddrp == NULL)
		bpf_map_update_elem(&bytes_per_ip_map, &daddr, &new_bytes, BPF_ANY);
	else
		*daddrp += new_bytes;

	// don't drop
	return 1;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
