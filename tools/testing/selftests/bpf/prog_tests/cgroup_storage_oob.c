// SPDX-License-Identifier: GPL-2.0
/* Test for cgroup storage OOB read when value_size is not 8-byte aligned.
 *
 * This test reproduces a bug where copy_map_value_long() rounds up the copy
 * size to 8 bytes, but cgroup storage only allocates exactly value_size bytes,
 * leading to an out-of-bounds read when copying from cgroup storage to other
 * map types with the same unaligned value_size.
 *
 * The bug occurs when:
 * 1. A CGROUP_STORAGE map is created with value_size not aligned to 8 bytes
 * 2. A PERCPU_HASH map is created with the same value_size
 * 3. bpf_map_update_elem() is called to update the PERCPU_HASH map
 * 4. copy_map_value_long() rounds up the size and reads beyond the cgroup
 *    storage buffer
 */

#include <unistd.h>
#include <sys/socket.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "test_cgroup_storage_oob.skel.h"

void test_cgroup_storage_oob(void)
{
	struct test_cgroup_storage_oob *skel;
	int cgroup_fd = -1;
	int err;

	/* Setup cgroup */
	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	cgroup_fd = create_and_get_cgroup("/test_cgroup_storage_oob");
	if (!ASSERT_GE(cgroup_fd, 0, "create_and_get_cgroup"))
		goto cleanup_cgroup;

	/* Load and attach BPF program */
	skel = test_cgroup_storage_oob__open_and_load();
	if (!ASSERT_OK_PTR(skel, "test_cgroup_storage_oob__open_and_load"))
		goto cleanup_cgroup;

	err = test_cgroup_storage_oob__attach(skel);
	if (!ASSERT_OK(err, "test_cgroup_storage_oob__attach"))
		goto cleanup_skel; 

	skel->links.trigger_oob = bpf_program__attach_cgroup(skel->progs.trigger_oob,
							      cgroup_fd);
	if (!ASSERT_OK_PTR(skel->links.trigger_oob, "attach_cgroup"))
		goto cleanup_skel;

	/* Join the cgroup so that socket creation will trigger the BPF program */
	if (test__join_cgroup("/test_cgroup_storage_oob") == 0) {
		/* Create a socket to trigger cgroup/sock_create hook.
		 * This will execute our BPF program and trigger the OOB read
		 * if the bug is present (before the fix).
		 */
		int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock_fd >= 0)
			close(sock_fd);
	}

	/* If we reach here without a kernel panic or KASAN report,
	 * the test passes (the fix is working).
	 */

cleanup_skel:
	test_cgroup_storage_oob__destroy(skel);
cleanup_cgroup:
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	cleanup_cgroup_environment();
}
