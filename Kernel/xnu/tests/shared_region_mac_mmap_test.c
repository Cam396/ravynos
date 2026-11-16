/*
 * Regression test for shared_region_map_and_slide_2_np() MAC policy maxprot
 * enforcement (mac_file_check_mmap lowering maxprot) and header validation.
 * MIT License (original test code in ravynOS lab bring-up).
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define _SHARED_REGION_PROT_HOST_TEST 1
typedef int vm_prot_t;
#define VM_PROT_NONE    ((vm_prot_t)0x00)
#define VM_PROT_READ    ((vm_prot_t)0x01)
#define VM_PROT_WRITE   ((vm_prot_t)0x02)
#define VM_PROT_EXECUTE ((vm_prot_t)0x04)
#define VM_PROT_ALL     (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
#define VM_PROT_COW     ((vm_prot_t)0x08)
#define VM_PROT_ZF      ((vm_prot_t)0x10)
#define VM_PROT_SLIDE   ((vm_prot_t)0x20)
#define VM_PROT_NOAUTH  ((vm_prot_t)0x40)

#include "../bsd/vm/shared_region_prot.h"

struct sim_mapping {
	vm_prot_t sms_init_prot;
	vm_prot_t sms_max_prot;
};

typedef int (*sim_mpo_file_check_mmap_t)(int req_prot, int flags, vm_prot_t *maxprot);

static int
policy_strip_execute(int req_prot, int flags, vm_prot_t *maxprot)
{
	(void)req_prot;
	(void)flags;
	*maxprot &= ~VM_PROT_EXECUTE;
	return 0;
}

static int
policy_strip_write_and_exec(int req_prot, int flags, vm_prot_t *maxprot)
{
	(void)req_prot;
	(void)flags;
	*maxprot &= ~(VM_PROT_WRITE | VM_PROT_EXECUTE);
	return 0;
}

static int
policy_deny_all(int req_prot, int flags, vm_prot_t *maxprot)
{
	(void)req_prot;
	(void)flags;
	(void)maxprot;
	return EPERM;
}

static int
simulate_syscall536_policy_check(
	sim_mpo_file_check_mmap_t policy_cb,
	const struct sim_mapping *mappings,
	size_t count)
{
	vm_prot_t maxprot = VM_PROT_ALL;
	int error = 0;

	if (policy_cb != NULL) {
		error = policy_cb(VM_PROT_ALL, 0x0001 /* MAP_FILE */, &maxprot);
		if (error != 0) {
			return error;
		}
	}
	for (size_t i = 0; i < count; i++) {
		error = shared_region_validate_mapping_protections(
		    mappings[i].sms_init_prot, mappings[i].sms_max_prot, maxprot);
		if (error != 0) {
			return error;
		}
	}
	return 0;
}

int
main(void)
{
	/* 1. Policy lowers maxprot by stripping EXECUTE -> RX initial/max must fail EPERM. */
	struct sim_mapping rx_mappings[] = {
		{ VM_PROT_READ, VM_PROT_READ },
		{ VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE },
	};
	assert(simulate_syscall536_policy_check(policy_strip_execute, rx_mappings, 2) == EPERM);

	/* 2. Even if sms_init_prot is only READ, sms_max_prot with EXECUTE exceeds maxprot -> EPERM. */
	struct sim_mapping max_exec_only[] = {
		{ VM_PROT_READ, VM_PROT_READ | VM_PROT_EXECUTE },
	};
	assert(simulate_syscall536_policy_check(policy_strip_execute, max_exec_only, 1) == EPERM);

	/* 3. Even if sms_max_prot is only READ, sms_init_prot with EXECUTE exceeds maxprot -> EPERM. */
	struct sim_mapping init_exec_only[] = {
		{ VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ },
	};
	assert(simulate_syscall536_policy_check(policy_strip_execute, init_exec_only, 1) == EPERM);

	/* 4. Policy lowers maxprot to READ-only; WRITE (even with COW/SLIDE) in init or max -> EPERM. */
	struct sim_mapping rw_cow[] = {
		{ VM_PROT_READ, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COW },
	};
	assert(simulate_syscall536_policy_check(policy_strip_write_and_exec, rw_cow, 1) == EPERM);

	/* 5. Mappings within reduced maxprot (READ + allowed extra flags) succeed. */
	struct sim_mapping ro_with_flags[] = {
		{ VM_PROT_READ | VM_PROT_SLIDE, VM_PROT_READ | VM_PROT_COW | VM_PROT_SLIDE | VM_PROT_NOAUTH },
		{ VM_PROT_READ | VM_PROT_ZF, VM_PROT_READ | VM_PROT_ZF },
	};
	assert(simulate_syscall536_policy_check(policy_strip_write_and_exec, ro_with_flags, 2) == 0);

	/* 6. Unrecognized protection bits fail with EINVAL. */
	struct sim_mapping bad_bits[] = {
		{ VM_PROT_READ | 0x80, VM_PROT_READ },
	};
	assert(simulate_syscall536_policy_check(NULL, bad_bits, 1) == EINVAL);

	/* 7. Explicit policy denial propagates EPERM. */
	struct sim_mapping r_only[] = {
		{ VM_PROT_READ, VM_PROT_READ },
	};
	assert(simulate_syscall536_policy_check(policy_deny_all, r_only, 1) == EPERM);

	printf("shared_region_mac_mmap_test: all assertions passed\n");
	return 0;
}
