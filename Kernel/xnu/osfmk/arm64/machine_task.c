/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * NOTICE: This file was modified for the ravynOS macOS bring-up project
 * (2026-10-18 to 2026-11-15). Included in support of clause 2.2(b) of the
 * Apple Public Source License, Version 2.0.
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <kern/task.h>
#include <kern/thread.h>
#include <arm/misc_protos.h>

extern zone_t ads_zone;

kern_return_t
machine_task_set_state(
	task_t task,
	int flavor,
	thread_state_t state,
	mach_msg_type_number_t state_count)
{
	switch (flavor) {
	case ARM_DEBUG_STATE:
	{
		arm_legacy_debug_state_t *tstate = (arm_legacy_debug_state_t *) state;
		if (task_has_64Bit_data(task) ||
		    (state_count != ARM_LEGACY_DEBUG_STATE_COUNT) ||
		    (!debug_legacy_state_is_valid(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc(ads_zone);
			if (task->task_debug == NULL) {
				return KERN_FAILURE;
			}
		}

		copy_legacy_debug_state(tstate, (arm_legacy_debug_state_t *) task->task_debug, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE32:
	{
		arm_debug_state32_t *tstate = (arm_debug_state32_t *) state;
		if (task_has_64Bit_data(task) ||
		    (state_count != ARM_DEBUG_STATE32_COUNT) ||
		    (!debug_state_is_valid32(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc(ads_zone);
			if (task->task_debug == NULL) {
				return KERN_FAILURE;
			}
		}

		copy_debug_state32(tstate, (arm_debug_state32_t *) task->task_debug, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE64:
	{
		arm_debug_state64_t *tstate = (arm_debug_state64_t *) state;

		if ((!task_has_64Bit_data(task)) ||
		    (state_count != ARM_DEBUG_STATE64_COUNT) ||
		    (!debug_state_is_valid64(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc(ads_zone);
			if (task->task_debug == NULL) {
				return KERN_FAILURE;
			}
		}

		copy_debug_state64(tstate, (arm_debug_state64_t *) task->task_debug, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */

		return KERN_SUCCESS;
	}
	case THREAD_STATE_NONE:         /* Using this flavor to clear task_debug */
	{
		if (task->task_debug != NULL) {
			zfree(ads_zone, task->task_debug);
			task->task_debug = NULL;

			return KERN_SUCCESS;
		}
		return KERN_FAILURE;
	}
	default:
	{
		return KERN_INVALID_ARGUMENT;
	}
	}

	return KERN_FAILURE;
}

kern_return_t
machine_task_get_state(task_t task,
    int flavor,
    thread_state_t state,
    mach_msg_type_number_t *state_count)
{
	switch (flavor) {
	case ARM_DEBUG_STATE:
	{
		arm_legacy_debug_state_t *tstate = (arm_legacy_debug_state_t *) state;

		if (task_has_64Bit_data(task) || (*state_count != ARM_LEGACY_DEBUG_STATE_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_legacy_debug_state((arm_legacy_debug_state_t*) task->task_debug, tstate, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */
		}

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE32:
	{
		arm_debug_state32_t *tstate = (arm_debug_state32_t *) state;

		if (task_has_64Bit_data(task) || (*state_count != ARM_DEBUG_STATE32_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_debug_state32((arm_debug_state32_t*) task->task_debug, tstate, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */
		}

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE64:
	{
		arm_debug_state64_t *tstate = (arm_debug_state64_t *) state;

		if ((!task_has_64Bit_data(task)) || (*state_count != ARM_DEBUG_STATE64_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_debug_state64((arm_debug_state64_t*) task->task_debug, tstate, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */
		}

		return KERN_SUCCESS;
	}
	default:
	{
		return KERN_INVALID_ARGUMENT;
	}
	}
	return KERN_FAILURE;
}

void
machine_task_terminate(task_t task)
{
	if (task) {
		void *task_debug;

		task_debug = task->task_debug;
		if (task_debug != NULL) {
			task->task_debug = NULL;
			zfree(ads_zone, task_debug);
		}
	}
}


kern_return_t
machine_thread_inherit_taskwide(
	thread_t thread,
	task_t parent_task)
{
	if (parent_task->task_debug) {
		int flavor;
		mach_msg_type_number_t count;

		flavor = task_has_64Bit_data(parent_task) ? ARM_DEBUG_STATE64 : ARM_DEBUG_STATE32;
		count = task_has_64Bit_data(parent_task) ? ARM_DEBUG_STATE64_COUNT : ARM_DEBUG_STATE32_COUNT;

		return machine_thread_set_state(thread, flavor, parent_task->task_debug, count);
	}

	return KERN_SUCCESS;
}


void
machine_task_init(__unused task_t new_task,
    __unused task_t parent_task,
    __unused boolean_t memory_inherit)
{
#if defined(ARM64_BOARD_CONFIG_BCM2837)
    extern void ravyn_user_pauth_exec(task_t);
    if (memory_inherit && parent_task != TASK_NULL)
        memcpy(new_task->ravyn_user_pauth_keys, parent_task->ravyn_user_pauth_keys,
            sizeof(new_task->ravyn_user_pauth_keys));
    else
        ravyn_user_pauth_exec(new_task);
#endif
}

#if defined(ARM64_BOARD_CONFIG_BCM2837)
#include <pexpert/pexpert.h>
extern void read_random(void *, unsigned int);

boolean_t
ravyn_arm64e_reference_enabled(void)
{
    int optin = 0;
    uint64_t isar1;
    if (!PE_parse_boot_argn("ravyn_arm64e", &optin, sizeof(optin)) || optin != 1)
        return FALSE;
    __asm__ volatile("mrs %0, ID_AA64ISAR1_EL1" : "=r"(isar1));
    return (isar1 & 0xff0) != 0 && (isar1 & 0xff000000) != 0;
}

/* arm64e uses process-independent IA/DA keys for shared-cache pointers.
 * IB/DB/GA remain task-owned and are inherited across fork, renewed on exec. */
static uint64_t ravyn_shared_pauth_keys[4];
static int ravyn_shared_pauth_ready;
static void ravyn_shared_pauth_initialize(void)
{
    int expected=0;
    if (__atomic_compare_exchange_n(&ravyn_shared_pauth_ready,&expected,1,FALSE,
            __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        read_random(ravyn_shared_pauth_keys,sizeof(ravyn_shared_pauth_keys));
        __atomic_store_n(&ravyn_shared_pauth_ready,2,__ATOMIC_RELEASE);
    } else {
        while (__atomic_load_n(&ravyn_shared_pauth_ready,__ATOMIC_ACQUIRE)!=2)
            __asm__ volatile("yield");
    }
}

boolean_t
ravyn_sign_shared_cache_ptr(uint64_t value, unsigned key, uint64_t modifier,
    uint64_t *signed_value)
{
    if (!ravyn_arm64e_reference_enabled() || (key!=0 && key!=2))
        return FALSE;
    ravyn_shared_pauth_initialize();
    boolean_t interrupts=ml_set_interrupts_enabled(FALSE);
    uint64_t oldlo,oldhi,oldctl,ctl;
    __asm__ volatile("mrs %0, SCTLR_EL1" : "=r"(oldctl));
    ctl=oldctl | (1ULL<<31) | (1ULL<<27);
    __asm__ volatile("msr SCTLR_EL1, %0\n\tisb" :: "r"(ctl) : "memory");
    if (key==0) {
        __asm__ volatile("mrs %0, S3_0_C2_C1_0\n\tmrs %1, S3_0_C2_C1_1" : "=r"(oldlo),"=r"(oldhi));
        __asm__ volatile("msr S3_0_C2_C1_0, %0\n\tmsr S3_0_C2_C1_1, %1" :: "r"(ravyn_shared_pauth_keys[0]),"r"(ravyn_shared_pauth_keys[1]) : "memory");
        __asm__ volatile(".arch_extension pauth\n\tpacia %0, %1" : "+r"(value) : "r"(modifier));
        __asm__ volatile("msr S3_0_C2_C1_0, %0\n\tmsr S3_0_C2_C1_1, %1" :: "r"(oldlo),"r"(oldhi) : "memory");
    } else {
        __asm__ volatile("mrs %0, S3_0_C2_C2_0\n\tmrs %1, S3_0_C2_C2_1" : "=r"(oldlo),"=r"(oldhi));
        __asm__ volatile("msr S3_0_C2_C2_0, %0\n\tmsr S3_0_C2_C2_1, %1" :: "r"(ravyn_shared_pauth_keys[2]),"r"(ravyn_shared_pauth_keys[3]) : "memory");
        __asm__ volatile(".arch_extension pauth\n\tpacda %0, %1" : "+r"(value) : "r"(modifier));
        __asm__ volatile("msr S3_0_C2_C2_0, %0\n\tmsr S3_0_C2_C2_1, %1" :: "r"(oldlo),"r"(oldhi) : "memory");
    }
    __asm__ volatile("msr SCTLR_EL1, %0\n\tisb" :: "r"(oldctl) : "memory");
    ml_set_interrupts_enabled(interrupts);
    *signed_value=value;
    return TRUE;
}

extern boolean_t ravyn_task_uses_user_jop(task_t task);

/* Authenticate the ABI's process-independent function-pointer arguments.
 * Preserve authentication failure poison; never strip an unverified pointer. */
uint64_t
ravyn_auth_user_function_ptr(task_t task, uint64_t value)
{
    if (!value || !ravyn_task_uses_user_jop(task))
        return value;
    boolean_t interrupts = ml_set_interrupts_enabled(FALSE);
    uint64_t oldlo, oldhi, oldctl;
    __asm__ volatile("mrs %0, SCTLR_EL1" : "=r"(oldctl));
    __asm__ volatile("mrs %0, S3_0_C2_C1_0\n\tmrs %1, S3_0_C2_C1_1"
        : "=r"(oldlo), "=r"(oldhi));
    __asm__ volatile("msr S3_0_C2_C1_0, %0\n\tmsr S3_0_C2_C1_1, %1"
        :: "r"(task->ravyn_user_pauth_keys[0]),
           "r"(task->ravyn_user_pauth_keys[1]) : "memory");
    uint64_t control = oldctl | (1ULL << 31);
    __asm__ volatile("msr SCTLR_EL1, %0\n\tisb" :: "r"(control) : "memory");
    __asm__ volatile(".arch_extension pauth\n\tautiza %0" : "+r"(value));
    __asm__ volatile("msr S3_0_C2_C1_0, %0\n\tmsr S3_0_C2_C1_1, %1"
        :: "r"(oldlo), "r"(oldhi) : "memory");
    __asm__ volatile("msr SCTLR_EL1, %0\n\tisb" :: "r"(oldctl) : "memory");
    ml_set_interrupts_enabled(interrupts);
    return value;
}

void
ravyn_user_pauth_exec(task_t task)
{
    if (ravyn_arm64e_reference_enabled()) {
        ravyn_shared_pauth_initialize();
        read_random(task->ravyn_user_pauth_keys, sizeof(task->ravyn_user_pauth_keys));
        memcpy(task->ravyn_user_pauth_keys,ravyn_shared_pauth_keys,2*sizeof(uint64_t));
        memcpy(task->ravyn_user_pauth_keys+4,ravyn_shared_pauth_keys+2,2*sizeof(uint64_t));
    }
}

#define RAVYN_PAUTH_CONTROL_BITS ((1ULL << 31) | (1ULL << 30) | (1ULL << 27) | (1ULL << 13))

static uint64_t ravyn_kernel_pauth_keys[10];
static boolean_t ravyn_kernel_pauth_ready;

static void
ravyn_pauth_install(const uint64_t *k, boolean_t enable_jop)
{
#define KEY(reg, index) __asm__ volatile("msr " reg ", %0" :: "r"(k[index]) : "memory")
    KEY("S3_0_C2_C1_0",0); KEY("S3_0_C2_C1_1",1);
    KEY("S3_0_C2_C1_2",2); KEY("S3_0_C2_C1_3",3);
    KEY("S3_0_C2_C2_0",4); KEY("S3_0_C2_C2_1",5);
    KEY("S3_0_C2_C2_2",6); KEY("S3_0_C2_C2_3",7);
    KEY("S3_0_C2_C3_0",8); KEY("S3_0_C2_C3_1",9);
#undef KEY
    uint64_t control;
    __asm__ volatile("mrs %0, SCTLR_EL1" : "=r"(control));
    control |= RAVYN_PAUTH_CONTROL_BITS;
    if (!enable_jop)
        control &= ~((1ULL << 31) | (1ULL << 27) | (1ULL << 13));
    __asm__ volatile("msr SCTLR_EL1, %0\n\tisb" :: "r"(control) : "memory");
}

/* Install boot-local keys before static MAC policies or user tasks can run. */
void
ravyn_kernel_pauth_init(void)
{
    int enabled = 0;
    if (!PE_parse_boot_argn("rvn_kpac", &enabled, sizeof(enabled)) ||
        enabled != 1 || !ravyn_arm64e_reference_enabled()) {
        return;
    }

    read_random(ravyn_kernel_pauth_keys, sizeof(ravyn_kernel_pauth_keys));
    boolean_t interrupts = ml_set_interrupts_enabled(FALSE);
    ravyn_pauth_install(ravyn_kernel_pauth_keys, TRUE);
    __atomic_store_n(&ravyn_kernel_pauth_ready, TRUE, __ATOMIC_RELEASE);
    ml_set_interrupts_enabled(interrupts);
}

/* EL0 state has been saved. Nested EL1 exceptions retain the kernel keys. */
void
ravyn_kernel_pauth_enter(void)
{
    if (__atomic_load_n(&ravyn_kernel_pauth_ready, __ATOMIC_ACQUIRE)) {
        ravyn_pauth_install(ravyn_kernel_pauth_keys, TRUE);
    }
}

/* Called with interrupts masked just before restoring EL0 registers. */
void
ravyn_user_pauth_restore(thread_t thread)
{
    if (ravyn_arm64e_reference_enabled()) {
        task_t task = thread->task;
        ravyn_pauth_install(task->ravyn_user_pauth_keys, ravyn_task_uses_user_jop(task));
    }
}

#if DEVELOPMENT || DEBUG
int
ravyn_kernel_pauth_status(void)
{
    if (!__atomic_load_n(&ravyn_kernel_pauth_ready, __ATOMIC_ACQUIRE)) {
        return -1;
    }

    uint64_t current, mismatch = 0;
#define CHECK_KEY(reg, index) do { \
    __asm__ volatile("mrs %0, " reg : "=r"(current)); \
    mismatch |= current ^ ravyn_kernel_pauth_keys[index]; \
} while (0)
    CHECK_KEY("S3_0_C2_C1_0", 0); CHECK_KEY("S3_0_C2_C1_1", 1);
    CHECK_KEY("S3_0_C2_C1_2", 2); CHECK_KEY("S3_0_C2_C1_3", 3);
    CHECK_KEY("S3_0_C2_C2_0", 4); CHECK_KEY("S3_0_C2_C2_1", 5);
    CHECK_KEY("S3_0_C2_C2_2", 6); CHECK_KEY("S3_0_C2_C2_3", 7);
    CHECK_KEY("S3_0_C2_C3_0", 8); CHECK_KEY("S3_0_C2_C3_1", 9);
#undef CHECK_KEY

    __asm__ volatile("mrs %0, SCTLR_EL1" : "=r"(current));
    int correct = (mismatch == 0) && (current & RAVYN_PAUTH_CONTROL_BITS) == RAVYN_PAUTH_CONTROL_BITS;
    const uint64_t *user = current_task()->ravyn_user_pauth_keys;
    for (unsigned i = 0; i < sizeof(ravyn_kernel_pauth_keys) / sizeof(*user); i += 2) {
        correct &= (ravyn_kernel_pauth_keys[i] != user[i]) ||
            (ravyn_kernel_pauth_keys[i + 1] != user[i + 1]);
    }

    return correct;
}

#endif

#endif
