/*
 * Copyright (c) 2026 ravynOS Project. All rights reserved.
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
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * NOTICE: Created for the ravynOS macOS bring-up project on 2026-11-15
 * in support of clause 2.2(b) of the Apple Public Source License, Version 2.0.
 */

#ifndef _BSD_VM_SHARED_REGION_PROT_H_
#define _BSD_VM_SHARED_REGION_PROT_H_

#ifndef _SHARED_REGION_PROT_HOST_TEST
#include <mach/vm_prot.h>
#include <mach/shared_region.h>
#include <sys/errno.h>
#endif

static inline int
shared_region_validate_mapping_protections(
	vm_prot_t init_prot,
	vm_prot_t max_prot,
	vm_prot_t policy_maxprot)
{
	const vm_prot_t extra_protections =
	    VM_PROT_COW | VM_PROT_ZF | VM_PROT_SLIDE | VM_PROT_NOAUTH;
	vm_prot_t limit = (policy_maxprot & VM_PROT_ALL);

	if ((max_prot & ~(VM_PROT_ALL | extra_protections)) != 0 ||
	    (init_prot & ~(VM_PROT_ALL | extra_protections)) != 0) {
		return EINVAL;
	}
	if (((max_prot & VM_PROT_ALL) & ~limit) != 0 ||
	    ((init_prot & VM_PROT_ALL) & ~limit) != 0) {
		return EPERM;
	}
	return 0;
}

#endif /* _BSD_VM_SHARED_REGION_PROT_H_ */
