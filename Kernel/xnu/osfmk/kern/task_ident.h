/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
 * NOTICE: Adapted and modified from Apple XNU (xnu-8020.140.41) for
 * ravynOS Darwin 19.6 compatibility (2026-10-24 to 2026-11-15).
 * Included in support of clause 2.2(b) of the Apple Public Source
 * License, Version 2.0.
 */


#ifndef _KERN_TASK_IDENT_H
#define _KERN_TASK_IDENT_H
#include <kern/kern_types.h>
#include <mach/mach_types.h>
#include <mach/task_info.h>
__BEGIN_DECLS
typedef struct task_id_token *task_id_token_t;
#define TASK_ID_TOKEN_NULL ((task_id_token_t)0)
kern_return_t task_id_token_port_name_to_task(mach_port_name_t, task_t *);
void task_id_token_release(task_id_token_t);
ipc_port_t convert_task_id_token_to_port(task_id_token_t);
task_id_token_t convert_port_to_task_id_token(ipc_port_t);
void task_id_token_notify(mach_msg_header_t *);
kern_return_t task_create_identity_token(task_t, task_id_token_t *);
kern_return_t task_identity_token_get_task_port(task_id_token_t, task_flavor_t, mach_port_t *);
__END_DECLS
#endif
