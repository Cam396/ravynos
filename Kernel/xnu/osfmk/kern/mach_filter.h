/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you by this License
 * may not be used to create or enable the creation or redistribution of
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent any terms of an Apple operating system software license.
 *
 * The Original Code is provided "AS IS", without warranty of any kind.
 * See the License for the specific language governing rights and limitations.
 * http://www.opensource.apple.com/apsl/
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * NOTICE: This file was modified for the ravynOS macOS bring-up project
 * (2026-10-18 to 2026-11-15). Included in support of clause 2.2(b) of the
 * Apple Public Source License, Version 2.0.
 */

/* ABI adapted from the pinned Darwin 21.6 XNU mach_filter.h. */
#ifndef _KERN_MACH_FILTER_H_
#define _KERN_MACH_FILTER_H_

#include <sys/cdefs.h>
#include <mach/message.h>
#include <mach/port.h>

struct task;

typedef boolean_t (*mach_msg_fetch_filter_policy_cbfunc_t)(
    struct task *task, void *portlabel, mach_msg_id_t msgid, mach_msg_filter_id *fpid);
typedef kern_return_t (*mach_msg_filter_alloc_service_port_sblabel_cbfunc_t)(
    mach_service_port_info_t service_port_info, void **sblabel);
typedef void (*mach_msg_filter_dealloc_service_port_sblabel_cbfunc_t)(void *sblabel);
typedef void *(*mach_msg_filter_derive_sblabel_from_service_port_cbfunc_t)(
    void *service_port_sblabel, boolean_t *send_side_filtering);
typedef kern_return_t (*mach_msg_filter_get_connection_port_filter_policy_cbfunc_t)(
    void *service_port_sblabel, void *connection_port_sblabel, uint64_t *fpid);
typedef void (*mach_msg_filter_retain_sblabel_cbfunc_t)(void *sblabel);

struct mach_msg_filter_callbacks {
    unsigned int version;
    const mach_msg_fetch_filter_policy_cbfunc_t fetch_filter_policy;
    const mach_msg_filter_alloc_service_port_sblabel_cbfunc_t alloc_service_port_sblabel;
    const mach_msg_filter_dealloc_service_port_sblabel_cbfunc_t dealloc_service_port_sblabel;
    const mach_msg_filter_derive_sblabel_from_service_port_cbfunc_t derive_sblabel_from_service_port;
    const mach_msg_filter_get_connection_port_filter_policy_cbfunc_t get_connection_port_filter_policy;
    const mach_msg_filter_retain_sblabel_cbfunc_t retain_sblabel;
};

#define MACH_MSG_FILTER_CALLBACKS_VERSION_0 0
#define MACH_MSG_FILTER_CALLBACKS_VERSION_1 1
#define MACH_MSG_FILTER_CALLBACKS_CURRENT MACH_MSG_FILTER_CALLBACKS_VERSION_1

__BEGIN_DECLS
kern_return_t mach_msg_filter_register_callback(
    const struct mach_msg_filter_callbacks *callbacks);
__END_DECLS

#if XNU_KERNEL_PRIVATE
extern struct mach_msg_filter_callbacks mach_msg_filter_callbacks;
boolean_t mach_msg_filter_at_least(unsigned int version);
#define mach_msg_fetch_filter_policy_callback (mach_msg_filter_callbacks.fetch_filter_policy)
#define mach_msg_filter_alloc_service_port_sblabel_callback (mach_msg_filter_callbacks.alloc_service_port_sblabel)
#define mach_msg_filter_dealloc_service_port_sblabel_callback (mach_msg_filter_callbacks.dealloc_service_port_sblabel)
#define mach_msg_filter_derive_sblabel_from_service_port_callback (mach_msg_filter_callbacks.derive_sblabel_from_service_port)
#define mach_msg_filter_get_connection_port_filter_policy_callback (mach_msg_filter_callbacks.get_connection_port_filter_policy)
#define mach_msg_filter_retain_sblabel_callback (mach_msg_filter_callbacks.retain_sblabel)
boolean_t mach_msg_fetch_filter_policy(
    void *portlabel, mach_msg_id_t msgh_id, mach_msg_filter_id *fid);
#endif

#endif /* _KERN_MACH_FILTER_H_ */
