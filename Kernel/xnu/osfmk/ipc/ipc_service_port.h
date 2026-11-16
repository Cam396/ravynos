/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * This file contains Original Code and/or Modifications of Original Code
 * subject to the Apple Public Source License Version 2.0 (the "License").
 * The Original Code is provided "AS IS", without warranty of any kind.
 * See http://www.opensource.apple.com/apsl/ for the License.
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * NOTICE: This file was modified for the ravynOS macOS bring-up project
 * (2026-10-18 to 2026-11-15). Included in support of clause 2.2(b) of the
 * Apple Public Source License, Version 2.0.
 */
#ifndef _IPC_IPC_SERVICE_PORT_H_
#define _IPC_IPC_SERVICE_PORT_H_
#include <mach/port.h>
#include <ipc/ipc_port.h>
#ifdef MACH_KERNEL_PRIVATE
enum {
    ISPL_FLAGS_SPECIAL_PDREQUEST = 1u << 0,
    ISPL_FLAGS_BOOTSTRAP_PORT = 1u << 1,
};
struct ipc_service_port_label {
    void *ispl_sblabel;
    mach_port_context_t ispl_launchd_context;
    mach_port_name_t ispl_launchd_name;
    uint16_t ispl_flags;
    uint8_t ispl_domain;
    char ispl_service_name[MACH_SERVICE_PORT_INFO_STRING_NAME_MAX_BUF_LEN];
};
typedef struct ipc_service_port_label *ipc_service_port_label_t;
#define IPC_SERVICE_PORT_LABEL_NULL ((ipc_service_port_label_t)0)
#define ipc_service_port_label_is_bootstrap_port(label) \
    (((label)->ispl_flags & ISPL_FLAGS_BOOTSTRAP_PORT) != 0)
kern_return_t ipc_service_port_label_alloc(mach_service_port_info_t service_port_info, void **port_label_ptr);
void ipc_service_port_label_dealloc(void *port_label, boolean_t service_port);
kern_return_t ipc_service_port_derive_sblabel(mach_port_name_t service_port_name, void **sblabel_ptr, boolean_t *filter_msgs);
void *ipc_service_port_get_sblabel(ipc_port_t port);
void ipc_service_port_label_set_attr(ipc_service_port_label_t port_splabel, mach_port_name_t name, mach_port_context_t context);
#endif /* MACH_KERNEL_PRIVATE */
#endif /* _IPC_IPC_SERVICE_PORT_H_ */
