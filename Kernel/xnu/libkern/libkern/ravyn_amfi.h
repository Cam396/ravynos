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
 * NOTICE: This file was modified for the ravynOS macOS bring-up project
 * (2026-10-18 to 2026-11-15). Included in support of clause 2.2(b) of the
 * Apple Public Source License, Version 2.0.
 */


#ifndef _LIBKERN_RAVYN_AMFI_H_
#define _LIBKERN_RAVYN_AMFI_H_
#include <sys/types.h>
#include <mach/vm_types.h>
struct vnode;
#include <stdbool.h>
#include <kern/cs_blobs.h>
struct _amfi;
struct _coretrust;
struct cs_blob;
/* Opaque full interfaces; only the pinned AMFI v5 prefix is consumed here. */
void amfi_interface_register(const struct _amfi *);
void coretrust_interface_register(const struct _coretrust *);
bool ravyn_amfi_registered(void);
void ravyn_amfi_entitlements_invalidate(void *);
void *ravyn_amfi_entitlements_dictionary(void *);
bool ravyn_amfi_entitlements_xml(void *, CS_GenericBlob **);
bool ravyn_amfi_entitlements_der(void *, const CS_GenericBlob **);
void csblob_os_entitlements_set(struct cs_blob *, void *);
void *csblob_os_entitlements_copy(struct cs_blob *);
void *csblob_os_entitlements_get(struct cs_blob *);
uint32_t ravyn_csblob_macho_platform(struct cs_blob *);
void *csblob_get_storage_addr(struct cs_blob *);
int csblob_register_profile(struct cs_blob *, void *, vm_size_t);
void csvnode_invalidate_flags(struct vnode *);
void ravyn_amfi_signing_init(void);
bool pmap_cs_enabled(void);
void pmap_set_compilation_service_cdhash(const uint8_t [CS_CDHASH_LEN]);
bool pmap_match_compilation_service_cdhash(const uint8_t [CS_CDHASH_LEN]);
void pmap_set_local_signing_public_key(const uint8_t [97]);
uint8_t *pmap_get_local_signing_public_key(void);
void pmap_unrestrict_local_signing(const uint8_t [CS_CDHASH_LEN]);
uint64_t ptrauth_utils_sign_blob_generic(const void *, size_t, uint64_t, int);
void ptrauth_utils_auth_blob_generic(const void *, size_t, uint64_t, int, uint64_t);
#endif
