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


#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/ravyn_amfi.h>
#include <libkern/OSAtomic.h>
#include <kern/lock.h>
#include <kern/simple_lock.h>
#include <kern/assert.h>
#include <sys/codesign.h>
#include <sys/ubc_internal.h>
#include <sys/vnode_internal.h>

/* Exact first five pointer-sized fields of xnu-8020.140.41 amfi_t.  The
 * CoreEntitlements implementation and its private types remain in Apple AMFI.
 * The query slot is never invoked or reinterpreted by this bridge. */
struct ravyn_amfi_prefix {
    void (*invalidate)(void *);
    void *(*as_dictionary)(void *);
    void (*private_query)(void);
    bool (*transmuted)(void *, const CS_GenericBlob **);
    bool (*xml)(void *, CS_GenericBlob **);
};
static SECURITY_READ_ONLY_LATE(const struct _amfi *) amfi_interface = NULL;
static SECURITY_READ_ONLY_LATE(const struct _coretrust *) coretrust_interface = NULL;

static const struct ravyn_amfi_prefix *
amfi_prefix(void)
{
    return (const struct ravyn_amfi_prefix *)(const void *)amfi_interface;
}

void
amfi_interface_register(const struct _amfi *interface)
{
    if (amfi_interface || interface == NULL)
        panic("AppleMobileFileIntegrity interface already set or null");
    amfi_interface = interface;
}

void
coretrust_interface_register(const struct _coretrust *interface)
{
    if (coretrust_interface || interface == NULL)
        panic("CoreTrust interface already set or null");
    coretrust_interface = interface;
}

bool ravyn_amfi_registered(void) { return amfi_interface != NULL; }
void
ravyn_amfi_entitlements_invalidate(void *entitlements)
{
    if (amfi_interface && entitlements) amfi_prefix()->invalidate(entitlements);
}
void *
ravyn_amfi_entitlements_dictionary(void *entitlements)
{
    assert(amfi_interface != NULL);
    return amfi_prefix()->as_dictionary(entitlements);
}
bool
ravyn_amfi_entitlements_xml(void *entitlements, CS_GenericBlob **blob)
{
    *blob = NULL;
    return amfi_interface && entitlements && amfi_prefix()->xml(entitlements, blob);
}
bool
ravyn_amfi_entitlements_der(void *entitlements, const CS_GenericBlob **blob)
{
    *blob = NULL;
    return amfi_interface && entitlements && amfi_prefix()->transmuted(entitlements, blob);
}

void
csblob_os_entitlements_set(struct cs_blob *blob, void *entitlements)
{
    assert(blob->csb_entitlements == NULL);
    if (entitlements) osobject_retain(entitlements);
    blob->csb_entitlements = entitlements;
}
void *
csblob_os_entitlements_copy(struct cs_blob *blob)
{
    if (blob->csb_entitlements) osobject_retain(blob->csb_entitlements);
    return blob->csb_entitlements;
}
void *csblob_os_entitlements_get(struct cs_blob *blob) { return blob->csb_entitlements; }
uint32_t ravyn_csblob_macho_platform(struct cs_blob *blob) { return blob->csb_macho_platform; }

void *
csblob_get_storage_addr(struct cs_blob *blob)
{
    /* Darwin19 has no RO-zone alias.  Its allocated cs_blob itself is the
     * stable storage object, also used by subsequent getter callbacks. */
    return blob;
}
int
csblob_register_profile(struct cs_blob *__unused blob,
    void *__unused profile, vm_size_t __unused size)
{
    /* Exact Intel xnu-8020 behavior: AMFI validates provisioning profiles;
     * this architecture has no PMAP/PPL profile registration backend. */
    return 0;
}
void
csvnode_invalidate_flags(struct vnode *vp)
{
    struct cs_blob *blob = ubc_get_cs_blobs(vp);
    if (blob == NULL) return;
    vnode_lock(vp);
    if (vp->v_ubcinfo) vp->v_ubcinfo->ui_flags |= UI_CSBLOBINVALID;
    vnode_unlock(vp);
    /* Vnode iocount protects the list, which is reclaimed only at inactive. */
    for (; blob != NULL; blob = blob->csb_next) {
        OSBitAndAtomic(~CS_VALID, &blob->csb_flags);
        ravyn_amfi_entitlements_invalidate(blob->csb_entitlements);
    }
}

#if defined(__x86_64__)
/* Intel behavior from xnu-8020 x86_64/pmap.c and ptrauth_utils.c.  This does
 * not advertise ARM PPL, pointer authentication, or PMAP code-signing support. */
decl_simple_lock_data(static, amfi_signing_lock);
void ravyn_amfi_signing_init(void) { simple_lock_init(&amfi_signing_lock, 0); }
static uint8_t compilation_cdhash[CS_CDHASH_LEN];
static uint8_t local_signing_public_key[97];
static bool local_signing_public_key_set;
bool pmap_cs_enabled(void) { return false; }
void
pmap_set_compilation_service_cdhash(const uint8_t hash[CS_CDHASH_LEN])
{
    simple_lock(&amfi_signing_lock, LCK_GRP_NULL);
    memcpy(compilation_cdhash, hash, sizeof(compilation_cdhash));
    simple_unlock(&amfi_signing_lock);
}
bool
pmap_match_compilation_service_cdhash(const uint8_t hash[CS_CDHASH_LEN])
{
    bool match;
    simple_lock(&amfi_signing_lock, LCK_GRP_NULL);
    match = memcmp(compilation_cdhash, hash, sizeof(compilation_cdhash)) == 0;
    simple_unlock(&amfi_signing_lock);
    return match;
}
void
pmap_set_local_signing_public_key(const uint8_t key[97])
{
    simple_lock(&amfi_signing_lock, LCK_GRP_NULL);
    if (local_signing_public_key_set)
        panic("attempted to set the local signing public key multiple times");
    memcpy(local_signing_public_key, key, sizeof(local_signing_public_key));
    /* Publish only after the complete key has been copied. */
    local_signing_public_key_set = true;
    simple_unlock(&amfi_signing_lock);
}
uint8_t *
pmap_get_local_signing_public_key(void)
{
    uint8_t *key;
    simple_lock(&amfi_signing_lock, LCK_GRP_NULL);
    key = local_signing_public_key_set ? local_signing_public_key : NULL;
    simple_unlock(&amfi_signing_lock);
    return key;
}
void pmap_unrestrict_local_signing(const uint8_t __unused hash[CS_CDHASH_LEN]) { }
uint64_t
ptrauth_utils_sign_blob_generic(const void *__unused p, size_t __unused size,
    uint64_t __unused data, int __unused flags)
{
    return 0;
}
void
ptrauth_utils_auth_blob_generic(const void *__unused p, size_t __unused size,
    uint64_t __unused data, int __unused flags, uint64_t __unused signature) { }
#endif
