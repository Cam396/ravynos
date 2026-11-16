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


#include <os/refcnt.h>
#include <kern/task_ident.h>
#include <kern/task.h>
#include <kern/ipc_tt.h>
#include <kern/ipc_kobject.h>
#include <kern/kalloc.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <mach/notify.h>
#include <mach/task.h>

/* Keep the exact BSD proc_ident layout without importing BSD internals into
 * osfmk. proc_find_ident validates PID, uniqueid and exec identity version. */
struct proc_ident { uint64_t p_uniqueid; int p_pid; int p_idversion; };
struct proc;
struct ucred;
extern struct proc *proc_find(int);
extern struct proc *proc_find_ident(const struct proc_ident *);
extern struct proc_ident proc_ident(struct proc *);
extern int proc_rele(struct proc *);
extern task_t proc_task(struct proc *);
extern kern_return_t task_conversion_eval(task_t, task_t);
#if CONFIG_MACF
extern int mac_proc_check_task_id_token_get_task(struct proc *, unsigned int);
#endif

struct task_id_token {
    struct proc_ident ident;
    ipc_port_t port;
    os_refcnt_t refs;
};

void
task_id_token_release(task_id_token_t token)
{
    if (!token || os_ref_release(&token->refs) != 0) return;
    ipc_port_t port = token->port;
    if (IP_VALID(port)) {
        /* Serialize the last release with converter try-retains. A converter
         * must neither resurrect the object nor dereference a freed token. */
        ip_lock(port);
        assert(ip_get_kobject(port) == (ipc_kobject_t)token);
        ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
        ip_unlock(port);
        ipc_port_dealloc_kernel(port);
    }
    bzero(token, sizeof(*token));
    kfree(token, sizeof(*token));
}

task_id_token_t
convert_port_to_task_id_token(ipc_port_t port)
{
    task_id_token_t token = TASK_ID_TOKEN_NULL;
    if (!IP_VALID(port)) return token;
    ip_lock(port);
    if (ip_active(port) && ip_kotype(port) == IKOT_TASK_ID_TOKEN) {
        task_id_token_t candidate = (task_id_token_t)ip_get_kobject(port);
        if (candidate && os_ref_retain_try(&candidate->refs)) token = candidate;
    }
    ip_unlock(port);
    return token;
}

ipc_port_t
convert_task_id_token_to_port(task_id_token_t token)
{
    if (!token) return IP_NULL;
    boolean_t donated = ipc_kobject_make_send_lazy_alloc_port(&token->port,
        (ipc_kobject_t)token, IKOT_TASK_ID_TOKEN);
    ipc_port_t port = token->port;
    if (!donated) task_id_token_release(token);
    return port;
}

void
task_id_token_notify(mach_msg_header_t *message)
{
    /* Called only after ipc_kobject_notify verifies the kernel audit/security
     * trailer. A stale no-senders notification still owns its donated ref. */
    ipc_port_t port = message->msgh_remote_port;
    ip_lock(port);
    task_id_token_t token = (task_id_token_t)ip_get_kobject(port);
    assert(ip_active(port) && ip_kotype(port) == IKOT_TASK_ID_TOKEN && token);
    ip_unlock(port);
    task_id_token_release(token);
}

kern_return_t
task_create_identity_token(task_t task, task_id_token_t *out)
{
    if (!out) return KERN_INVALID_ARGUMENT;
    *out = TASK_ID_TOKEN_NULL;
    if (task == TASK_NULL || task == kernel_task) return KERN_INVALID_ARGUMENT;
    /* Darwin 19 has no lookup-by-corpse-uniqueid lifetime protocol. */
    if (is_corpsetask(task)) return KERN_NOT_SUPPORTED;
    if (!task->active) return KERN_INVALID_ARGUMENT;
    struct proc *p = proc_find(task_pid(task));
    if (!p) return KERN_NOT_FOUND;
    struct proc_ident identity = proc_ident(p);
    if (proc_task(p) != task) {
        proc_rele(p);
        return KERN_NOT_FOUND;
    }
    proc_rele(p);
    task_id_token_t token = kalloc(sizeof(*token));
    if (!token) return KERN_RESOURCE_SHORTAGE;
    bzero(token, sizeof(*token));
    token->ident = identity;
    os_ref_init_count(&token->refs, NULL, 1);
    *out = token;
    return KERN_SUCCESS;
}

static kern_return_t
task_identity_token_resolve(task_id_token_t token, task_t *out)
{
    *out = TASK_NULL;
    if (!token) return KERN_INVALID_ARGUMENT;
    struct proc *p = proc_find_ident(&token->ident);
    if (!p) return KERN_NOT_FOUND;
    task_t task = proc_task(p);
    if (task == TASK_NULL || task == kernel_task || !task->active) {
        proc_rele(p);
        return KERN_NOT_FOUND;
    }
    task_reference(task);
    proc_rele(p);
    *out = task;
    return KERN_SUCCESS;
}

kern_return_t
task_id_token_port_name_to_task(mach_port_name_t name, task_t *out)
{
    if (!out) return KERN_INVALID_ARGUMENT;
    *out = TASK_NULL;
    if (!MACH_PORT_VALID(name)) return KERN_INVALID_ARGUMENT;
    ipc_port_t port;
    kern_return_t kr = ipc_port_translate_send(current_space(), name, &port);
    if (kr != KERN_SUCCESS) return KERN_INVALID_ARGUMENT;
    task_id_token_t token = TASK_ID_TOKEN_NULL;
    if (ip_kotype(port) == IKOT_TASK_ID_TOKEN) {
        task_id_token_t candidate = (task_id_token_t)ip_get_kobject(port);
        if (candidate && os_ref_retain_try(&candidate->refs)) token = candidate;
    }
    ip_unlock(port);
    kr = task_identity_token_resolve(token, out);
    task_id_token_release(token);
    return kr;
}

kern_return_t
task_identity_token_get_task_port(task_id_token_t token, task_flavor_t flavor,
    mach_port_t *out)
{
    if (!out) return KERN_INVALID_ARGUMENT;
    *out = IP_NULL;
    if (flavor > TASK_FLAVOR_NAME) return KERN_INVALID_ARGUMENT;
    /* Do not substitute a control port for an unsupported inspect flavor. */
    if (flavor == TASK_FLAVOR_INSPECT) return KERN_NOT_SUPPORTED;
    task_t task;
    kern_return_t kr = task_identity_token_resolve(token, &task);
    if (kr != KERN_SUCCESS) return kr;
    if (flavor != TASK_FLAVOR_NAME && task_conversion_eval(current_task(), task)) {
        task_deallocate(task);
        return KERN_INVALID_ARGUMENT;
    }
#if CONFIG_MACF
    if (task != current_task()) {
        struct proc *p = proc_find_ident(&token->ident);
        if (!p || proc_task(p) != task) {
            if (p) proc_rele(p);
            task_deallocate(task);
            return KERN_NOT_FOUND;
        }
        int denied = mac_proc_check_task_id_token_get_task(p, flavor);
        proc_rele(p);
        if (denied) {
            task_deallocate(task);
            return KERN_DENIED;
        }
    }
#endif
    /* Each real converter consumes the referenced task. */
    switch (flavor) {
    case TASK_FLAVOR_CONTROL: *out = convert_task_to_port(task); break;
    case TASK_FLAVOR_READ: *out = convert_task_read_to_port(task); break;
    case TASK_FLAVOR_NAME: *out = convert_task_name_to_port(task); break;
    default: task_deallocate(task); return KERN_INVALID_ARGUMENT;
    }
    return IP_VALID(*out) ? KERN_SUCCESS : KERN_FAILURE;
}
