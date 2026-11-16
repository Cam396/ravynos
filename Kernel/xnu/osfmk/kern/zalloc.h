/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
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
/*
 */
/*
 *	File:	zalloc.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	 1985
 *
 */

#ifdef  KERNEL_PRIVATE

#ifndef _KERN_ZALLOC_H_
#define _KERN_ZALLOC_H_

#include <mach/machine/vm_types.h>
#include <mach_debug/zone_info.h>
#include <kern/kern_types.h>
#include <sys/cdefs.h>

/* Monterey read-only zone KPI subset, ABI-compatible with XNU 8020. */
typedef uint16_t zone_id_t;
typedef uint32_t zalloc_flags_t;
typedef uint32_t zro_atomic_op_t;
typedef uint32_t zone_create_ro_id_t;
__options_decl(zone_create_flags_t, uint64_t, {
 ZC_NONE=0, ZC_CACHING=0x00000010, ZC_NOCACHING=0x00000020, ZC_READONLY=0x00800000,
 ZC_ZFREE_CLEARMEM=0x02000000, ZC_NOGC=0x04000000,
 ZC_NOENCRYPT=0x08000000, ZC_ALIGNMENT_REQUIRED=0x10000000,
 ZC_NOGZALLOC=0x20000000, ZC_NOCALLOUT=0x40000000
});
enum { Z_WAITOK=0, Z_NOWAIT=0x0001, Z_NOPAGEWAIT=0x0002,
       Z_ZERO=0x0004, Z_NOFAIL=0x8000 };
enum { ZC_RO_ID_SANDBOX=0, ZC_RO_ID_PROFILE=1, ZC_RO_ID_PROTOBOX=2,
       ZC_RO_ID_SB_FILTER=3, ZC_RO_ID__LAST=ZC_RO_ID_SB_FILTER };
enum {
 ZRO_ATOMIC_OR_8=0x11,ZRO_ATOMIC_OR_16=0x12,ZRO_ATOMIC_OR_32=0x14,ZRO_ATOMIC_OR_64=0x18,
 ZRO_ATOMIC_XOR_8=0x21,ZRO_ATOMIC_XOR_16=0x22,ZRO_ATOMIC_XOR_32=0x24,ZRO_ATOMIC_XOR_64=0x28,
 ZRO_ATOMIC_AND_8=0x31,ZRO_ATOMIC_AND_16=0x32,ZRO_ATOMIC_AND_32=0x34,ZRO_ATOMIC_AND_64=0x38,
 ZRO_ATOMIC_ADD_8=0x41,ZRO_ATOMIC_ADD_16=0x42,ZRO_ATOMIC_ADD_32=0x44,ZRO_ATOMIC_ADD_64=0x48,
 ZRO_ATOMIC_XCHG_8=0x51,ZRO_ATOMIC_XCHG_16=0x52,ZRO_ATOMIC_XCHG_32=0x54,ZRO_ATOMIC_XCHG_64=0x58
};
__BEGIN_DECLS
extern zone_t zone_create(const char *, vm_size_t, zone_create_flags_t);
extern void *zalloc_flags(zone_t, zalloc_flags_t);
extern void kern_os_zfree(zone_t, void *, vm_size_t);
__END_DECLS

extern zone_id_t zone_create_ro(const char *, vm_size_t, zone_create_flags_t, zone_create_ro_id_t);
extern void *zalloc_ro(zone_id_t, zalloc_flags_t);
extern void zalloc_ro_mut(zone_id_t, void *, vm_offset_t, const void *, vm_size_t);
extern uint64_t zalloc_ro_mut_atomic(zone_id_t, void *, vm_offset_t, zro_atomic_op_t, uint64_t);
extern void zfree_ro(zone_id_t, void *);
extern void zone_require_ro(zone_id_t, vm_size_t, void *);

#ifdef  MACH_KERNEL_PRIVATE

#include <zone_debug.h>
#include <kern/locks.h>
#include <kern/queue.h>
#include <kern/thread_call.h>
#include <kern/btlog.h>

#if KASAN
#include <sys/queue.h>
#include <san/kasan.h>
#endif

#ifdef CONFIG_ZCACHE
#include <kern/zcache.h>
#endif

#if     CONFIG_GZALLOC
typedef struct gzalloc_data {
	uint32_t        gzfc_index;
	vm_offset_t     *gzfc;
} gzalloc_data_t;
#endif

/*
 *	A zone is a collection of fixed size blocks for which there
 *	is fast allocation/deallocation access.  Kernel routines can
 *	use zones to manage data structures dynamically, creating a zone
 *	for each type of data structure to be managed.
 *
 */

struct zone_free_element;
struct zone_page_metadata;

struct zone {
#ifdef   CONFIG_ZCACHE
	struct zone_cache *zcache;
#endif  /* CONFIG_ZCACHE */
	struct zone_free_element *free_elements;        /* free elements directly linked */
	struct {
		queue_head_t                    any_free_foreign;       /* foreign pages crammed into zone */
		queue_head_t                    all_free;
		queue_head_t                    intermediate;
		queue_head_t                    all_used;
	} pages;                /* list of zone_page_metadata structs, which maintain per-page free element lists */
	int             count;          /* Number of elements used now */
	int             countfree;      /* Number of free elements */
	int     count_all_free_pages;  /* Number of pages collectable by GC */
	lck_attr_t      lock_attr;      /* zone lock attribute */
	decl_lck_mtx_data(, lock);       /* zone lock */
	lck_mtx_ext_t   lock_ext;       /* placeholder for indirect mutex */
	vm_size_t       cur_size;       /* current memory utilization */
	vm_size_t       max_size;       /* how large can this zone grow */
	vm_size_t       elem_size;      /* size of an element */
	vm_size_t       alloc_size;     /* size used for more memory */
	uint64_t        page_count __attribute__((aligned(8)));   /* number of pages used by this zone */
	uint64_t        sum_count;      /* count of allocs (life of zone) */
	uint64_t
	/* boolean_t */ exhaustible        :1,  /* (F) merely return if empty? */
	/* boolean_t */ collectable        :1,  /* (F) garbage collect empty pages */
	/* boolean_t */ expandable         :1,  /* (T) expand zone (with message)? */
	/* boolean_t */ allows_foreign     :1,  /* (F) allow non-zalloc space */
	/* boolean_t */ doing_alloc_without_vm_priv:1,  /* is zone expanding now via a non-vm_privileged thread? */
	/* boolean_t */ doing_alloc_with_vm_priv:1, /* is zone expanding now via a vm_privileged thread? */
	/* boolean_t */ waiting            :1,  /* is thread waiting for expansion? */
	/* boolean_t */ async_pending      :1,  /* asynchronous allocation pending? */
	/* boolean_t */ zleak_on           :1,  /* Are we collecting allocation information? */
	/* boolean_t */ caller_acct        :1,  /* do we account allocation/free to the caller? */
	/* boolean_t */ noencrypt          :1,
	/* boolean_t */ no_callout         :1,
	/* boolean_t */ async_prio_refill  :1,
	/* boolean_t */ gzalloc_exempt     :1,
	/* boolean_t */ alignment_required :1,
	/* boolean_t */ zone_logging       :1,  /* Enable zone logging for this zone. */
	/* boolean_t */ zone_replenishing  :1,
	/* boolean_t */ kasan_quarantine   :1,
	/* boolean_t */ tags               :1,
	/* boolean_t */ tags_inline        :1,
	/* future    */ tag_zone_index     :6,
	/* boolean_t */ zone_valid         :1,
	/* boolean_t */ cpu_cache_enable_when_ready  :1,
	/* boolean_t */ cpu_cache_enabled  :1,
	/* boolean_t */ clear_memory       :1,
	/* boolean_t */ zone_destruction   :1,
	/* boolean_t */ zero_on_free       :1,
	/* future    */ _reserved          :32;

	int             index;          /* index into zone_info arrays for this zone */
	const char      *zone_name;     /* a name for the zone */

#if CONFIG_ZLEAKS
	uint32_t zleak_capture;         /* per-zone counter for capturing every N allocations */
#endif /* CONFIG_ZLEAKS */
	uint32_t zp_count;              /* counter for poisoning every N frees */
	uint32_t prio_refill_count;     /* if async_prio_refill, refill to this count */
	thread_t zone_replenish_thread;
#if     CONFIG_GZALLOC
	gzalloc_data_t  gz;
#endif /* CONFIG_GZALLOC */

#if KASAN_ZALLOC
	vm_size_t kasan_redzone;
#endif

	btlog_t         *zlog_btlog;            /* zone logging structure to hold stacks and element references to those stacks. */
};

/*
 *	structure for tracking zone usage
 *	Used either one per task/thread for all zones or <per-task,per-zone>.
 */
typedef struct zinfo_usage_store_t {
	/* These fields may be updated atomically, and so must be 8 byte aligned */
	uint64_t        alloc __attribute__((aligned(8)));              /* allocation counter */
	uint64_t        free __attribute__((aligned(8)));               /* free counter */
} zinfo_usage_store_t;

/*
 * For sysctl kern.zones_collectable_bytes used by memory_maintenance to check if a
 * userspace reboot is needed. The only other way to query for this information
 * is via mach_memory_info() which is unavailable on release kernels.
 */
extern uint64_t get_zones_collectable_bytes(void);

/*
 * zone_gc also checks if the zone_map is getting close to full and triggers jetsams if needed, provided
 * consider_jetsams is set to TRUE. To avoid deadlocks, we only pass a value of TRUE from within the
 * vm_pageout_garbage_collect thread.
 */
extern void             zone_gc(boolean_t consider_jetsams);
extern void             consider_zone_gc(boolean_t consider_jetsams);
extern void             drop_free_elements(zone_t z);

/* Debug logging for zone-map-exhaustion jetsams. */
extern void             get_zone_map_size(uint64_t *current_size, uint64_t *capacity);
extern void             get_largest_zone_info(char *zone_name, size_t zone_name_len, uint64_t *zone_size);

/* Bootstrap zone module (create zone zone) */
extern void             zone_bootstrap(void);

/* Init zone module */
extern void             zone_init(
	vm_size_t       map_size);

/* Stack use statistics */
extern void             stack_fake_zone_init(int zone_index);
extern void             stack_fake_zone_info(
	int                     *count,
	vm_size_t       *cur_size,
	vm_size_t       *max_size,
	vm_size_t       *elem_size,
	vm_size_t       *alloc_size,
	uint64_t        *sum_size,
	int                     *collectable,
	int                     *exhaustable,
	int             *caller_acct);

#if             ZONE_DEBUG

extern void             zone_debug_enable(
	zone_t          z);

extern void             zone_debug_disable(
	zone_t          z);

#define zone_debug_enabled(z) z->active_zones.next
#define ROUNDUP(x, y)            ((((x)+(y)-1)/(y))*(y))
#define ZONE_DEBUG_OFFSET       ROUNDUP(sizeof(queue_chain_t),16)
#endif  /* ZONE_DEBUG */

extern unsigned int            num_zones;
extern struct zone             zone_array[];

/* zindex and page_count must pack into 16 bits
 * update tools/lldbmacros/memory.py:GetRealMetadata
 * when these values change */

#define ZINDEX_BITS              (10U)
#define PAGECOUNT_BITS           (16U - ZINDEX_BITS)
#define MULTIPAGE_METADATA_MAGIC ((1UL << ZINDEX_BITS) - 1)
#define ZONE_CHUNK_MAXPAGES      ((1UL << PAGECOUNT_BITS) - 1)

/*
 * The max # of elements in a chunk should fit into zone_page_metadata.free_count (uint16_t).
 * Update this if the type of free_count changes.
 */
#define ZONE_CHUNK_MAXELEMENTS   (UINT16_MAX)

#endif  /* MACH_KERNEL_PRIVATE */

__BEGIN_DECLS


/* Item definitions for zalloc/zinit/zone_change */
#define Z_EXHAUST       1       /* Make zone exhaustible	*/
#define Z_COLLECT       2       /* Make zone collectable	*/
#define Z_EXPAND        3       /* Make zone expandable		*/
#define Z_FOREIGN       4       /* Allow collectable zone to contain foreign elements */
#define Z_CALLERACCT    5       /* Account alloc/free against the caller */
#define Z_NOENCRYPT     6       /* Don't encrypt zone during hibernation */
#define Z_NOCALLOUT     7       /* Don't asynchronously replenish the zone via callouts */
#define Z_ALIGNMENT_REQUIRED 8
#define Z_GZALLOC_EXEMPT 9      /* Not tracked in guard allocation mode */
#define Z_KASAN_QUARANTINE      10 /* Allow zone elements to be quarantined on free */
#ifdef  XNU_KERNEL_PRIVATE
#define Z_TAGS_ENABLED  11      /* Store tags */
#endif  /* XNU_KERNEL_PRIVATE */
#define Z_CACHING_ENABLED 12    /*enable and initialize per-cpu caches for the zone*/
#define Z_CLEARMEMORY 13        /* Use KMA_ZERO on new allocations */

#ifdef  XNU_KERNEL_PRIVATE

extern vm_offset_t     zone_map_min_address;
extern vm_offset_t     zone_map_max_address;

/* free an element with no regard for gzalloc, zleaks, or kasan*/
extern void     zfree_direct(           zone_t          zone,
    vm_offset_t     elem);

/* attempts to allocate an element with no regard for gzalloc, zleaks, or kasan*/
extern void *   zalloc_attempt(         zone_t          zone);

/* Non-waiting for memory version of zalloc */
extern void *   zalloc_nopagewait(
	zone_t          zone);

/* No page wait, retaining kalloc request-size/tag accounting. */
extern void *   zalloc_nopagewait_tag(zone_t zone, vm_size_t reqsize, vm_tag_t tag);

/* selective version of zalloc */
extern void *   zalloc_canblock(
	zone_t          zone,
	boolean_t       canblock);

/* selective version of zalloc */
extern void *   zalloc_canblock_tag(
	zone_t          zone,
	boolean_t       canblock,
	vm_size_t       reqsize,
	vm_tag_t    tag);

/* Get from zone free list */
extern void *   zget(
	zone_t          zone);

/* Fill zone with memory */
extern void             zcram(
	zone_t          zone,
	vm_offset_t     newmem,
	vm_size_t       size);

/* Initially fill zone with specified number of elements */
extern int              zfill(
	zone_t          zone,
	int                     nelem);

extern void             zone_prio_refill_configure(zone_t);

/* See above/top of file. Z_* definitions moved so they would be usable by kexts */

/* Preallocate space for zone from zone map */
extern void             zprealloc(
	zone_t          zone,
	vm_size_t       size);

extern integer_t        zone_free_count(
	zone_t          zone);

extern vm_size_t        zone_element_size(
	void            *addr,
	zone_t          *z);

/*
 *  Structure for keeping track of a backtrace, used for leak detection.
 *  This is in the .h file because it is used during panic, see kern/debug.c
 *  A non-zero size indicates that the trace is in use.
 */
struct ztrace {
	vm_size_t               zt_size;                        /* How much memory are all the allocations referring to this trace taking up? */
	uint32_t                zt_depth;                       /* depth of stack (0 to MAX_ZTRACE_DEPTH) */
	void*                   zt_stack[MAX_ZTRACE_DEPTH];     /* series of return addresses from OSBacktrace */
	uint32_t                zt_collisions;                  /* How many times did a different stack land here while it was occupied? */
	uint32_t                zt_hit_count;                   /* for determining effectiveness of hash function */
};

#if CONFIG_ZLEAKS

/* support for the kern.zleak.* sysctls */

extern kern_return_t zleak_activate(void);
extern vm_size_t zleak_max_zonemap_size;
extern vm_size_t zleak_global_tracking_threshold;
extern vm_size_t zleak_per_zone_tracking_threshold;

extern int get_zleak_state(void);

#endif  /* CONFIG_ZLEAKS */

#ifndef VM_MAX_TAG_ZONES
#error MAX_TAG_ZONES
#endif

#if VM_MAX_TAG_ZONES

extern boolean_t zone_tagging_on;
extern uint32_t  zone_index_from_tag_index(uint32_t tag_zone_index, vm_size_t * elem_size);

#endif /* VM_MAX_TAG_ZONES */

/* These functions used for leak detection both in zalloc.c and mbuf.c */
extern uintptr_t hash_mix(uintptr_t);
extern uint32_t hashbacktrace(uintptr_t *, uint32_t, uint32_t);
extern uint32_t hashaddr(uintptr_t, uint32_t);

#define lock_zone(zone)                                 \
MACRO_BEGIN                                             \
	lck_mtx_lock_spin_always(&(zone)->lock);        \
MACRO_END

#define unlock_zone(zone)                               \
MACRO_BEGIN                                             \
	lck_mtx_unlock(&(zone)->lock);                  \
MACRO_END

#if     CONFIG_GZALLOC
void gzalloc_init(vm_size_t);
void gzalloc_zone_init(zone_t);
void gzalloc_configure(void);
void gzalloc_reconfigure(zone_t);
void gzalloc_empty_free_cache(zone_t);
boolean_t gzalloc_enabled(void);

vm_offset_t gzalloc_alloc(zone_t, boolean_t);
boolean_t gzalloc_free(zone_t, void *);
boolean_t gzalloc_element_size(void *, zone_t *, vm_size_t *);
#endif /* CONFIG_GZALLOC */

/* Callbacks for btlog lock/unlock */
void zlog_btlog_lock(__unused void *);
void zlog_btlog_unlock(__unused void *);

#ifdef MACH_KERNEL_PRIVATE
#define MAX_ZONE_NAME   32      /* max length of a zone name we can take from the boot-args */
int track_this_zone(const char *zonename, const char *logname);
#endif

#if DEBUG || DEVELOPMENT
extern boolean_t run_zone_test(void);
extern vm_size_t zone_element_info(void *addr, vm_tag_t * ptag);
#endif /* DEBUG || DEVELOPMENT */

#endif  /* XNU_KERNEL_PRIVATE */

/* Allocate from zone */
extern void *   zalloc(
	zone_t          zone);

/* Non-blocking version of zalloc */
extern void *   zalloc_noblock(
	zone_t          zone);

/* Free zone element */
extern void             zfree(
	zone_t          zone,
	void            *elem);

#ifdef XNU_KERNEL_PRIVATE
#define zfree(zone, elem) \
_Pragma("clang diagnostic push") \
_Pragma("clang diagnostic ignored \"-Wshadow\"") \
	do { \
	        _Static_assert(sizeof (elem) == sizeof (void *) || sizeof (elem) == sizeof (mach_vm_address_t), "elem is not a pointer"); \
	        void *__tmp_addr = (void *) elem; \
	        zone_t __tmp_zone = zone; \
	        elem = (__typeof__(elem)) NULL; \
	        (zfree)(__tmp_zone, __tmp_addr); \
	} while (0) \
_Pragma("clang diagnostic pop")
#endif /* XNU_KERNEL_PRIVATE */

/* Create zone */
extern zone_t   zinit(
	vm_size_t       size,                                           /* the size of an element */
	vm_size_t       maxmem,                                         /* maximum memory to use */
	vm_size_t       alloc,                                          /* allocation size */
	const char      *name);                                         /* a name for the zone */

/* Change zone parameters */
extern void             zone_change(
	zone_t                  zone,
	unsigned int    item,
	boolean_t               value);

/* Destroy the zone */
extern void             zdestroy(
	zone_t          zone);

#ifdef XNU_KERNEL_PRIVATE

/* Panic if a pointer is not mapped to the zone specified */
extern void             zone_require(
	void *addr,
	zone_t expected_zone);

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _KERN_ZALLOC_H_ */

#endif  /* KERNEL_PRIVATE */
