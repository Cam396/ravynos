/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */

#include <pexpert/protos.h>
#include <pexpert/boot.h>
#include <pexpert/device_tree.h>

#include <mach/mach_types.h>
#include <mach/machine/vm_types.h>
#include <kern/debug.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <os/overflow.h>

#include <sys/types.h>

static int DTInitialized;
static RealDTEntry DTRootNode;

/*
 * Support Routines
 */
static inline DeviceTreeNodeProperty*
next_prop(DeviceTreeNodeProperty* prop)
{
	uintptr_t next_addr;
	if (os_add3_overflow((uintptr_t)prop, prop->length, sizeof(DeviceTreeNodeProperty) + 3, &next_addr)) {
		panic("Device tree property overflow: prop %p, length 0x%x\n", prop, prop->length);
	}
	next_addr &= ~(3ULL);
	return (DeviceTreeNodeProperty*)next_addr;
}

static RealDTEntry
skipProperties(RealDTEntry entry)
{
	DeviceTreeNodeProperty *prop;
	unsigned int k;

	if (entry == NULL || entry->nProperties == 0) {
		return NULL;
	} else {
		prop = (DeviceTreeNodeProperty *) (entry + 1);
		for (k = 0; k < entry->nProperties; k++) {
			prop = next_prop(prop);
		}
	}
	return (RealDTEntry) prop;
}

static RealDTEntry
skipTree(RealDTEntry root)
{
	RealDTEntry entry;
	unsigned int k;

	entry = skipProperties(root);
	if (entry == NULL) {
		return NULL;
	}
	for (k = 0; k < root->nChildren; k++) {
		entry = skipTree(entry);
	}
	return entry;
}

static RealDTEntry
GetFirstChild(RealDTEntry parent)
{
	return skipProperties(parent);
}

static RealDTEntry
GetNextChild(RealDTEntry sibling)
{
	return skipTree(sibling);
}

static const char *
GetNextComponent(const char *cp, char *bp)
{
	size_t length = 0;
	char *origbp = bp;

	while (*cp != 0) {
		if (*cp == kDTPathNameSeparator) {
			cp++;
			break;
		}
		if (++length > kDTMaxEntryNameLength) {
			*origbp = '\0';
			return cp;
		}
		*bp++ = *cp++;
	}
	*bp = 0;
	return cp;
}

static RealDTEntry
FindChild(RealDTEntry cur, char *buf)
{
	RealDTEntry     child;
	unsigned long   index;
	char *                  str;
	unsigned int    dummy;

	if (cur->nChildren == 0) {
		return NULL;
	}
	index = 1;
	child = GetFirstChild(cur);
	while (1) {
		if (DTGetProperty(child, "name", (void **)&str, &dummy) != kSuccess) {
			break;
		}
		if (strcmp(str, buf) == 0) {
			return child;
		}
		if (index >= cur->nChildren) {
			break;
		}
		child = GetNextChild(child);
		index++;
	}
	return NULL;
}


/*
 * External Routines
 */
void
DTInit(void *base)
{
	DTRootNode = (RealDTEntry) base;
	DTInitialized = (DTRootNode != 0);
}

int
DTEntryIsEqual(const DTEntry ref1, const DTEntry ref2)
{
	/* equality of pointers */
	return ref1 == ref2;
}

static char *startingP;         // needed for find_entry
int find_entry(const char *propName, const char *propValue, DTEntry *entryH);

int
DTFindEntry(const char *propName, const char *propValue, DTEntry *entryH)
{
	if (!DTInitialized) {
		return kError;
	}

	startingP = (char *)DTRootNode;
	return find_entry(propName, propValue, entryH);
}

int
find_entry(const char *propName, const char *propValue, DTEntry *entryH)
{
	DeviceTreeNode *nodeP = (DeviceTreeNode *) (void *) startingP;
	unsigned int k;

	if (nodeP->nProperties == 0) {
		return kError;                        // End of the list of nodes
	}
	startingP = (char *) (nodeP + 1);

	// Search current entry
	for (k = 0; k < nodeP->nProperties; ++k) {
		DeviceTreeNodeProperty *propP = (DeviceTreeNodeProperty *) (void *) startingP;

		startingP += sizeof(*propP) + ((propP->length + 3) & -4);

		if (strcmp(propP->name, propName) == 0) {
			if (propValue == NULL || strcmp((char *)(propP + 1), propValue) == 0) {
				*entryH = (DTEntry)nodeP;
				return kSuccess;
			}
		}
	}

	// Search child nodes
	for (k = 0; k < nodeP->nChildren; ++k) {
		if (find_entry(propName, propValue, entryH) == kSuccess) {
			return kSuccess;
		}
	}
	return kError;
}

int
DTLookupEntry(const DTEntry searchPoint, const char *pathName, DTEntry *foundEntry)
{
	DTEntryNameBuf  buf;
	RealDTEntry     cur;
	const char *    cp;

	if (!DTInitialized) {
		return kError;
	}
	if (searchPoint == NULL) {
		cur = DTRootNode;
	} else {
		cur = searchPoint;
	}
	cp = pathName;
	if (*cp == kDTPathNameSeparator) {
		cp++;
		if (*cp == 0) {
			*foundEntry = cur;
			return kSuccess;
		}
	}
	do {
		cp = GetNextComponent(cp, buf);

		/* Check for done */
		if (*buf == 0) {
			if (*cp == 0) {
				*foundEntry = cur;
				return kSuccess;
			}
			break;
		}

		cur = FindChild(cur, buf);
	} while (cur != NULL);

	return kError;
}

int
DTInitEntryIterator(const DTEntry startEntry, DTEntryIterator iter)
{
	if (!DTInitialized) {
		return kError;
	}

	if (startEntry != NULL) {
		iter->outerScope = (RealDTEntry) startEntry;
		iter->currentScope = (RealDTEntry) startEntry;
	} else {
		iter->outerScope = DTRootNode;
		iter->currentScope = DTRootNode;
	}
	iter->currentEntry = NULL;
	iter->savedScope = NULL;
	iter->currentIndex = 0;

	return kSuccess;
}

int
DTEnterEntry(DTEntryIterator iter, DTEntry childEntry)
{
	DTSavedScopePtr newScope;

	if (childEntry == NULL) {
		return kError;
	}
	newScope = (DTSavedScopePtr) kalloc(sizeof(struct DTSavedScope));
	newScope->nextScope = iter->savedScope;
	newScope->scope = iter->currentScope;
	newScope->entry = iter->currentEntry;
	newScope->index = iter->currentIndex;

	iter->currentScope = childEntry;
	iter->currentEntry = NULL;
	iter->savedScope = newScope;
	iter->currentIndex = 0;

	return kSuccess;
}

int
DTExitEntry(DTEntryIterator iter, DTEntry *currentPosition)
{
	DTSavedScopePtr newScope;

	newScope = iter->savedScope;
	if (newScope == NULL) {
		return kError;
	}
	iter->savedScope = newScope->nextScope;
	iter->currentScope = newScope->scope;
	iter->currentEntry = newScope->entry;
	iter->currentIndex = newScope->index;
	*currentPosition = iter->currentEntry;

	kfree(newScope, sizeof(struct DTSavedScope));

	return kSuccess;
}

int
DTIterateEntries(DTEntryIterator iter, DTEntry *nextEntry)
{
	if (iter->currentIndex >= iter->currentScope->nChildren) {
		*nextEntry = NULL;
		return kIterationDone;
	} else {
		iter->currentIndex++;
		if (iter->currentIndex == 1) {
			iter->currentEntry = GetFirstChild(iter->currentScope);
		} else {
			iter->currentEntry = GetNextChild(iter->currentEntry);
		}
		*nextEntry = iter->currentEntry;
		return kSuccess;
	}
}

int
DTRestartEntryIteration(DTEntryIterator iter)
{
#if 0
	// This commented out code allows a second argument (outer)
	// which (if true) causes restarting at the outer scope
	// rather than the current scope.
	DTSavedScopePtr scope;

	if (outer) {
		while ((scope = iter->savedScope) != NULL) {
			iter->savedScope = scope->nextScope;
			kfree((vm_offset_t) scope, sizeof(struct DTSavedScope));
		}
		iter->currentScope = iter->outerScope;
	}
#endif
	iter->currentEntry = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}

int
DTGetProperty(const DTEntry entry, const char *propertyName, void **propertyValue, unsigned int *propertySize)
{
	DeviceTreeNodeProperty *prop;
	unsigned int k;

	if (entry == NULL || entry->nProperties == 0) {
		return kError;
	} else {
		prop = (DeviceTreeNodeProperty *) (entry + 1);
		for (k = 0; k < entry->nProperties; k++) {
			if (strcmp(prop->name, propertyName) == 0) {
				*propertyValue = (void *) (((uintptr_t)prop)
				    + sizeof(DeviceTreeNodeProperty));
				*propertySize = prop->length;
				return kSuccess;
			}
			prop = next_prop(prop);
		}
	}
	return kError;
}

int
DTInitPropertyIterator(const DTEntry entry, DTPropertyIterator iter)
{
	iter->entry = entry;
	iter->currentProperty = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}

int
DTIterateProperties(DTPropertyIterator iter, char **foundProperty)
{
	if (iter->currentIndex >= iter->entry->nProperties) {
		*foundProperty = NULL;
		return kIterationDone;
	} else {
		iter->currentIndex++;
		if (iter->currentIndex == 1) {
			iter->currentProperty = (DeviceTreeNodeProperty *) (iter->entry + 1);
		} else {
			iter->currentProperty = next_prop(iter->currentProperty);
		}
		*foundProperty = iter->currentProperty->name;
		return kSuccess;
	}
}

int
DTRestartPropertyIteration(DTPropertyIterator iter)
{
	iter->currentProperty = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}


/* Bounded read-only Intel DT APIs required by Monterey AppleImage4.
 * The region size comes from the actual EFI boot_args, not a guessed tree walk.
 * Legacy DT entry points retain their existing ABI and behavior. */
static uintptr_t secure_dt_start, secure_dt_end;

void
DTSecureInit(void *base, unsigned int size)
{
    uintptr_t start = (uintptr_t)base;
    if (!base || size < sizeof(DeviceTreeNode) || start > UINTPTR_MAX - size)
        panic("invalid bounded EFI device tree region");
    DTInit(base);
    secure_dt_start = start;
    secure_dt_end = start + size;
}

static int
secure_dt_range(const void *pointer, size_t size)
{
    uintptr_t address = (uintptr_t)pointer;
    return secure_dt_start && address >= secure_dt_start &&
        address <= secure_dt_end && size <= secure_dt_end - address &&
        (address & 3) == 0;
}

static const char *
secure_dt_find_zero(const void *data, size_t length)
{
    const char *bytes = data;
    for (size_t i = 0; i < length; i++) if (bytes[i] == 0) return bytes + i;
    return NULL;
}

static const DeviceTreeNodeProperty *
secure_dt_next_property(const DeviceTreeNodeProperty *property)
{
    if (!secure_dt_range(property, sizeof(*property))) return NULL;
    size_t length;
    if (os_add_overflow((size_t)property->length, (size_t)3, &length)) return NULL;
    length &= ~(size_t)3;
    if (length > SIZE_MAX - sizeof(*property) ||
        !secure_dt_range(property, sizeof(*property) + length)) return NULL;
    if (!secure_dt_find_zero(property->name, sizeof(property->name))) return NULL;
    return (const DeviceTreeNodeProperty *)((uintptr_t)property + sizeof(*property) + length);
}

static const DeviceTreeNode *
secure_dt_children(const DeviceTreeNode *node)
{
    if (!secure_dt_range(node, sizeof(*node))) return NULL;
    const DeviceTreeNodeProperty *property = (const DeviceTreeNodeProperty *)(node + 1);
    for (unsigned int i = 0; i < node->nProperties; i++) {
        property = secure_dt_next_property(property);
        if (!property) return NULL;
    }
    return (const DeviceTreeNode *)property;
}

static const DeviceTreeNode *
secure_dt_skip(const DeviceTreeNode *node, unsigned int depth)
{
    if (depth >= 128) return NULL;
    const DeviceTreeNode *cursor = secure_dt_children(node);
    if (!cursor) return NULL;
    for (unsigned int i = 0; i < node->nChildren; i++) {
        cursor = secure_dt_skip(cursor, depth + 1);
        if (!cursor) return NULL;
    }
    return cursor;
}

int
SecureDTGetProperty(const DTEntry entry, const char *name,
    const void **value, unsigned int *size)
{
    const DeviceTreeNode *node = (const DeviceTreeNode *)entry;
    if (!name || !value || !size || !secure_dt_range(node, sizeof(*node))) return kError;
    const DeviceTreeNodeProperty *property = (const DeviceTreeNodeProperty *)(node + 1);
    for (unsigned int i = 0; i < node->nProperties; i++) {
        const DeviceTreeNodeProperty *next = secure_dt_next_property(property);
        if (!next) return kError;
        if (strcmp(property->name, name) == 0) {
            *value = property + 1;
            *size = property->length;
            return kSuccess;
        }
        property = next;
    }
    return kError;
}

int
SecureDTLookupEntry(const DTEntry start, const char *path, DTEntry *found)
{
    const DeviceTreeNode *node = start ? (const DeviceTreeNode *)start :
        (const DeviceTreeNode *)secure_dt_start;
    if (!path || !found || !secure_dt_range(node, sizeof(*node))) return kError;
    if (*path == '/') path++;
    while (*path) {
        const char *end = strchr(path, '/');
        size_t length = end ? (size_t)(end - path) : strlen(path);
        if (!length || length > kDTMaxEntryNameLength) return kError;
        const DeviceTreeNode *child = secure_dt_children(node);
        if (!child) return kError;
        const DeviceTreeNode *match = NULL;
        for (unsigned int i = 0; i < node->nChildren; i++) {
            const void *name = NULL;
            unsigned int size = 0;
            if (SecureDTGetProperty((DTEntry)child, "name", &name, &size) != kSuccess)
                return kError;
            const char *zero = secure_dt_find_zero(name, size);
            if (zero && (size_t)(zero - (const char *)name) == length &&
                memcmp(name, path, length) == 0) {
                match = child;
                break;
            }
            child = secure_dt_skip(child, 0);
            if (!child) return kError;
        }
        if (!match) return kError;
        node = match;
        path = end ? end + 1 : path + length;
    }
    *found = (DTEntry)node;
    return kSuccess;
}
