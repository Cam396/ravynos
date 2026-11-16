/*
 * Portions Copyright (c) 1999-2003 Apple Computer, Inc. All Rights
 * Reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * This file was modified by William Kent in 2017 to support the PureDarwin
 * project. This notice is included in support of clause 2.2(b) of the License.
 */
/*
 * NOTICE: This file was modified for the ravynOS macOS bring-up project
 * (2026-10-18 to 2026-11-15). Included in support of clause 2.2(b) of the
 * Apple Public Source License, Version 2.0.
 */

#include "ACPICPU.h"
#include "ACPIPlatformExpert.h"

extern "C" uint32_t ml_get_apicid(uint32_t cpu);

#undef super
#define super IOCPU

uint32_t ncpus = 0;

OSDefineMetaClassAndStructors(ACPICPU, IOCPU);

IOService *ACPICPU::probe(IOService *provider, SInt32 *score) {
	return this;
}

bool ACPICPU::startCommon() {
	if (startCommonCompleted) return true;

        cpuIC = new ACPICPUInterruptController;
	if (cpuIC == 0) return false;
	/* The source count seeds XNU's maximum CPU count. numCPUs remains one
         * because each ACPI CPU owns a distinct interrupt controller object. */
        if (ncpus == 0 || cpuIC->initCPUInterruptController(ncpus, 1) !=
            kIOReturnSuccess) return false;

	cpuIC->attach(this);
        cpuIC->registerCPUInterruptController();

	setCPUState(kIOCPUStateUninitalized);
	registerService();

	startCommonCompleted = true;
	return true;
}

bool ACPICPU::start(IOService *provider) {
        IOLog("ACPICPU::start(%p)\n", provider);
        const OSSymbol * cpuNumSym = OSSymbol::withCStringNoCopy("cpu-number");
        OSNumber *cpuNum = OSDynamicCast(OSNumber, getProperty(cpuNumSym));
        cpuNumSym->release();
        if (cpuNum)
            index = cpuNum->unsigned32BitValue();
	const OSSymbol * apicIdSym = OSSymbol::withCStringNoCopy("apic-id");
	OSNumber *apicIdNumber = OSDynamicCast(OSNumber, getProperty(apicIdSym));
	if (apicIdSym) apicIdSym->release();
	if (!apicIdNumber) {
		IOLog("ACPICPU: missing MADT APIC ID\n");
		return false;
	}
	apicId = apicIdNumber->unsigned32BitValue();

	/* Controller initialization calls ml_init_max_cpus(), which releases
	 * commpage initialization. The platform must register every machine
	 * CPU before startCommon() publishes that discovery is complete. */
	return super::start(provider);
}

void ACPICPU::prepareInterrupts() {
	/* Install once before startup. initCPU() runs on the target processor
	 * and is called again when a stopped processor is brought online. */
	if (!cpuInterruptEnabled) {
		cpuIC->enableCPUInterrupt(this);
		cpuInterruptEnabled = true;
	}
}

void ACPICPU::initCPU(bool boot) {
	(void)boot;
	prepareInterrupts();
	/* The machine layer calls this on the CPU after it has actually started.
	 * A successful registration request alone must not publish Running. */
	setCPUState(kIOCPUStateRunning);
}

bool ACPICPU::registerMachineCPU(bool start) {
	const bool bootCPU = (apicId == ml_get_apicid(0));
	kern_return_t result = ml_processor_register(
	    (cpu_id_t)(uintptr_t)this, apicId, &machProcessor, bootCPU, start);
	if (result != KERN_SUCCESS) {
		IOLog("ACPICPU: XNU %s failed for APIC ID %u (result %d)\n",
		    start ? "startup" : "registration", apicId, result);
		return false;
	}
	return true;
}

void ACPICPU::quiesceCPU() {
	// Not required.
}

kern_return_t ACPICPU::startCPU(vm_offset_t start_paddr, vm_offset_t arg_paddr) {
	// Not implemented.
	kprintf("ACPICPU::startCPU(%p, %p) is a stub! (KERN_FAILURE)\n",
	    (void*)start_paddr, (void*)arg_paddr);
	return KERN_FAILURE;
}

void ACPICPU::haltCPU() {
	// Not required.
}

const OSSymbol *ACPICPU::getCPUName() {
        char buf[32];
        snprintf(buf, sizeof(buf), "cpu%u", index);
	return OSSymbol::withCString(buf);
}

#pragma mark -
#undef super
#define super IOCPUInterruptController

OSDefineMetaClassAndStructors(ACPICPUInterruptController, IOCPUInterruptController);

IOReturn ACPICPUInterruptController::handleInterrupt(void *refCon,
        IOService *nub, int source) {
    return ((ACPIPlatformExpert *)getPlatform())->handleInterrupt(refCon, nub, source);
}
