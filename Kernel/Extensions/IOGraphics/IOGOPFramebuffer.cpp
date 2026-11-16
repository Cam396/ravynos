/*
 * IOGOPFramebuffer.cpp: minimal boot framebuffer using EFI GOP
 *
 * Copyright (C) 2025-2026 Zoe Knox. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "IOGOPFramebuffer.h"

#define kDisplayModeID 1

#ifndef GRAPHICS_MODE
/* ARM64 selects the graphics console when Boot_Video.v_display is nonzero. */
#define GRAPHICS_MODE 1
#endif
#define kDepthIndex    0  /* One 32-bit pixel format, at depth index zero. */

#define DEBUG(x, ...) kprintf("IOGOPFramebuffer: " x, ##__VA_ARGS__)

#define super IOFramebuffer
OSDefineMetaClassAndStructors(IOGOPFramebuffer, IOFramebuffer);

IOService *
IOGOPFramebuffer::probe(IOService *provider, SInt32 *score)
{
    return this;
}

bool
IOGOPFramebuffer::start(IOService *provider)
{
    if (!super::start(provider)) {
        DEBUG("super::start failed\n");
        return false;
    }

    PE_Video    bootDisplay;
    IOPlatformExpert *pe = getPlatform();
    if (!pe) {
        DEBUG("getPlatform() returned null\n");
        return false;
    }
    IOReturn err = pe->getConsoleInfo( &bootDisplay);
    if (err != kIOReturnSuccess) {
        DEBUG("getConsoleInfo failed: %d\n", err);
        return false;
    }
    if (bootDisplay.v_baseAddr == 0) {
        DEBUG("no framebuffer base address\n");
        return false;
    }
    // PE console addresses carry low-bit mapping flags, not pixel offsets.
    // initialize_screen() strips these same two bits before physical mapping.
    const unsigned long rawConsoleBase = bootDisplay.v_baseAddr;
    bootDisplay.v_baseAddr &= ~3UL;
    fbBase = (void *)bootDisplay.v_baseAddr;
    kprintf("RAVYN-GOP-BASE raw=0x%lx physical=0x%lx flags=%lu\n",
            rawConsoleBase, bootDisplay.v_baseAddr, rawConsoleBase & 3UL);
    width  = bootDisplay.v_width;
    height = bootDisplay.v_height;
    pitch  = bootDisplay.v_rowBytes;
    bpp    = 32;

    IOLog("IOFB: GOP framebuffer %dx%d @ %p\n", width, height, fbBase);

    // Register the framebuffer with the kernel console system
    PE_Video consoleInfo;
    consoleInfo.v_baseAddr   = bootDisplay.v_baseAddr | 1;  // Set low bit to force mapping
    consoleInfo.v_width      = bootDisplay.v_width;
    consoleInfo.v_height     = bootDisplay.v_height;
    consoleInfo.v_depth      = 32;  // GOP is always 32-bit
    consoleInfo.v_rowBytes   = bootDisplay.v_rowBytes;
    consoleInfo.v_display    = GRAPHICS_MODE;
    consoleInfo.v_offset     = 0;
    consoleInfo.v_length     = 0;  // Let kernel calculate from height * rowBytes
    consoleInfo.v_rotate     = 0;
    consoleInfo.v_scale      = kPEScaleFactor1x;

    // Initialize graphics console with this framebuffer
    // Use the public IOPlatformExpert::setConsoleInfo() method
    IOReturn ret = pe->setConsoleInfo(&consoleInfo, kPEAcquireScreen);
    ret |= pe->setConsoleInfo(&consoleInfo, kPEGraphicsMode);
    ret |= pe->setConsoleInfo(&consoleInfo, kPEEnableScreen);
    if (ret != kIOReturnSuccess) {
        DEBUG("setConsoleInfo failed: %d\n", ret);
        // Don't fail - we can still register the service even if console init fails
    } else {
        DEBUG("Kernel graphics console initialized\n");
    }

#if defined(RAVYN_ARM64_STATIC_IOGRAPHICS)
    /*
     * Acquiring graphics mode intentionally discards the terminal buffers.
     * This raw-kernel target has no later display-driver open to select the
     * verbose console, so complete that standard transition here when asked.
     */
    if (PE_parse_boot_argn("-v", NULL, 0)) {
        ret = pe->setConsoleInfo(NULL, kPETextScreen);
        DEBUG("Verbose text console selected: 0x%x\n", ret);
    }
#endif

    setupForCurrentConfig(); // full setup
    registerService();
    return true;
}

void
IOGOPFramebuffer::stop(IOService *provider)
{
    DEBUG("stop %p\n", provider);
    super::stop(provider);
}

void * IOGOPFramebuffer::getBaseAddress(void) { return fbBase; }
uint32_t IOGOPFramebuffer::getWidth(void) { return width; }
uint32_t IOGOPFramebuffer::getHeight(void) { return height; }
uint32_t IOGOPFramebuffer::getPitch(void) { return pitch; }
uint32_t IOGOPFramebuffer::getDepth(void) { return bpp; }


IOReturn
IOGOPFramebuffer::enableController()
{
    return kIOReturnSuccess;
}

IOReturn
IOGOPFramebuffer::getAttributeForConnection(IOIndex connectIndex,
                                           IOSelect attribute, uintptr_t *value)
{
    if (connectIndex != 0 || !value)
        return kIOReturnBadArgument;
    switch (attribute) {
        case kConnectionFlags:
            /* Fixed GOP scanout, without built-in-panel or stereo features. */
            *value = 0;
            return kIOReturnSuccess;
        case kConnectionEnable:
        case kConnectionCheckEnable:
            /* The single firmware-provided scanout is already active. */
            *value = 1;
            return kIOReturnSuccess;
        default:
            return super::getAttributeForConnection(connectIndex, attribute, value);
    }
}

const char *
IOGOPFramebuffer::getPixelFormats()
{
    const char *        ret;
    PE_Video            bootDisplay;

    getPlatform()->getConsoleInfo( &bootDisplay);

    switch (bootDisplay.v_depth)
    {
        case 8:
        default:
            ret = IO8BitIndexedPixels;
            break;
        case 15:
        case 16:
            ret = IO16BitDirectPixels;
            break;
        case 24:
        case 32:
            ret = IO32BitDirectPixels;
            break;
    }

    return (ret);
}

IOReturn
IOGOPFramebuffer::getCurrentDisplayMode(IODisplayModeID * displayMode,
                                        IOIndex         * depth)
{
    if (displayMode) *displayMode = kDisplayModeID;
    if (depth) *depth = kDepthIndex;
    DEBUG("current mode=%u depth-index=%u\n", kDisplayModeID, kDepthIndex);
    return kIOReturnSuccess;
}

IOReturn
IOGOPFramebuffer::setDisplayMode(IODisplayModeID displayMode,
                                 IOIndex depth)
{
    return (displayMode == kDisplayModeID && depth == kDepthIndex)
        ? kIOReturnSuccess : kIOReturnUnsupportedMode;
}

IODeviceMemory *
IOGOPFramebuffer::getApertureRange(IOPixelAperture)
{
    return IODeviceMemory::withRange(
        (mach_vm_address_t)fbBase,
        pitch * height
    );
}

IOReturn
IOGOPFramebuffer::getInformationForDisplayMode(IODisplayModeID displayMode,
                                               IODisplayModeInformation * info)
{
    if (!info)
        return kIOReturnBadArgument;
    if (displayMode != kDisplayModeID)
        return kIOReturnUnsupportedMode;
    bzero(info, sizeof(*info));

    info->nominalWidth  = width;
    info->nominalHeight = height;
    info->refreshRate   = 60 << 16;

    info->maxDepthIndex = kDepthIndex;
    /* This is the firmware-selected, currently scanning-out fixed mode. */
    info->flags = kDisplayModeValidFlag | kDisplayModeSafeFlag | kDisplayModeDefaultFlag;

    return kIOReturnSuccess;
}

UInt64
IOGOPFramebuffer::getPixelFormatsForDisplayMode(IODisplayModeID displayMode,
                                                IOIndex depth)
{
    // Bit zero selects the first format returned by getPixelFormats().
    return (displayMode == kDisplayModeID && depth == kDepthIndex) ? 1ULL : 0ULL;
}

IOItemCount
IOGOPFramebuffer::getDisplayModeCount(void)
{
    return 1;
}

IOReturn
IOGOPFramebuffer::getDisplayModes(IODisplayModeID * allDisplayModes)
{
    *allDisplayModes = kDisplayModeID;
    return kIOReturnSuccess;
}

IOReturn
IOGOPFramebuffer::getPixelInformation(IODisplayModeID      displayMode,
                                      IOIndex              depth,
                                      IOPixelAperture      aperture,
                                      IOPixelInformation * info)
{
    PE_Video    bootDisplay;

    if (aperture || depth || (displayMode != kDisplayModeID))
    {
        return (kIOReturnUnsupportedMode);
    }

    getPlatform()->getConsoleInfo( &bootDisplay);

    bzero( info, sizeof(*info));

    info->activeWidth           = static_cast<UInt32>(bootDisplay.v_width);
    info->activeHeight          = static_cast<UInt32>(bootDisplay.v_height);
    info->bytesPerRow           = bootDisplay.v_rowBytes & 0x7fff;
    info->bytesPerPlane         = 0;

    switch (bootDisplay.v_depth)
    {
        case 8:
        default:
            strlcpy(info->pixelFormat, IO8BitIndexedPixels, sizeof(info->pixelFormat));
            info->pixelType             = kIOCLUTPixels;
            info->componentMasks[0]     = 0xff;
            info->bitsPerPixel          = 8;
            info->componentCount        = 1;
            info->bitsPerComponent      = 8;
            break;
        case 15:
        case 16:
            strlcpy(info->pixelFormat, IO16BitDirectPixels, sizeof(info->pixelFormat));
            info->pixelType     = kIORGBDirectPixels;
            info->componentMasks[0] = 0x7c00;
            info->componentMasks[1] = 0x03e0;
            info->componentMasks[2] = 0x001f;
            info->bitsPerPixel  = 16;
            info->componentCount        = 3;
            info->bitsPerComponent      = 5;
            break;
        case 24:
        case 32:
            strlcpy(info->pixelFormat, IO32BitDirectPixels, sizeof(info->pixelFormat));
            info->pixelType     = kIORGBDirectPixels;
            info->componentMasks[0] = 0x00ff0000;
            info->componentMasks[1] = 0x0000ff00;
            info->componentMasks[2] = 0x000000ff;
            info->bitsPerPixel  = 32;
            info->componentCount        = 3;
            info->bitsPerComponent      = 8;
            break;
    }

    return (kIOReturnSuccess);
}

bool IOGOPFramebuffer::isConsoleDevice( void )
{
    return true;
}

