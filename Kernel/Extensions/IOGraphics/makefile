MK_WERROR = no
SUBDIR =
KEXT = IOGOPFramebuffer
KERNEL_PRIVATE = yes
INFO_PLIST = Info-IOGOPFramebuffer.plist
BUNDLE_IDENTIFIER = com.ravynos.iokit.IOGOPFramebuffer
BUNDLE_VERSION = 1.0.0
MAIN_FUNCTION = IOGraphicsFamilyModuleStart

CSTD = gnu11
CXXSTD = gnu++14

.PATH: ${.CURDIR}/IOGraphicsFamily
.PATH: ${ROOT_SOURCE_DIR}/Developer/Default.xctoolchain/lzvndecode
SRCS = IOGOPFramebuffer.cpp \
        IOGraphicsDevice.cpp \
        IOBootFramebuffer.cpp \
        IOFramebuffer.cpp \
        IOI2CInterface.cpp \
        IODisplay.cpp \
        IODisplayWrangler.cpp \
        IOBacklightDisplay.cpp \
        IOKit/graphics/tl/osmemory.cpp \
        IOFramebufferUserClient.cpp \
        IODisplayWranglerUserClients.cpp \
        GMetric/GMetric.cpp \
        lzvn_decode.c

SLF = /System/Library/Frameworks
CFLAGS = -DKERNEL -DPRIVATE \
        -Wno-implicit-int-conversion -Wno-sign-conversion \
	-Wno-c++11-narrowing \
        -I${.CURDIR}/IOGraphicsFamily \
        -I${.CURDIR:H}/IOHIDFamily/IOHIDSystem \
        -I${.CURDIR}/IOGraphicsFamily/IOKit/graphics/tl \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/iokit \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/osfmk \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/bsd \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/libkern \
	-I${.CURDIR:H}/IOPCIFamily \
	-I${.CURDIR:H}/IOACPIFamily/include \
        -I${.CURDIR}/GTrace/Kernel -I${.CURDIR}/GMetric -I${.CURDIR} \
        -I${.CURDIR}/IONDRVSupport \
        -I${ROOT_SOURCE_DIR}/Developer/Default.xctoolchain/lzvndecode \
	-I${ROOT_BINARY_DIR}${ROOT_SOURCE_DIR}/Kernel/xnu/EXPORT_HDRS/osfmk \
	-I${ROOT_BINARY_DIR}${ROOT_SOURCE_DIR}/Kernel/xnu/EXPORT_HDRS/libkern \
	-I${ROOT_BINARY_DIR}${ROOT_SOURCE_DIR}/Kernel/xnu/EXPORT_HDRS/san \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/EXTERNAL_HEADERS
CFLAGS += -include${.CURDIR}/shims.h

# Keep the combined bootstrap driver available, but provide a proper family
# and hardware-driver split for Apple's graphics clients and dependent kexts.
GRAPHICS_COMPONENT ?= combined
.if ${GRAPHICS_COMPONENT} == "family"
KEXT = IOGraphicsFamily
INFO_PLIST = IOGraphicsFamily/Info.plist
BUNDLE_IDENTIFIER = com.apple.iokit.IOGraphicsFamily
BUNDLE_VERSION = 576.1
SRCS := ${SRCS:NIOGOPFramebuffer.cpp}
.elif ${GRAPHICS_COMPONENT} == "gop"
INFO_PLIST = Info-IOGOPOnly.plist
SRCS = IOGOPFramebuffer.cpp
.undef MAIN_FUNCTION
.elif ${GRAPHICS_COMPONENT} != "combined"
.error Unsupported GRAPHICS_COMPONENT
.endif

.include <rvn.kext.mk>
.include <bsd.subdir.mk>
