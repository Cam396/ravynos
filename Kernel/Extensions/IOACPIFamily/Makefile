MK_WERROR = no
SUBDIR =
ACPI_COMPONENT ?= combined
.if ${ACPI_COMPONENT} == "platform"
KEXT = RavynACPIPlatform
INFO_PLIST = Info-PlatformOnly.plist
BUNDLE_IDENTIFIER = com.ravynos.driver.ACPIPlatform
.else
KEXT = IOACPIFamily
.endif
INFO_PLIST ?= Info.plist
BUNDLE_IDENTIFIER ?= com.apple.iokit.IOACPIFamily
BUNDLE_VERSION = 1.0.0
KERNEL_PRIVATE = yes

SRCS = ACPIRTC.cpp \
	EFINVRAM.cpp \
	ACPICPU.cpp \
	ACPIPCIBridge.cpp \
	ACPIPlatformExpert.cpp \
	IOACPIPlatformDevice.cpp \
	util.cpp

.if ${ACPI_COMPONENT} == "platform"
SRCS := ${SRCS:NIOACPIPlatformDevice.cpp}
.endif

CFLAGS = -Wno-implicit-int-conversion -Wno-sign-conversion \
	-I${.CURDIR}/include \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/iokit \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/osfmk \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/bsd \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/libkern \
	-I${ROOT_BINARY_DIR}${ROOT_SOURCE_DIR}/Kernel/xnu/EXPORT_HDRS/osfmk \
	-I${ROOT_BINARY_DIR}${ROOT_SOURCE_DIR}/Kernel/xnu/EXPORT_HDRS \
	-I${ROOT_SOURCE_DIR}/Kernel/xnu/EXTERNAL_HEADERS \
	-I${.CURDIR:H}/IOPCIFamily \
	-I${.CURDIR:H}/AppleAPIC \
	-I${.CURDIR:H}/RavynAHCIPort \
	-I${.CURDIR:H}/ApplePS2Controller

.if ${ACPI_COMPONENT} == "platform"
CFLAGS += -DRAVYN_APPLE_ACPI_INTERFACE=1
.endif

LDFLAGS = -mmacos-version-min=${MACOS_VERSION_MIN} --sysroot=${RAVYN_SDKROOT} \
	-fuse-ld=${LD}

.include <rvn.kext.mk>
