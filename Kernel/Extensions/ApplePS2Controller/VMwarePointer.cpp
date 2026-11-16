// VMware absolute-pointer protocol adapter. Local implementation; see PROVENANCE.md.
#include "VMwarePointer.h"

namespace {
const UInt32 magic = 0x564d5868;
struct Registers { UInt32 a, b, c, d; };
Registers call(UInt32 command, UInt32 argument, UInt32 initialB = 0)
{
    Registers r = {magic, argument, command, 0x5658};
    if (initialB) r.b = initialB;
    UInt32 si = 0, di = 0;
    __asm__ volatile("inl %%dx, %%eax" : "+a"(r.a), "+b"(r.b),
                     "+c"(r.c), "+d"(r.d), "+S"(si), "+D"(di) : : "memory");
    return r;
}
bool isVMware()
{
    UInt32 a = 0x40000000, b, c, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    return b == 0x61774d56 && c == 0x4d566572 && d == 0x65726177;
}
}

bool VMwarePointerEnable()
{
    if (!isVMware()) return false;
    Registers version = call(10, 0, ~magic);
    if (version.b != magic || version.a == 0xffffffff) return false;
    call(41, 0x45414552); // Request protocol identification.
    UInt32 status = call(40, 0).a;
    if ((status & 0xffff0000) == 0xffff0000 || !(status & 0xffff)) {
        VMwarePointerDisable();
        return false;
    }
    if (call(39, 1).a != 0x3442554a) {
        VMwarePointerDisable();
        return false;
    }
    call(41, 0x53424152); // Absolute mode, 16-bit coordinates.
    return true;
}

void VMwarePointerDisable() { call(41, 0xf5); }

int VMwarePointerRead(VMwarePointerEvent *event)
{
    UInt32 status = call(40, 0).a;
    UInt32 words = status & 0xffff;
    if ((status & 0xffff0000) == 0xffff0000 || words % 4) return -1;
    if (!words) return 0;
    Registers data = call(39, 4);
    event->flags = data.a;
    event->x = data.b;
    event->y = data.c;
    event->wheel = static_cast<SInt8>(data.d & 0xff);
    return 1;
}
