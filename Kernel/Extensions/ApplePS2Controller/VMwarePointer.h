// VMware absolute-pointer protocol adapter. Local implementation; see PROVENANCE.md.
#ifndef RAVYN_VMWARE_POINTER_H
#define RAVYN_VMWARE_POINTER_H
#include <IOKit/IOTypes.h>
struct VMwarePointerEvent { UInt32 flags, x, y; SInt32 wheel; };
bool VMwarePointerEnable();
void VMwarePointerDisable();
// 1 = event, 0 = empty, -1 = invalid/error status.
int VMwarePointerRead(VMwarePointerEvent *event);
#endif
