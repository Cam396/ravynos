/* Native legacy IOHIPointing -> NX event adapter for the reduced HID build.
 * Runs on IOHIDSystem's command gate and uses its existing cursor and queue APIs.
 * Standard pointing callbacks/EV button numbering follow Apple's IOHIDFamily.
 */
struct IOHIDSystem::LegacyPointerEvent {
    int buttons, dx, dy;
    bool absolute, scroll;
    IOGPoint position;
    IOGBounds bounds;
    NXEventData data;
    AbsoluteTime time;
    OSObject *sender;
};

void IOHIDSystem::legacyRelativePointer(OSObject *target, int buttons, int dx, int dy,
                                        AbsoluteTime time, OSObject *sender, void *)
{
    IOHIDSystem *self = static_cast<IOHIDSystem *>(target);
    LegacyPointerEvent event = {};
    event.buttons = buttons; event.dx = dx; event.dy = dy;
    event.time = time; event.sender = sender;
    self->cmdGate->runAction(legacyPointerGated, &event);
}

void IOHIDSystem::legacyAbsolutePointer(OSObject *target, int buttons, IOGPoint *position,
        IOGBounds *bounds, bool proximity, int, int, AbsoluteTime time, OSObject *sender, void *)
{
    if (!proximity || !position || !bounds) return;
    IOHIDSystem *self = static_cast<IOHIDSystem *>(target);
    LegacyPointerEvent event = {};
    event.buttons = buttons; event.absolute = true;
    event.position = *position; event.bounds = *bounds;
    event.time = time; event.sender = sender;
    self->cmdGate->runAction(legacyPointerGated, &event);
}

void IOHIDSystem::legacyScrollWheel(OSObject *target, short a, short b, short c,
        IOFixed fa, IOFixed fb, IOFixed fc, SInt32 pa, SInt32 pb, SInt32 pc,
        SInt32, AbsoluteTime time, OSObject *sender, void *)
{
    IOHIDSystem *self = static_cast<IOHIDSystem *>(target);
    LegacyPointerEvent event = {};
    event.scroll = true; event.time = time; event.sender = sender;
    event.data.scrollWheel.deltaAxis1 = a; event.data.scrollWheel.deltaAxis2 = b;
    event.data.scrollWheel.deltaAxis3 = c;
    event.data.scrollWheel.fixedDeltaAxis1 = fa; event.data.scrollWheel.fixedDeltaAxis2 = fb;
    event.data.scrollWheel.fixedDeltaAxis3 = fc;
    event.data.scrollWheel.pointDeltaAxis1 = pa; event.data.scrollWheel.pointDeltaAxis2 = pb;
    event.data.scrollWheel.pointDeltaAxis3 = pc;
    self->cmdGate->runAction(legacyPointerGated, &event);
}

IOReturn IOHIDSystem::legacyPointerGated(OSObject *target, void *argument, void *, void *, void *)
{
    IOHIDSystem *self = static_cast<IOHIDSystem *>(target);
    LegacyPointerEvent &event = *static_cast<LegacyPointerEvent *>(argument);
    if (self->_privateData->legacyPointerLogged++ < 12)
        IOLog("IOHIDSystem: native pointer eventsOpen=%d queues=%u absolute=%d buttons=%d\n",
              self->eventsOpen, self->dataQueueSet ? self->dataQueueSet->getCount() : 0,
              event.absolute, event.buttons);
    if (!self->eventsOpen) return kIOReturnNotOpen;
    self->updateHidActivity();
    // Keep the current coupling decision observable while diagnosing the
    // native legacy path. Do not override WindowServer cursor ownership.
    OSObject *coupled = self->cursorCoupled ? kOSBooleanTrue : kOSBooleanFalse;
    if (self->getProperty("RavynLegacyCursorCoupled") != coupled)
        self->setProperty("RavynLegacyCursorCoupled", coupled);
    if (!event.scroll) {
        IOGPoint old = {self->evg->cursorLoc.x, self->evg->cursorLoc.y};
        // Derive the desktop union from live registrations. The reduced
        // build's cached workspace is not updated by virtual-display bounds.
        IOGBounds screen = {};
        bool haveScreen = false;
        for (unsigned i = 0; i < EV_MAX_SCREENS; ++i) {
            IOGBounds *bounds = static_cast<EvScreen *>(self->evScreen)[i].desktopBounds;
            if (!bounds || bounds->maxx - bounds->minx < 2 || bounds->maxy - bounds->miny < 2) continue;
            if (!haveScreen) { screen = *bounds; haveScreen = true; }
            else {
                if (bounds->minx < screen.minx) screen.minx = bounds->minx;
                if (bounds->miny < screen.miny) screen.miny = bounds->miny;
                if (bounds->maxx > screen.maxx) screen.maxx = bounds->maxx;
                if (bounds->maxy > screen.maxy) screen.maxy = bounds->maxy;
            }
        }
        if (self->_privateData->legacyPointerLogged < 12)
            IOLog("IOHIDSystem: live desktop bounds (%d,%d)-(%d,%d), screens=%d\n", screen.minx, screen.miny, screen.maxx, screen.maxy, self->screens);
        if (!haveScreen) return kIOReturnNotReady;
        SInt64 x = static_cast<SInt64>(old.x) + event.dx;
        SInt64 y = static_cast<SInt64>(old.y) + event.dy;
        if (event.absolute) {
            SInt32 width = event.bounds.maxx - event.bounds.minx;
            SInt32 height = event.bounds.maxy - event.bounds.miny;
            if (width <= 0 || height <= 0) return kIOReturnBadArgument;
            x = screen.minx + static_cast<SInt64>(event.position.x - event.bounds.minx) *
                (screen.maxx - screen.minx - 1) / width;
            y = screen.miny + static_cast<SInt64>(event.position.y - event.bounds.miny) *
                (screen.maxy - screen.miny - 1) / height;
        }
        if (x < screen.minx) x = screen.minx;
        if (x >= screen.maxx) x = screen.maxx - 1;
        if (y < screen.miny) y = screen.miny;
        if (y >= screen.maxy) y = screen.maxy - 1;
        IOGPoint position = {static_cast<SInt16>(x), static_cast<SInt16>(y)};
        self->setCursorPosition(&position, false, event.sender);
        IOGPoint current = {self->evg->cursorLoc.x, self->evg->cursorLoc.y};
        // An uncoupled cursor is positioned by WindowServer. _setCursorPosition
        // deliberately restores its shared location in that mode, so comparing
        // only current with old drops every physical movement. Preserve the
        // requested device delta and let the server perform its normal update.
        bool uncoupledMove = !self->cursorCoupled &&
            (position.x != old.x || position.y != old.y);
        if (current.x != old.x || current.y != old.y || uncoupledMove) {
            NXEventData data = {};
            data.mouseMove.dx = uncoupledMove ? position.x - old.x : current.x - old.x;
            data.mouseMove.dy = uncoupledMove ? position.y - old.y : current.y - old.y;
            int type = (event.buttons & EV_LB) ? NX_LMOUSEDRAGGED :
                       (event.buttons & EV_RB) ? NX_RMOUSEDRAGGED : NX_MOUSEMOVED;
            self->postEvent(type, &self->_privateData->cursorHelper.desktopLocation(), event.time, &data, event.sender);
        }
        UInt32 oldButtons = self->evg->buttons;
        UInt32 changed = oldButtons ^ event.buttons;
        if (changed) {
            NXEventData auxiliary = {};
            auxiliary.compound.subType = NX_SUBTYPE_AUX_MOUSE_BUTTONS;
            UInt32 hardware = (event.buttons & ~7) | ((event.buttons & EV_LB) ? 1 : 0) |
                ((event.buttons & EV_RB) ? 2 : 0) | ((event.buttons & 2) ? 4 : 0);
            UInt32 hardwareChanged = (changed & ~7) | ((changed & EV_LB) ? 1 : 0) |
                ((changed & EV_RB) ? 2 : 0) | ((changed & 2) ? 4 : 0);
            auxiliary.compound.misc.L[0] = hardwareChanged;
            auxiliary.compound.misc.L[1] = hardware;
            self->evg->buttons = event.buttons;
            self->postEvent(NX_SYSDEFINED, &self->_privateData->cursorHelper.desktopLocation(), event.time, &auxiliary, event.sender);
            for (unsigned button = 0; button < 2; ++button) {
                UInt32 mask = button ? EV_RB : EV_LB;
                if (!(changed & mask)) continue;
                bool down = event.buttons & mask;
                if (down) {
                    UInt64 ns; absolutetime_to_nanoseconds(event.time, &ns);
                    IOGPoint previous = self->_privateData->legacyClickLocation[button];
                    bool near = abs(current.x - previous.x) <= 4 && abs(current.y - previous.y) <= 4;
                    UInt64 last = self->_privateData->legacyClickTime[button];
                    self->_privateData->legacyClickCount[button] =
                        last && ns >= last && ns - last <= 500000000 && near ?
                        self->_privateData->legacyClickCount[button] + 1 : 1;
                    self->_privateData->legacyClickTime[button] = ns;
                    self->_privateData->legacyClickLocation[button] = current;
                    if (++self->evg->eNum <= 0) self->evg->eNum = 1;
                    self->_privateData->legacyButtonEvent[button] = self->evg->eNum;
                }
                NXEventData data = {};
                data.mouse.buttonNumber = button;
                data.mouse.click = self->_privateData->legacyClickCount[button];
                data.mouse.eventNum = self->_privateData->legacyButtonEvent[button];
                data.mouse.pressure = down ? 255 : 0;
                int type = button ? (down ? NX_RMOUSEDOWN : NX_RMOUSEUP) : (down ? NX_LMOUSEDOWN : NX_LMOUSEUP);
                self->postEvent(type, &self->_privateData->cursorHelper.desktopLocation(), event.time, &data, event.sender);
            }
        }
    } else {
        self->postEvent(NX_SCROLLWHEELMOVED, &self->_privateData->cursorHelper.desktopLocation(), event.time, &event.data, event.sender);
    }
    self->scheduleNextPeriodicEvent();
    return kIOReturnSuccess;
}
