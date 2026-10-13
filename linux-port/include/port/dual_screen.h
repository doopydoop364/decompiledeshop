/* Dual-screen window layout + software compositor. Newly written (port infrastructure). */
#ifndef ESHOP_PORT_DUAL_SCREEN_H
#define ESHOP_PORT_DUAL_SCREEN_H

#include "compat/ctr_compat.h"

namespace port {

struct Rect { int x = 0, y = 0, w = 0, h = 0; bool contains(int px, int py) const { return px >= x && py >= y && px < x + w && py < y + h; } };

struct Layout {
    Rect top, bottom;  // in window pixels
    int scale = 1;     // pixel multiplier (integer mode) -- fractional mode sets scale_f
    float scale_f = 1.0f;
};

// Stacked layout: top screen (400x240) above bottom (320x240) centred under it, as on the
// handheld. integer_scale=true floors to a whole multiplier (>=1); false fits the window
// exactly, preserving aspect ratio. `forced_scale` > 0 overrides auto-fit (integer only).
Layout compute_layout(int window_w, int window_h, bool integer_scale, int forced_scale = 0);

// Maps window coords to bottom-screen touch coords; false if outside the bottom screen.
bool window_to_touch(const Layout& l, int wx, int wy, int* tx, int* ty);

// Nearest-neighbour compose of both framebuffers into `out` (window_w x window_h, 0xAARRGGBB).
void compose(const Layout& l, const ctr::Framebuffer& top, const ctr::Framebuffer& bottom,
             ctr::Framebuffer& out);

} // namespace port
#endif
