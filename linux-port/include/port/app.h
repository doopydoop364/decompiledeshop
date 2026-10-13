/* Application shell: owns the compat Platform and drives one frame at a time. */
#ifndef ESHOP_PORT_APP_H
#define ESHOP_PORT_APP_H
#include "compat/ctr_compat.h"
#include <cstdint>

namespace port {

// BRING-UP SCREEN: newly written substitute UI (NOT the original eShop interface).
// It routes all string handling through reconstructed original routines
// (eshop_orig::cstring_* / string16_length) so those are exercised end to end.
class App {
public:
    bool init();
    void frame();            // hid_scan + render both screens
    void shutdown();
    ctr::Platform& platform() { return plat_; }
    uint64_t frame_count() const { return frames_; }
private:
    ctr::Platform plat_;
    uint64_t frames_ = 0;
};

// 5x7 bitmap font drawing (newly written; glcd-style font table).
void draw_text(ctr::Framebuffer& fb, int x, int y, const char* text, uint32_t argb, int scale = 1);

} // namespace port
#endif
