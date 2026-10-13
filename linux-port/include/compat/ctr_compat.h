/*
 * Nintendo 3DS compatibility layer -- API boundary between reconstructed original
 * code and Linux. CLASSIFICATION: Linux compatibility implementation (newly written;
 * NOT recovered original code). Only behaviour the eShop binary is observed to need is
 * provided; everything else reports Unsupported (see docs/COMPAT_LAYER.md).
 */
#ifndef ESHOP_COMPAT_CTR_H
#define ESHOP_COMPAT_CTR_H

#include <cstdint>
#include <string>
#include <vector>

namespace ctr {

constexpr int kTopWidth = 400, kTopHeight = 240;
constexpr int kBottomWidth = 320, kBottomHeight = 240;

// libctru-compatible button bits (HID pad register layout).
enum Button : uint32_t {
    KEY_A = 1u << 0, KEY_B = 1u << 1, KEY_SELECT = 1u << 2, KEY_START = 1u << 3,
    KEY_DRIGHT = 1u << 4, KEY_DLEFT = 1u << 5, KEY_DUP = 1u << 6, KEY_DDOWN = 1u << 7,
    KEY_R = 1u << 8, KEY_L = 1u << 9, KEY_X = 1u << 10, KEY_Y = 1u << 11,
};

// Result codes: 0 = success; the negative-bit pattern follows the 3DS convention
// (bit31 set = failure). Only the codes below are used.
using Result = int32_t;
constexpr Result kResultSuccess = 0;
constexpr Result kResultUnsupported = static_cast<Result>(0xD8E007F7);  // "not implemented" style code

struct Framebuffer {
    int width = 0, height = 0;
    std::vector<uint32_t> pixels;  // 0xAARRGGBB, row-major, top-left origin
    void resize(int w, int h) { width = w; height = h; pixels.assign(size_t(w) * h, 0xFF000000u); }
};

struct HidState {
    uint32_t held = 0, down = 0, up = 0;
    bool touching = false;
    int touch_x = 0, touch_y = 0;  // bottom-screen coordinates 0..319 / 0..239
};

// Services named by strings in the original executable (see docs/LINUX_PORT_AUDIT.md).
struct ServiceInfo { const char* name; bool supported; const char* note; };
const std::vector<ServiceInfo>& service_table();

class Platform {
public:
    Result init();
    void shutdown();
    bool initialized() const { return initialized_; }

    // Display (gfxInit / gfxGetFramebuffer analogue).
    Framebuffer& top() { return top_; }
    Framebuffer& bottom() { return bottom_; }

    // Input (hidScanInput analogue). Raw state is pushed in by the frontend.
    void hid_set_held(uint32_t buttons);
    void hid_set_touch(bool touching, int x, int y);
    const HidState& hid() const { return hid_; }
    void hid_scan();  // computes down/up edges

    // Timing (svcGetSystemTick analogue; ARM11 tick rate 268,111,856 Hz).
    static constexpr uint64_t kTicksPerSecond = 268111856ull;
    uint64_t system_tick() const;

    // Service access (srvGetServiceHandle analogue): only logs + reports status.
    Result open_service(const std::string& name) const;

    // Filesystem roots (fs:USER save data / cache analogue), created under $XDG_DATA_HOME.
    std::string save_dir() const { return save_dir_; }

private:
    bool initialized_ = false;
    Framebuffer top_, bottom_;
    HidState hid_;
    uint32_t prev_held_ = 0, raw_held_ = 0;
    bool raw_touch_ = false; int raw_tx_ = 0, raw_ty_ = 0;
    std::string save_dir_;
    uint64_t start_ns_ = 0;
};

} // namespace ctr
#endif
