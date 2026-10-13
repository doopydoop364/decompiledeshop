// Linux implementation of the 3DS compatibility layer. Newly written (not original code).
#include "compat/ctr_compat.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <system_error>

namespace ctr {

static uint64_t now_ns() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Service names found as literals in the decompressed executable. Support reflects what
// this port currently provides, not what the original needs for full functionality.
const std::vector<ServiceInfo>& service_table() {
    static const std::vector<ServiceInfo> t = {
        {"fs:USER", true,  "mapped to a host directory (save_dir)"},
        {"hid:USER", true, "keyboard/mouse via frontend"},
        {"srv:", true,     "no-op; handles are not modelled"},
        {"APT:U", false,   "applet manager: needs home-menu/sleep semantics"},
        {"cfg:u", false,   "console config (language/country): stubbed values TBD"},
        {"http:C", false,  "HTTP client; backend replacement planned (docs/ROADMAP.md)"},
        {"ac:u", false,    "Wi-Fi connection manager"},
        {"act:u", false,   "Nintendo Network ID accounts -- deliberately NOT implemented"},
        {"am:sys", false,  "title management / installs -- deliberately NOT implemented"},
        {"nim:s", false,   "download/install service -- deliberately NOT implemented"},
        {"boss:U", false,  "SpotPass"},
        {"frd:u", false,   "friends"},
        {"cam:u", false,   "camera (QR scanning)"},
        {"y2r:u", false,   "YUV->RGB converter"},
        {"ptm:u", false,   "power/play-time"},
        {"ndm:u", false,   "network daemon manager"},
        {"fs:LDR", false,  "loader file access (RomFS/ExeFS)"},
    };
    return t;
}

Result Platform::init() {
    if (initialized_) return kResultSuccess;
    top_.resize(kTopWidth, kTopHeight);
    bottom_.resize(kBottomWidth, kBottomHeight);
    const char* xdg = std::getenv("XDG_DATA_HOME");
    const char* home = std::getenv("HOME");
    std::string base = xdg && *xdg ? std::string(xdg) : (home ? std::string(home) + "/.local/share" : ".");
    save_dir_ = base + "/eshop-linux-port";
    std::error_code ec;
    std::filesystem::create_directories(save_dir_, ec);
    start_ns_ = now_ns();
    initialized_ = true;
    return kResultSuccess;
}

void Platform::shutdown() { initialized_ = false; }

void Platform::hid_set_held(uint32_t b) { raw_held_ = b; }
void Platform::hid_set_touch(bool t, int x, int y) { raw_touch_ = t; raw_tx_ = x; raw_ty_ = y; }

void Platform::hid_scan() {
    hid_.held = raw_held_;
    hid_.down = raw_held_ & ~prev_held_;
    hid_.up = ~raw_held_ & prev_held_;
    prev_held_ = raw_held_;
    hid_.touching = raw_touch_;
    if (raw_touch_) { hid_.touch_x = raw_tx_; hid_.touch_y = raw_ty_; }
}

uint64_t Platform::system_tick() const {
    uint64_t ns = now_ns() - start_ns_;
    return (ns / 1000000000ull) * kTicksPerSecond + (ns % 1000000000ull) * kTicksPerSecond / 1000000000ull;
}

Result Platform::open_service(const std::string& name) const {
    for (const auto& s : service_table())
        if (name == s.name) return s.supported ? kResultSuccess : kResultUnsupported;
    return kResultUnsupported;
}

} // namespace ctr
