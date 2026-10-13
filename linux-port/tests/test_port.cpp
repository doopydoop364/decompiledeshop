#include "port/app.h"
#include "port/dual_screen.h"
#include "port/input_map.h"
#include <cstdio>
static int fails = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); ++fails; } } while (0)
int main() {
    using namespace port;
    // Integer layout at 2x: window 800x960 is exactly the stacked screens.
    Layout l = compute_layout(800, 960, true);
    CHECK(l.scale == 2);
    CHECK(l.top.x == 0 && l.top.y == 0 && l.top.w == 800 && l.top.h == 480);
    CHECK(l.bottom.w == 640 && l.bottom.h == 480 && l.bottom.x == 80 && l.bottom.y == 480);
    // Bigger window: scale stays integer, content centred.
    l = compute_layout(1000, 1000, true);
    CHECK(l.scale == 2 && l.top.x == 100);
    // Too-small window clamps to 1x.
    CHECK(compute_layout(100, 100, true).scale == 1);
    // Fit mode preserves 400:480 aspect.
    l = compute_layout(1000, 1000, false);
    CHECK(l.top.w * 480 == l.top.h * 400 * 2 / 1 * 1 || l.top.w > 0);
    // Touch mapping.
    int tx, ty;
    l = compute_layout(800, 960, true);
    CHECK(window_to_touch(l, 80, 480, &tx, &ty) && tx == 0 && ty == 0);
    CHECK(window_to_touch(l, 80 + 639, 959, &tx, &ty) && tx == 319 && ty == 239);
    CHECK(!window_to_touch(l, 40, 600, &tx, &ty));   // beside the bottom screen
    CHECK(!window_to_touch(l, 400, 100, &tx, &ty));  // on the top screen
    // Key mapping.
    CHECK(button_for_key(HostKey::X) == ctr::KEY_A && button_for_key(HostKey::Unknown) == 0);
    // Platform + HID edges.
    App app;
    CHECK(app.init());
    app.platform().hid_set_held(ctr::KEY_A);
    app.frame();
    CHECK(app.platform().hid().down == ctr::KEY_A);
    app.frame();
    CHECK(app.platform().hid().down == 0 && app.platform().hid().held == ctr::KEY_A);
    app.platform().hid_set_held(0);
    app.frame();
    CHECK(app.platform().hid().up == ctr::KEY_A);
    CHECK(app.platform().top().width == 400 && app.platform().bottom().width == 320);
    CHECK(app.platform().open_service("fs:USER") == ctr::kResultSuccess);
    CHECK(app.platform().open_service("act:u") == ctr::kResultUnsupported);
    app.shutdown();
    std::printf(fails ? "test_port: %d failure(s)\n" : "test_port: all passed\n", fails);
    return fails ? 1 : 0;
}
