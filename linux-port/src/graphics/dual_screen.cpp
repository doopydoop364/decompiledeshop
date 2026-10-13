#include "port/dual_screen.h"

#include <algorithm>

namespace port {

Layout compute_layout(int ww, int wh, bool integer_scale, int forced) {
    Layout l;
    const int lw = ctr::kTopWidth, lh = ctr::kTopHeight + ctr::kBottomHeight;
    if (ww < 1) ww = 1;
    if (wh < 1) wh = 1;
    int sw, sh, s = 1;
    if (integer_scale) {
        s = forced > 0 ? forced : std::max(1, std::min(ww / lw, wh / lh));
        sw = lw * s; sh = lh * s;
        l.scale = s; l.scale_f = (float)s;
    } else {
        float f = std::min((float)ww / lw, (float)wh / lh);
        sw = std::max(1, (int)(lw * f)); sh = std::max(1, (int)(lh * f));
        l.scale_f = f; l.scale = std::max(1, (int)f);
    }
    int ox = (ww - sw) / 2, oy = (wh - sh) / 2;
    int topH = (sh * ctr::kTopHeight) / lh;
    int botW = (sw * ctr::kBottomWidth) / lw;
    l.top = {ox, oy, sw, topH};
    l.bottom = {ox + (sw - botW) / 2, oy + topH, botW, sh - topH};
    return l;
}

bool window_to_touch(const Layout& l, int wx, int wy, int* tx, int* ty) {
    if (!l.bottom.contains(wx, wy)) return false;
    int x = (wx - l.bottom.x) * ctr::kBottomWidth / l.bottom.w;
    int y = (wy - l.bottom.y) * ctr::kBottomHeight / l.bottom.h;
    *tx = std::clamp(x, 0, ctr::kBottomWidth - 1);
    *ty = std::clamp(y, 0, ctr::kBottomHeight - 1);
    return true;
}

static void blit(const Rect& r, const ctr::Framebuffer& src, ctr::Framebuffer& out) {
    for (int y = 0; y < r.h; ++y) {
        int oy = r.y + y;
        if (oy < 0 || oy >= out.height) continue;
        int sy = y * src.height / r.h;
        for (int x = 0; x < r.w; ++x) {
            int ox = r.x + x;
            if (ox < 0 || ox >= out.width) continue;
            out.pixels[size_t(oy) * out.width + ox] = src.pixels[size_t(sy) * src.width + x * src.width / r.w];
        }
    }
}

void compose(const Layout& l, const ctr::Framebuffer& top, const ctr::Framebuffer& bottom,
             ctr::Framebuffer& out) {
    std::fill(out.pixels.begin(), out.pixels.end(), 0xFF101010u);
    blit(l.top, top, out);
    blit(l.bottom, bottom, out);
}

} // namespace port
