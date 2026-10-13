// eshop (Linux port) -- program entry. Newly written frontend.
//   eshop [--headless] [--frames N] [--dump file.ppm] [--scale N] [--fit] [--fullscreen]
#include "port/app.h"
#include "port/dual_screen.h"
#include "port/input_map.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef ESHOP_SDL
#if ESHOP_SDL == 3
#include <SDL3/SDL.h>
#else
#include <SDL.h>
#endif
#endif

static bool write_ppm(const char* path, const ctr::Framebuffer& fb) {
    FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    std::fprintf(f, "P6\n%d %d\n255\n", fb.width, fb.height);
    for (uint32_t p : fb.pixels) { unsigned char rgb[3] = {(unsigned char)(p >> 16), (unsigned char)(p >> 8), (unsigned char)p}; std::fwrite(rgb, 1, 3, f); }
    std::fclose(f);
    return true;
}

int main(int argc, char** argv) {
    bool headless = false, integer = true, fullscreen = false;
    int frames = -1, scale = 0;
    const char* dump = nullptr;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--headless")) headless = true;
        else if (!std::strcmp(argv[i], "--fit")) integer = false;
        else if (!std::strcmp(argv[i], "--fullscreen")) fullscreen = true;
        else if (!std::strcmp(argv[i], "--frames") && i + 1 < argc) frames = std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--scale") && i + 1 < argc) scale = std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--dump") && i + 1 < argc) dump = argv[++i];
        else { std::fprintf(stderr, "usage: %s [--headless] [--frames N] [--dump f.ppm] [--scale N] [--fit] [--fullscreen]\n", argv[0]); return 2; }
    }
    port::App app;
    if (!app.init()) { std::fprintf(stderr, "platform init failed\n"); return 1; }
    std::printf("eshop linux port: compat layer initialised (save dir: %s)\n", app.platform().save_dir().c_str());

    int ww = ctr::kTopWidth * (scale > 0 ? scale : 2), wh = (ctr::kTopHeight + ctr::kBottomHeight) * (scale > 0 ? scale : 2);
    ctr::Framebuffer out;

#ifdef ESHOP_SDL
    if (!headless) {
#if ESHOP_SDL == 3
        if (!SDL_Init(SDL_INIT_VIDEO)) { std::fprintf(stderr, "SDL_Init: %s\n", SDL_GetError()); return 1; }
        SDL_Window* win = SDL_CreateWindow("eShop (Linux port)", ww, wh, SDL_WINDOW_RESIZABLE | (fullscreen ? SDL_WINDOW_FULLSCREEN : 0));
        SDL_Renderer* ren = win ? SDL_CreateRenderer(win, nullptr) : nullptr;
#else
        if (SDL_Init(SDL_INIT_VIDEO) != 0) { std::fprintf(stderr, "SDL_Init: %s\n", SDL_GetError()); return 1; }
        SDL_Window* win = SDL_CreateWindow("eShop (Linux port)", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, ww, wh,
                                           SDL_WINDOW_RESIZABLE | (fullscreen ? SDL_WINDOW_FULLSCREEN_DESKTOP : 0));
        SDL_Renderer* ren = win ? SDL_CreateRenderer(win, -1, 0) : nullptr;
#endif
        if (!win || !ren) { std::fprintf(stderr, "window/renderer creation failed: %s\n", SDL_GetError()); return 1; }
        SDL_Texture* tex = nullptr; int tw = 0, th = 0;
        bool running = true; uint32_t held = 0; bool mouse = false;
        port::Layout lay;
        while (running && (frames < 0 || (int)app.frame_count() < frames)) {
            SDL_Event e;
            while (SDL_PollEvent(&e)) {
#if ESHOP_SDL == 3
                if (e.type == SDL_EVENT_QUIT) running = false;
#else
                if (e.type == SDL_QUIT) running = false;
#endif
            }
            int w, h;
#if ESHOP_SDL == 3
            SDL_GetWindowSize(win, &w, &h);
#else
            SDL_GetWindowSize(win, &w, &h);
#endif
            if (out.width != w || out.height != h) out.resize(w, h);
            lay = port::compute_layout(w, h, integer, scale);
            int mx, my; uint32_t mb;
#if ESHOP_SDL == 3
            float fx, fy; mb = SDL_GetMouseState(&fx, &fy); mx = (int)fx; my = (int)fy;
            const bool* ks = SDL_GetKeyboardState(nullptr);
            auto K = [&](SDL_Scancode s) { return ks[s]; };
#else
            mb = SDL_GetMouseState(&mx, &my);
            const Uint8* ks = SDL_GetKeyboardState(nullptr);
            auto K = [&](SDL_Scancode s) { return ks[s] != 0; };
#endif
            held = 0;
            struct { SDL_Scancode sc; port::HostKey hk; } map[] = {
                {SDL_SCANCODE_X, port::HostKey::X}, {SDL_SCANCODE_Z, port::HostKey::Z}, {SDL_SCANCODE_S, port::HostKey::S},
                {SDL_SCANCODE_A, port::HostKey::A}, {SDL_SCANCODE_Q, port::HostKey::Q}, {SDL_SCANCODE_W, port::HostKey::W},
                {SDL_SCANCODE_RETURN, port::HostKey::Return}, {SDL_SCANCODE_RSHIFT, port::HostKey::RShift},
                {SDL_SCANCODE_UP, port::HostKey::Up}, {SDL_SCANCODE_DOWN, port::HostKey::Down},
                {SDL_SCANCODE_LEFT, port::HostKey::Left}, {SDL_SCANCODE_RIGHT, port::HostKey::Right}};
            for (auto& m : map) if (K(m.sc)) held |= port::button_for_key(m.hk);
            int tx = 0, ty = 0;
            mouse = (mb & SDL_BUTTON(1)) && port::window_to_touch(lay, mx, my, &tx, &ty);
            if (K(SDL_SCANCODE_ESCAPE)) running = false;
            app.platform().hid_set_held(held);
            app.platform().hid_set_touch(mouse, tx, ty);
            app.frame();
            port::compose(lay, app.platform().top(), app.platform().bottom(), out);
            if (!tex || tw != w || th != h) {
                if (tex) SDL_DestroyTexture(tex);
                tex = SDL_CreateTexture(ren, SDL_PIXELFORMAT_ARGB8888, SDL_TEXTUREACCESS_STREAMING, w, h);
                tw = w; th = h;
            }
            SDL_UpdateTexture(tex, nullptr, out.pixels.data(), w * 4);
            SDL_RenderClear(ren);
#if ESHOP_SDL == 3
            SDL_RenderTexture(ren, tex, nullptr, nullptr);
#else
            SDL_RenderCopy(ren, tex, nullptr, nullptr);
#endif
            SDL_RenderPresent(ren);
            SDL_Delay(16);
        }
        if (dump) write_ppm(dump, out);
        if (tex) SDL_DestroyTexture(tex);
        SDL_DestroyRenderer(ren); SDL_DestroyWindow(win); SDL_Quit();
        app.shutdown();
        return 0;
    }
#else
    (void)fullscreen;
#endif
    // Headless: render N frames to the composed framebuffer (CI / verification path).
    if (frames < 0) frames = 1;
    out.resize(ww, wh);
    port::Layout lay = port::compute_layout(ww, wh, integer, scale);
    for (int i = 0; i < frames; ++i) {
        app.frame();
        port::compose(lay, app.platform().top(), app.platform().bottom(), out);
    }
    if (dump && !write_ppm(dump, out)) { std::fprintf(stderr, "cannot write %s\n", dump); return 1; }
    std::printf("headless: rendered %d frame(s) at %dx%d\n", frames, ww, wh);
    app.shutdown();
    return 0;
}
