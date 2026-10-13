# 3DS compatibility layer

Header: `include/compat/ctr_compat.h`; implementation: `src/compatibility/ctr_compat.cpp`. All code is **newly written** Linux compatibility code.

| Area | State |
|---|---|
| Framebuffers (gfx) | Two CPU framebuffers, 400×240 and 320×240, ARGB. No PICA200/GPU emulation. |
| HID | Buttons use libctru bit layout; down/up edge detection; touch in bottom-screen coordinates. Fed by SDL keyboard/mouse. No circle pad, gyro, accelerometer. |
| Timing | `system_tick()` at the ARM11 rate 268,111,856 Hz from `steady_clock`. |
| Filesystem | Save directory under `$XDG_DATA_HOME/eshop-linux-port`. No fs:USER archive API yet. |
| Services | `service_table()` lists the services named in the executable; `open_service` returns success only for those marked supported. `act:u`, `am:sys`, `nim:s` are deliberately never implemented (accounts/installs/payments). |
| Threads, mutexes, events, heap | Not implemented yet (no recovered code calls them yet). |
| Networking | Not implemented. |

Unsupported calls return `kResultUnsupported` rather than faking success.
