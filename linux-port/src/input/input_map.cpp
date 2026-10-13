#include "port/input_map.h"
#include "compat/ctr_compat.h"

namespace port {
uint32_t button_for_key(HostKey k) {
    using namespace ctr;
    switch (k) {
        case HostKey::X: return KEY_A;       case HostKey::Z: return KEY_B;
        case HostKey::S: return KEY_X;       case HostKey::A: return KEY_Y;
        case HostKey::Q: return KEY_L;       case HostKey::W: return KEY_R;
        case HostKey::Return: return KEY_START; case HostKey::RShift: return KEY_SELECT;
        case HostKey::Up: return KEY_DUP;    case HostKey::Down: return KEY_DDOWN;
        case HostKey::Left: return KEY_DLEFT; case HostKey::Right: return KEY_DRIGHT;
        default: return 0;
    }
}
} // namespace port
