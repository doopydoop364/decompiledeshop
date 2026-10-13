/* Keyboard -> 3DS button mapping (frontend-independent key ids). Newly written. */
#ifndef ESHOP_PORT_INPUT_MAP_H
#define ESHOP_PORT_INPUT_MAP_H
#include <cstdint>
namespace port {

// Abstract host keys, so this layer needs no SDL header.
enum class HostKey { Unknown, Z, X, A, S, Q, W, Return, RShift, Up, Down, Left, Right, Count };

// Default map: X=A, Z=B, S=X, A=Y, Q=L, W=R, Enter=Start, RShift=Select, arrows=D-pad.
uint32_t button_for_key(HostKey k);

} // namespace port
#endif
