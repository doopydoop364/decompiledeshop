// Reconstructions of eShop runtime leaf routines. See include/original/eshop_runtime.h.
#include "original/eshop_runtime.h"

#include <cstring>

namespace eshop_orig {

// @0x002A8F8C. The original scans 4 bytes at a time using UQSUB8 (zero-byte detection)
// after aligning; the decompiler output shows only the saturating-subtract idiom. The
// result is the index of the first NUL byte.
int cstring_length(const char* text) {
    const char* cursor = text;
    while (*cursor != '\0') ++cursor;
    return static_cast<int>(cursor - text);
}

// @0x002A0964 (Thumb): r1=0; while (*(u16*)r0 != 0) { r0+=2; r1++; } return r1;
int string16_length(const uint16_t* text) {
    int count = 0;
    for (; *text != 0; ++text) ++count;
    return count;
}

// @0x0029E4F0 (Thumb). When both pointers are 4-byte aligned, whole words are compared;
// on the first differing word the returned value is the difference of the *shortest
// differing little-endian prefix* of the word pair (byte0, then low 16 bits, then low 24
// bits, then the top byte). Otherwise (or for the tail) it is a byte-wise difference.
int compare_bytes(const void* left, const void* right, uint32_t byte_count) {
    const uint8_t* l = static_cast<const uint8_t*>(left);
    const uint8_t* r = static_cast<const uint8_t*>(right);
    if ((((uintptr_t)l | (uintptr_t)r) & 3) == 0) {
        while (byte_count >= 4) {
            uint32_t lw, rw;
            std::memcpy(&lw, l, 4);
            std::memcpy(&rw, r, 4);
            l += 4; r += 4; byte_count -= 4;
            if (lw != rw) {
                int diff = static_cast<int>(lw & 0xff) - static_cast<int>(rw & 0xff);
                if (diff == 0) diff = static_cast<int>(lw & 0xffff) - static_cast<int>(rw & 0xffff);
                if (diff == 0) diff = static_cast<int>(lw & 0xffffff) - static_cast<int>(rw & 0xffffff);
                if (diff == 0) diff = static_cast<int>(lw >> 24) - static_cast<int>(rw >> 24);
                return diff;
            }
        }
    }
    for (; byte_count != 0; --byte_count, ++l, ++r) {
        int diff = static_cast<int>(*l) - static_cast<int>(*r);
        if (diff != 0) return diff;
    }
    return 0;
}

// @0x002A8F1C: copies bytes up to and including the terminating NUL.
void cstring_copy(char* destination, const char* source) {
    while ((*destination++ = *source++) != '\0') {}
}

// @0x00100186 (Thumb): find end of destination, then copy source including NUL.
void cstring_append(char* destination, const char* source) {
    while (*destination != '\0') ++destination;
    while ((*destination++ = *source++) != '\0') {}
}

// @0x0029B7A0 / @0x002A81F0.
CopyEnds copy_bytes_forward(void* destination, const void* source, uint32_t byte_count) {
    uint8_t* d = static_cast<uint8_t*>(destination);
    const uint8_t* s = static_cast<const uint8_t*>(source);
    for (uint32_t i = 0; i < byte_count; ++i) d[i] = s[i];
    return CopyEnds{d + byte_count, s + byte_count};
}

} // namespace eshop_orig
