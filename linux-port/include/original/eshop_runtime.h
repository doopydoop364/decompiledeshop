/*
 * eShop runtime leaf routines, reconstructed from the original 3DS executable.
 *
 * Classification: "Faithful source reconstruction" (see docs/FUNCTION_PORT_STATUS.md).
 * Each function names the original address in code_decompressed.bin (load base
 * 0x00100000) and the eshop_decompile_v3.txt symbol it was reconstructed from.
 * The C++ below is NOT Nintendo's source: it is a behavioural reconstruction written
 * from decompiler output and ARM disassembly, and is verified by differential testing
 * against the original machine code (linux-port/tools/oracle_vectors.py).
 */
#ifndef ESHOP_ORIGINAL_RUNTIME_H
#define ESHOP_ORIGINAL_RUNTIME_H

#include <cstddef>
#include <cstdint>

namespace eshop_orig {

/* Pair returned by the original block-copy routines in r0:r1 (the decompiler shows an
 * undefined8 return). Observed via the oracle: r0 = dst + n, r1 = src + n. */
struct CopyEnds {
    void*       dst_end;
    const void* src_end;
};

/* @0x002A8F8C  cstring_length_002a8f8c (ARM). strlen equivalent. */
int cstring_length(const char* text);

/* @0x002A0964  string16_length_002a0964 (Thumb). Length in UTF-16 code units. */
int string16_length(const uint16_t* text);

/* @0x0029E4F0  compare_bytes_0029e4f0 (Thumb). memcmp-like; the *magnitude* of a
 * non-zero result follows the original's word-wise path (see implementation). */
int compare_bytes(const void* left, const void* right, uint32_t byte_count);

/* @0x002A8F1C  cstring_copy_002a8f1c (ARM). strcpy equivalent (no return value). */
void cstring_copy(char* destination, const char* source);

/* @0x00100186  cstring_append_00100186 (Thumb). strcat equivalent (no return value). */
void cstring_append(char* destination, const char* source);

/* @0x0029B7A0 copy_bytes_forward_0029b7a0 and @0x002A81F0 copy_bytes_forward_002a81f0
 * (ARM). Forward byte copy; both variants are behaviourally identical for
 * non-overlapping buffers (verified). Return the end pointers in r0:r1.
 * Not guaranteed for overlapping ranges: the originals are not memmove. */
CopyEnds copy_bytes_forward(void* destination, const void* source, uint32_t byte_count);

} // namespace eshop_orig

#endif
