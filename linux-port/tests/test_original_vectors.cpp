// Differential test: reconstructed functions vs. results recorded from the ORIGINAL
// ARM machine code (tools/oracle_vectors.py). Line format:
//   oa ob n A_hex B_hex ret A_after_hex B_after_hex
#include "original/eshop_runtime.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace eshop_orig;
static const uint32_t A_BASE = 0x10000000, B_BASE = 0x20000000;
static const size_t BUF = 0x2000;  // matches oracle; only the first window is non-zero

static std::vector<uint8_t> unhex(const std::string& h) {
    std::vector<uint8_t> v(h.size() / 2);
    for (size_t i = 0; i < v.size(); ++i) v[i] = (uint8_t)std::stoul(h.substr(2 * i, 2), nullptr, 16);
    return v;
}

struct Ctx { uint8_t* a; uint8_t* b; int oa, ob; uint32_t n; };
// Returns the 32-bit value to compare with the oracle's r0.
using Fn = std::function<uint32_t(Ctx&)>;

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <vector_dir>\n", argv[0]); return 2; }
    std::string dir = argv[1];
    std::map<std::string, Fn> fns = {
        {"cstring_length_002a8f8c", [](Ctx& c) { return (uint32_t)cstring_length((char*)c.a + c.oa); }},
        {"string16_length_002a0964", [](Ctx& c) { return (uint32_t)string16_length((uint16_t*)(c.a + c.oa)); }},
        {"compare_bytes_0029e4f0", [](Ctx& c) { return (uint32_t)compare_bytes(c.a + c.oa, c.b + c.ob, c.n); }},
        // void functions: oracle r0 is whatever the original left in r0; only memory is compared.
        {"cstring_copy_002a8f1c", [](Ctx& c) { cstring_copy((char*)c.b + c.ob, (char*)c.a + c.oa); return ~0u; }},
        {"cstring_append_00100186", [](Ctx& c) { cstring_append((char*)c.b + c.ob, (char*)c.a + c.oa); return ~0u; }},
        {"copy_bytes_forward_0029b7a0", [](Ctx& c) {
             CopyEnds e = copy_bytes_forward(c.b + c.ob, c.a + c.oa, c.n);
             return B_BASE + (uint32_t)((uint8_t*)e.dst_end - c.b); }},
        {"copy_bytes_forward_002a81f0", [](Ctx& c) {
             CopyEnds e = copy_bytes_forward(c.b + c.ob, c.a + c.oa, c.n);
             return B_BASE + (uint32_t)((uint8_t*)e.dst_end - c.b); }},
    };
    int failures = 0;
    for (auto& [name, fn] : fns) {
        std::ifstream in(dir + "/" + name + ".vec");
        if (!in) { std::printf("FAIL %s: vector file missing\n", name.c_str()); ++failures; continue; }
        std::string line; int cases = 0, bad = 0;
        while (std::getline(in, line)) {
            std::istringstream ss(line);
            int oa, ob; uint32_t n; std::string ah, bh, rh, a2h, b2h;
            ss >> oa >> ob >> n >> ah >> bh >> rh >> a2h >> b2h;
            std::vector<uint8_t> a = unhex(ah), b = unhex(bh), ea = unhex(a2h), eb = unhex(b2h);
            size_t win = a.size();
            a.resize(BUF); b.resize(BUF);  // zero tail, as in the oracle
            Ctx c{a.data(), b.data(), oa, ob, n};
            uint32_t ret = fn(c);
            uint32_t eret = (uint32_t)std::stoul(rh, nullptr, 16);
            bool check_ret = ret != ~0u;
            bool ok = (!check_ret || ret == eret) && !std::memcmp(a.data(), ea.data(), win) &&
                      !std::memcmp(b.data(), eb.data(), win);
            ++cases;
            if (!ok && bad++ < 3)
                std::printf("  mismatch %s case %d: ret=%08x expected=%08x\n", name.c_str(), cases, ret, eret);
        }
        std::printf("%s %s (%d cases, %d mismatches)\n", bad ? "FAIL" : "PASS", name.c_str(), cases, bad);
        failures += bad != 0;
    }
    return failures ? 1 : 0;
}
