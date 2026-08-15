// Golden vector generator: byte-exact ports of openppp2's pure algorithm
// functions (ssea.cpp / ITransmission.cpp), compiled standalone so the Rust
// implementation can be validated against the C++ reference semantics.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <algorithm>

typedef unsigned char Byte;
typedef unsigned int uint32;

// ------------------------- ssea.cpp ports (verbatim) -----------------------

static void shuffle_data(char* encoded_data, int data_size, uint32 key) {
    if (encoded_data != NULL && data_size > 0) {
        for (int i = 0; i < data_size; i++) {
            uint32 p = (uint32)i;
            uint32 j = (uint32)((p ^ key) % data_size);
            std::swap(encoded_data[i], encoded_data[j]);
        }
    }
}

static void unshuffle_data(char* encoded_data, int data_size, uint32 key) {
    if (encoded_data != NULL && data_size > 0) {
        for (int i = data_size - 1; i > -1; i--) {
            uint32 p = (uint32)i;
            uint32 j = (uint32)((p ^ key) % data_size);
            std::swap(encoded_data[i], encoded_data[j]);
        }
    }
}

static void delta_encode(unsigned char* out, const unsigned char* data, int data_size, int kf) {
    out[0] = (Byte)(data[0] - kf);
    for (int i = 1; i < data_size; i++) out[i] = (Byte)(data[i] - data[i - 1]);
}

static void delta_decode(unsigned char* out, const unsigned char* data, int data_size, int kf) {
    out[0] = (Byte)(data[0] + kf);
    for (int i = 1; i < data_size; i++) out[i] = (Byte)(out[i - 1] + data[i]);
}

static int random_next(unsigned int* seed) {
    unsigned int next = *seed;
    int result;
    next *= 1103515245; next += 12345;
    result = (unsigned int)(next / 65536) % 2048;
    next *= 1103515245; next += 12345;
    result <<= 10; result ^= (unsigned int)(next / 65536) % 1024;
    next *= 1103515245; next += 12345;
    result <<= 10; result ^= (unsigned int)(next / 65536) % 1024;
    *seed = next;
    return result;
}

static int random_next(unsigned int* seed, int min, int max) {
    int v = random_next(seed);
    return v % (max - min + 1) + min;
}

static bool masked_xor_random_next(void* mn, void* mx, int kf_) {
    unsigned char* min_ = (unsigned char*)mn;
    unsigned char* max_ = (unsigned char*)mx;
    int length = max_ - min_;
    if (length == 0) return true;
    if (length < 0) return false;
    int count = length >> 2, remainder = length & 3;
    unsigned int kf = (unsigned int)kf_;
    kf = (unsigned int)random_next((unsigned int*)&kf);
    unsigned int* p32 = (unsigned int*)min_;
    for (int i = 0; i < count; i++) { *p32 = *p32 ^ kf; p32++; kf = (unsigned int)random_next(&kf); }
    short* p16 = (short*)p32;
    if (remainder >> 1) { *p16 = (short)(*p16 ^ kf); p16++; kf = (unsigned int)random_next(&kf); }
    char* p8 = (char*)p16;
    if (remainder & 1) { *p8 = (char)(*p8 ^ kf); }
    return true;
}

static std::vector<Byte> base94_encode(const Byte* data, int datalen, int kf) {
    const int BASE93 = 93;
    std::vector<Byte> out;
    for (int i = 0; i < datalen; i++) {
        Byte b = (Byte)(data[i] - kf);
        if (b >= BASE93) {
            out.push_back('\x20' + (((b / BASE93) - 1) + BASE93));
            out.push_back('\x20' + (b % BASE93));
        } else {
            out.push_back('\x20' + b);
        }
    }
    return out;
}

static unsigned short inet_chksum(void* dataptr, int len) {
    // RFC1071: big-endian 16-bit words, odd tail padded as high byte, fold,
    // one's complement (matches lwIP ip_standard_chksum semantics).
    unsigned char* p = (unsigned char*)dataptr;
    unsigned int sum = 0;
    int i = 0;
    for (; i + 1 < len; i += 2) sum += (p[i] << 8) | p[i + 1];
    if (i < len) sum += p[i] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)~sum;
}

static std::string base94_decimal(unsigned long long v) {
    char buf[16];
    int n = 0;
    unsigned long long x = v;
    do { buf[n++] = (char)((x % 94) + 0x20); x /= 94; } while (x > 0);
    std::string s(buf, n);
    std::reverse(s.begin(), s.end());
    return s;
}

static unsigned long long base94_decimal_parse(const char* p, int len) {
    unsigned long long n = 0;
    for (int i = 0; i < len; i++) {
        unsigned char b = (unsigned char)p[i];
        if (b < 0x20) return 0;
        b -= 0x20;
        if (b >= 94) return 0;
        n = n * 94 + b;
    }
    return n;
}

// Deterministic stand-in for RandomNext (closed range, both inclusive).
struct Rng {
    unsigned int s;
    Rng(unsigned int seed) : s(seed) {}
    int next(int min, int max) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        return (int)(s % (unsigned int)(max - min + 1)) + min;
    }
    int next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return (int)(s & 0x7FFFFFFF); }
};

// base94_encode_length from ITransmission.cpp (no cipher, shared MOD).
static std::string base94_encode_length(int length, int kf, int MOD, bool frame_tn, Rng& rng) {
    const int KF_MOD = abs(kf % MOD);
    int N = (length + KF_MOD) % MOD;
    std::string d = base94_decimal((unsigned long long)N);
    int dl = (int)d.size();
    Byte h[7] = { 0x20,0x20,0x20,0x20,0,0,0 };
    memcpy(h + (4 - dl), d.data(), dl);
    Byte k = (Byte)rng.next(0x20, 0x7e);
    if (h[1] == 0x20) {
        if (k & 1) ++k;
        h[1] = (Byte)rng.next(0x20, 0x7e);
    } else if ((k & 1) == 0) {
        if (++k > 0x7e) k = 0x21;
    }
    h[0] = k;
    std::swap(h[2], h[3]);
    if (frame_tn) return std::string((char*)h, 4);
    int K = inet_chksum(h, 4) ^ length;
    N = (K + KF_MOD) % MOD;
    d = base94_decimal((unsigned long long)N);
    memcpy(h + 4, d.data(), 3);
    shuffle_data((char*)h + 4, 3, (uint32)kf);
    return std::string((char*)h, 7);
}

// Transmission_Packet_Encrypt header stage, no ciphers (ITransmission.cpp).
static void header_encrypt(int payload_len, int kf, int seed, Byte out[3], int* header_kf) {
    int adjusted = payload_len - 1;
    Byte a[3] = { (Byte)seed, (Byte)(adjusted >> 8), (Byte)(adjusted & 0xff) };
    *header_kf = kf ^ a[0];
    for (int i = 1; i < 3; i++) a[i] ^= (Byte)*header_kf;
    shuffle_data((char*)a + 1, 2, (uint32)*header_kf);
    Byte tmp[3];
    delta_encode(tmp, a, 3, kf);
    memcpy(out, tmp, 3);
}

// Transmission_Payload_Encrypt with all flags on (safest mode).
static std::vector<Byte> payload_encrypt(const Byte* data, int len, int kf, int header_kf) {
    std::vector<Byte> buf(data, data + len);
    masked_xor_random_next(buf.data(), buf.data() + len, header_kf);
    shuffle_data((char*)buf.data(), len, (uint32)header_kf);
    std::vector<Byte> out(len);
    delta_encode(out.data(), buf.data(), len, kf);
    return out;
}

// Transmission_Handshake_Pack_SessionId with stand-in rng.
static std::vector<Byte> pack_session_id(long long hi, unsigned long long lo, int kf, int kx, Rng& rng) {
    bool real = !(hi == 0 && lo == 0);
    Byte kfs[4];
    std::string id_str;
    if (real) {
        kfs[0] = (Byte)rng.next(0x00, 0x7f);
        char b[48];
        // decimal 128-bit via unsigned __int64 pair (hi < 10^19 cases here)
        if (hi == 0) sprintf_s(b, "%llu", lo);
        else sprintf_s(b, "%llu%019llu", hi, lo);
        id_str = b;
    } else {
        kfs[0] = (Byte)rng.next(0x80, 0xff);
        unsigned long long v1 = ((unsigned long long)rng.next() << 32) | (unsigned int)rng.next();
        unsigned long long v2 = ((unsigned long long)rng.next() << 32) | (unsigned int)rng.next();
        char b[48];
        sprintf_s(b, "%llu%019llu", v2, v1);
        id_str = b;
    }
    kfs[1] = (Byte)rng.next(0x01, 0xff);
    kfs[2] = (Byte)rng.next(0x01, 0xff);
    kfs[3] = (Byte)rng.next(0x01, 0xff);
    id_str.append(1, (char)rng.next(0x20, 0x2f));
    int max = kx % 0x100;
    if (max > 0) {
        for (int i = 0; i < max; i++) id_str.append(1, (char)rng.next(0x20, 0x7e));
        id_str.append(1, '/');
        int min = (int)id_str.size() + 4;
        if (min > max) max = min;
        int loops = rng.next(1, max << 2);
        for (int i = 0; i < loops; i++) id_str.append(1, (char)rng.next(0x20, 0x7e));
    }
    int packet_length = (int)id_str.size();
    int kfi = kf;
    for (int i = 0; i < 4; i++) {
        kfi ^= kfs[i];
        for (int j = 0; j < packet_length; j++) id_str[j] = (char)((Byte)id_str[j] ^ (Byte)kfi);
    }
    std::vector<Byte> msg(4 + packet_length);
    memcpy(msg.data(), kfs, 4);
    memcpy(msg.data() + 4, id_str.data(), packet_length);
    return msg;
}

// ------------------------------ output helpers -----------------------------

static void hex(const void* p, int len) {
    const unsigned char* b = (const unsigned char*)p;
    printf("\"");
    for (int i = 0; i < len; i++) printf("%02x", b[i]);
    printf("\"");
}

static void hexv(const std::vector<Byte>& v) { hex(v.data(), (int)v.size()); }

int main() {
    printf("// auto-generated by vectors.cpp - do not edit\n\n");

    // ---- LCG sequences ----
    printf("pub const LCG: &[(u32, u32)] = &[\n");
    unsigned int seeds[] = { 0, 1, 154543927u, 0xFFFFFFFFu };
    for (unsigned int sd : seeds) {
        unsigned int s = sd;
        for (int i = 0; i < 4; i++) random_next(&s);
        printf("    (0x%08X, 0x%08X),\n", sd, s);
    }
    printf("];\n\n");

    // ---- shuffle / delta / masked_xor / base94 on sample buffers ----
    Byte sample[300];
    for (int i = 0; i < 300; i++) sample[i] = (Byte)(i * 7 + 3);
    printf("pub const SHUFFLE: &[(&[u8], u32, &str)] = &[\n");
    {
        uint32 keys[] = { 0, 1, 0x5A5A5A5Au, 154543927u };
        int sizes[] = { 7, 64, 300 };
        for (uint32 key : keys) for (int sz : sizes) {
            Byte buf[300]; memcpy(buf, sample, sz);
            shuffle_data((char*)buf, sz, key);
            printf("    (&[%d], 0x%08X, ", sz * 0, key); hex(buf, sz); printf("),\n");
        }
    }
    printf("];\n\n");

    printf("pub const DELTA: &[(u32, &str)] = &[\n");
    {
        uint32 kfs[] = { 0, 0xAB, 154543927u };
        for (uint32 kf : kfs) {
            Byte out[300]; delta_encode(out, sample, 300, (int)kf);
            printf("    (0x%08X, ", kf); hex(out, 300); printf("),\n");
        }
    }
    printf("];\n\n");

    printf("pub const MASKED_XOR: &[(u32, u32, &str)] = &[\n");
    {
        struct { int len; uint32 kf; } cases[] = {
            {5, 0x12345678u}, {100, 154543927u}, {261, 1u},
        };
        for (auto& c : cases) {
            Byte buf[300]; memcpy(buf, sample, c.len);
            masked_xor_random_next(buf, buf + c.len, (int)c.kf);
            printf("    (%d, 0x%08X, ", c.len, c.kf); hex(buf, c.len); printf("),\n");
        }
    }
    printf("];\n\n");

    printf("pub const BASE94_ENC: &[(u32, &str)] = &[\n");
    {
        Byte all[256]; for (int i = 0; i < 256; i++) all[i] = (Byte)i;
        uint32 kfs[] = { 0, 93, 154543927u, 0xFFFFFFFFu };
        for (uint32 kf : kfs) {
            std::vector<Byte> e = base94_encode(all, 256, (int)kf);
            printf("    (0x%08X, ", kf); hexv(e); printf("),\n");
        }
    }
    printf("];\n\n");

    printf("pub const CHKSUM: &[(&[u8], u16)] = &[\n");
    {
        Byte c1[] = { 0x00,0x01,0xF2,0x03,0xF4,0xF5,0xF6,0xF7 };
        Byte c2[] = { 0x00,0x01,0xF2,0x03,0xF4,0xF5,0xF7 };
        Byte c3[] = { 0x21,0x22,0x7D,0x20,0x41 };
        printf("    (&[%02x,%02x,%02x,%02x,%02x,%02x,%02x,%02x], 0x%04X),\n",
            c1[0], c1[1], c1[2], c1[3], c1[4], c1[5], c1[6], c1[7], inet_chksum(c1, 8));
        printf("    (&[%02x,%02x,%02x,%02x,%02x,%02x,%02x], 0x%04X),\n",
            c2[0], c2[1], c2[2], c2[3], c2[4], c2[5], c2[6], inet_chksum(c2, 7));
        printf("    (&[%02x,%02x,%02x,%02x,%02x], 0x%04X),\n",
            c3[0], c3[1], c3[2], c3[3], c3[4], inet_chksum(c3, 5));
    }
    printf("];\n\n");

    printf("pub const DEC94: &[(u64, &str)] = &[\n");
    {
        unsigned long long vs[] = { 0, 1, 93, 94, 830583, 18446744073709551615ull };
        for (unsigned long long v : vs) {
            std::string s = base94_decimal(v);
            printf("    (%llu, \"%s\"), // parsed-back=%llu\n", v, s.c_str(), base94_decimal_parse(s.data(), (int)s.size()));
        }
    }
    printf("];\n\n");

    // ---- base94 frame headers: Rust must decode these lengths ----
    printf("pub const FRAME_HDR: &[(u32, usize, bool, usize, usize, &str)] = &[\n", nullptr);
    {
        uint32 kf = 154543927u;
        unsigned int lseed = kf;
        int MOD = random_next(&lseed, 64 * 64 * 64, 94 * 94 * 94);
        Rng rng(0xC0FFEE);
        int lens[] = { 1, 5, 93*93-1, 93*93, 5000, 131136 };
        bool tn = false;
        for (int len : lens) {
            std::string h = base94_encode_length(len, (int)kf, MOD, tn, rng);
            tn = true; // subsequent frames use the simple header
            printf("    (0x%08X, %d, %s, %d, %d, ", kf, (int)h.size(), h.size() == 7 ? "true" : "false", MOD, abs((int)kf % MOD));
            hex(h.data(), (int)h.size());
            printf("), // encodes length %d\n", len);
        }
    }
    printf("];\n\n");

    // ---- binary frame header (no cipher): Rust header_decrypt must match ----
    printf("pub const BIN_HDR: &[(u32, usize, u8, u32, &str)] = &[\n");
    {
        struct { int len; int seed; } cases[] = { {1, 0x41}, {65536, 0xFF}, {12345, 0x01}, {256, 0x80} };
        for (auto& c : cases) {
            Byte out[3]; int hkf;
            header_encrypt(c.len, 154543927, c.seed, out, &hkf);
            printf("    (0x%08X, %d, 0x%02X, 0x%08X, ", 154543927u, c.len, c.seed, (uint32)hkf);
            hex(out, 3); printf("),\n");
        }
    }
    printf("];\n\n");

    // ---- binary payload transform (safest): Rust deobfuscate must invert ----
    printf("pub const BIN_PAYLOAD: &[(u32, u32, &str, &str)] = &[\n");
    {
        struct { int len; int hkf; } cases[] = { {17, 0x11223344}, {300, 0xDEADBEEF}, {1, 7} };
        for (auto& c : cases) {
            std::vector<Byte> enc = payload_encrypt(sample, c.len, 154543927, c.hkf);
            printf("    (0x%08X, 0x%08X, ", (uint32)c.hkf, 154543927u);
            hex(sample, c.len); printf(", "); hexv(enc); printf("),\n");
        }
    }
    printf("];\n\n");

    // ---- session-id packets: Rust unpack must recover ----
    printf("pub const SESSION_ID: &[(u32, bool, &str)] = &[\n");
    {
        Rng rng(0xABCD1234);
        // (hi=0, lo=12345): real id 12345
        std::vector<Byte> p1 = pack_session_id(0, 12345, 154543927, 128, rng);
        // dummy
        std::vector<Byte> p2 = pack_session_id(0, 0, 154543927, 128, rng);
        // big: hi=0, lo=99999999999999999999 doesn't fit u64; use hi=5,lo=42...
        std::vector<Byte> p3 = pack_session_id(5, 4200000000000000000ull, 154543927, 128, rng);
        printf("    (0x%08X, true, ", 154543927u); hexv(p1); printf("), // id 12345\n");
        printf("    (0x%08X, false, ", 154543927u); hexv(p2); printf("), // dummy\n");
        printf("    (0x%08X, true, ", 154543927u); hexv(p3); printf("), // id 54200000000000000000 (hi=5)\n");
    }
    printf("];\n");
    return 0;
}
