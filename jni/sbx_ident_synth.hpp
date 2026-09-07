#ifndef SBX_IDENT_SYNTH_HPP
#define SBX_IDENT_SYNTH_HPP

#include <string>
#include <cstdint>
#include "sbx_native_read.hpp"

namespace sbxid {

inline char luhn_check_digit(const std::string& payload) {
    int sum = 0; bool dbl = true;
    for (int i = (int)payload.size() - 1; i >= 0; --i) {
        int n = payload[i] - '0';
        if (dbl) { n *= 2; if (n > 9) n -= 9; }
        sum += n; dbl = !dbl;
    }
    return (char)('0' + (10 - (sum % 10)) % 10);
}
inline bool luhn_valid(const std::string& full) {
    if (full.empty()) return false;
    int sum = 0; bool dbl = false;
    for (int i = (int)full.size() - 1; i >= 0; --i) {
        if (full[i] < '0' || full[i] > '9') return false;
        int n = full[i] - '0';
        if (dbl) { n *= 2; if (n > 9) n -= 9; }
        sum += n; dbl = !dbl;
    }
    return sum % 10 == 0;
}

inline void append_digits(std::string& d, uint64_t& s, int count) {
    for (int i = 0; i < count; ++i) d += (char)('0' + (int)(sbxnr::splitmix64(s) % 10));
}

inline std::string synth_imei(uint64_t seed) {
    static const char* TAC[] = {
        "35161511","35316010","35404911","35847313",
        "35692211","35876554","35291612","35438110",
        "86388803","86146203","35730012","35332510",
        "35479209","35516411","35790911","35402811",
        "35494911","35382209","35236211","35674708",
        "35322410","35785111","35851810","35935910",
        "35466810","35313011","35365810","35407115",
        "35397010","35814311","35495112","35929510",
        "35238004","35256412","35399511","35308214",
        "35453414","35505410","35553112","35715010",
        "35950010","35180010","35248510","35352111",
        "35210311","35226306","35456711","35694311",
    };
    uint64_t s = seed ^ 0x494D4549ULL;
    std::string d = TAC[sbxnr::splitmix64(s) % (sizeof(TAC)/sizeof(TAC[0]))];
    append_digits(d, s, 6);
    d += luhn_check_digit(d);
    return d;
}

inline std::string synth_imsi(uint64_t seed, std::string mccmnc) {
    if (mccmnc.size() < 5 || mccmnc.size() > 6) mccmnc = "51010";
    for (char c : mccmnc) if (c < '0' || c > '9') { mccmnc = "51010"; break; }
    uint64_t s = seed ^ 0x494D5349ULL;
    std::string d = mccmnc;
    append_digits(d, s, (int)(15 - mccmnc.size()));
    return d;
}

inline const char* iccid_cc_for_mcc(const std::string& mccmnc) {
    if (mccmnc.rfind("510", 0) == 0) return "62"; // Indonesia
    if (mccmnc.rfind("310", 0) == 0 || mccmnc.rfind("311", 0) == 0) return "1"; // US
    if (mccmnc.rfind("505", 0) == 0) return "61"; // Australia
    if (mccmnc.rfind("262", 0) == 0) return "49"; // Germany
    if (mccmnc.rfind("234", 0) == 0 || mccmnc.rfind("235", 0) == 0) return "44"; // UK
    if (mccmnc.rfind("404", 0) == 0 || mccmnc.rfind("405", 0) == 0) return "91"; // India
    if (mccmnc.rfind("440", 0) == 0) return "81"; // Japan
    if (mccmnc.rfind("724", 0) == 0) return "55"; // Brazil
    if (mccmnc.rfind("520", 0) == 0) return "66"; // Thailand
    if (mccmnc.rfind("502", 0) == 0) return "60"; // Malaysia
    if (mccmnc.rfind("515", 0) == 0) return "63"; // Philippines
    return "01";
}

inline std::string synth_iccid(uint64_t seed, const std::string& mccmnc) {
    uint64_t s = seed ^ 0x49434349ULL;
    std::string d = "89";
    d += iccid_cc_for_mcc(mccmnc);
    append_digits(d, s, (int)(18 - d.size()));
    d += luhn_check_digit(d);
    return d;
}

inline std::string synth_meid(uint64_t seed) {
    std::string h = sbxnr::hex_from_seed(seed ^ 0x4D454944ULL, 7);
    for (char& c : h) if (c >= 'a' && c <= 'f') c = (char)(c - 'a' + 'A');
    if (!h.empty()) {
        char c0 = h[0];
        int v = (c0 >= '0' && c0 <= '9') ? c0 - '0'
              : (c0 >= 'A' && c0 <= 'F') ? c0 - 'A' + 10 : 0;
        if (v < 0xA) h[0] = (char)('A' + (v % 6));
    }
    return h;
}

inline std::string synth_widevine_hex(uint64_t seed) {
    return sbxnr::hex_from_seed(seed ^ 0x57565F4944ULL, 32);
}

inline std::string synth_widevine_prov_hex(uint64_t seed) {
    return sbxnr::hex_from_seed(seed ^ 0x50524F565F5544ULL, 32);
}

inline std::string synth_gsf_id(uint64_t seed) {
    uint64_t s = seed ^ 0x4753464944ULL;
    uint64_t v = sbxnr::splitmix64(s) >> 1;
    if (v == 0) v = 1;
    return std::to_string(v);
}

struct SynthIds {
    std::string imei, imsi, iccid, meid, widevine_hex;
};
inline SynthIds synth_all(uint64_t seed, const std::string& mccmnc) {
    SynthIds o;
    o.imei         = synth_imei(seed);
    o.imsi         = synth_imsi(seed, mccmnc);
    o.iccid        = synth_iccid(seed, mccmnc);
    o.meid         = synth_meid(seed);
    o.widevine_hex = synth_widevine_hex(seed);
    return o;
}

}
#endif
