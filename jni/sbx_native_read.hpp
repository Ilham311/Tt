#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <string>

namespace sbxnr {

inline uint64_t fnv1a(const std::string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    return h;
}

inline uint64_t splitmix64(uint64_t& x) {
    x += 0x9E3779B97F4A7C15ULL;
    uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

inline void fill_bytes(uint64_t seed, uint8_t* out, size_t n) {
    uint64_t s = seed;
    size_t i = 0;
    while (i < n) {
        uint64_t v = splitmix64(s);
        for (int b = 0; b < 8 && i < n; ++b, ++i)
            out[i] = static_cast<uint8_t>(v >> (b * 8));
    }
}

inline char hex_lc(unsigned v) { return "0123456789abcdef"[v & 0xF]; }

inline std::string uuid_from_seed(uint64_t seed) {
    uint8_t b[16];
    fill_bytes(seed, b, sizeof(b));
    b[6] = static_cast<uint8_t>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<uint8_t>((b[8] & 0x3F) | 0x80);
    std::string s;
    s.reserve(36);
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) s.push_back('-');
        s.push_back(hex_lc(b[i] >> 4));
        s.push_back(hex_lc(b[i] & 0xF));
    }
    return s;
}

inline std::string mac_from_seed(uint64_t seed) {
    uint8_t b[6];
    fill_bytes(seed, b, sizeof(b));
    b[0] = 0x02;
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  b[0], b[1], b[2], b[3], b[4], b[5]);
    return std::string(buf);
}

inline bool is_valid_mac(const std::string& m) {
    if (m.size() != 17) return false;
    for (int i = 0; i < 17; ++i) {
        char c = m[i];
        if ((i % 3) == 2) { if (c != ':') return false; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }

    bool all_zero = true;
    for (char c : m) if (c != '0' && c != ':') { all_zero = false; break; }
    return !all_zero;
}

inline bool mac_str_to_bytes(const std::string& mac, uint8_t out[6]) {
    if (!is_valid_mac(mac)) return false;
    auto hv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < 6; ++i) {
        int hi = hv(mac[i * 3]);
        int lo = hv(mac[i * 3 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

inline bool is_wifi_iface(const char* name) {
    if (!name) return false;
    return std::strncmp(name, "wlan", 4) == 0 || std::strncmp(name, "p2p", 3) == 0;
}

inline std::string hex_from_seed(uint64_t seed, size_t nbytes) {
    std::string s;
    s.reserve(nbytes * 2);
    uint64_t st = seed;
    size_t i = 0;
    while (i < nbytes) {
        uint64_t v = splitmix64(st);
        for (int b = 0; b < 8 && i < nbytes; ++b, ++i) {
            uint8_t byte = static_cast<uint8_t>(v >> (b * 8));
            s.push_back(hex_lc(byte >> 4));
            s.push_back(hex_lc(byte & 0xF));
        }
    }
    return s;
}

struct ApplogIds {
    std::string did, iid, ssid, cdid, clientudid, openudid;
};

inline std::string snowflake_from_seed(uint64_t seed, uint64_t epoch_ms) {

    uint64_t v = (epoch_ms << 22) | (splitmix64(seed) & 0x3FFFFFULL);
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(v));
    return std::string(buf);
}

inline ApplogIds make_applog_ids(uint64_t seed, uint64_t epoch_ms) {
    ApplogIds ids;
    ids.did        = snowflake_from_seed(seed ^ 0x9E3779B97F4A7C15ULL, epoch_ms);
    ids.iid        = snowflake_from_seed(seed ^ 0xBF58476D1CE4E5B9ULL, epoch_ms);
    ids.ssid       = snowflake_from_seed(seed ^ 0x94D049BB133111EBULL, epoch_ms);
    ids.cdid       = uuid_from_seed(seed ^ 0x2545F4914F6CDD1DULL);
    ids.clientudid = uuid_from_seed(seed ^ 0x9E3779B97F4A7C15ULL);
    ids.openudid   = hex_from_seed(seed, 8);
    return ids;
}

inline bool patch_applog_xml(const std::string& real, const ApplogIds& ids,
                             std::string& out) {
    if (real.find("<map") == std::string::npos ||
        real.find("<string") == std::string::npos)
        return false;

    auto subst_contains_ci = [](const std::string& key, const char* needle) {
        size_t nl = std::strlen(needle);
        if (key.size() < nl) return false;
        for (size_t i = 0; i + nl <= key.size(); ++i) {
            size_t j = 0;
            while (j < nl) {
                char a = key[i + j];
                char b = needle[j];
                if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
                if (a != b) break;
                ++j;
            }
            if (j == nl) return true;
        }
        return false;
    };

    size_t pos = 0;
    while (pos < real.size()) {
        size_t open = real.find('<', pos);
        if (open == std::string::npos) { out.append(real, pos, std::string::npos); break; }
        out.append(real, pos, open - pos);

        size_t close = real.find('>', open);
        if (close == std::string::npos) { out.append(real, open, std::string::npos); break; }
        size_t tag_end = close + 1;

        if (real.compare(open, 7, "<string") == 0) {

            const std::string* repl = nullptr;
            size_t nam = real.find("name=\"", open);
            if (nam != std::string::npos && nam < close) {
                nam += 6;
                size_t nam_end = real.find('"', nam);
                if (nam_end != std::string::npos && nam_end < close) {
                    std::string key = real.substr(nam, nam_end - nam);
                    if      (subst_contains_ci(key, "clientudid")) repl = &ids.clientudid;
                    else if (subst_contains_ci(key, "openudid"))   repl = &ids.openudid;
                    else if (subst_contains_ci(key, "install_id")) repl = &ids.iid;
                    else if (subst_contains_ci(key, "device_id"))  repl = &ids.did;
                    else if (subst_contains_ci(key, "cdid"))       repl = &ids.cdid;
                    else if (subst_contains_ci(key, "ssid"))       repl = &ids.ssid;
                    else if (subst_contains_ci(key, "did"))        repl = &ids.did;
                    else if (subst_contains_ci(key, "iid"))        repl = &ids.iid;
                }
            }
            if (repl) {
                out.append(real, open, tag_end - open);
                out.append(*repl);
                size_t vend = real.find("</string>", tag_end);
                if (vend == std::string::npos) return false;

                size_t vtend = vend + 9;
                out.append(real, vend, vtend - vend);
                pos = vtend;
                continue;
            }
        }
        out.append(real, open, tag_end - open);
        pos = tag_end;
    }
    return true;
}

inline std::string applog_xml_synth(const ApplogIds& ids) {
    std::string x;
    x += "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n";
    x += "<map>\n";
    x += "    <string name=\"device_id\">"  + ids.did        + "</string>\n";
    x += "    <string name=\"install_id\">" + ids.iid        + "</string>\n";
    x += "    <string name=\"ssid\">"       + ids.ssid       + "</string>\n";
    x += "    <string name=\"openudid\">"   + ids.openudid   + "</string>\n";
    x += "    <string name=\"clientudid\">" + ids.clientudid + "</string>\n";
    x += "    <string name=\"cdid\">"       + ids.cdid       + "</string>\n";
    x += "</map>\n";
    return x;
}

inline int release_major(const std::string& release) {
    return std::atoi(release.c_str());
}

inline const char* kernel_base(const std::string& platform, int rmaj) {
    if (platform == "gs101" || platform == "gs201") return "5.10";
    if (platform == "zuma")                          return "5.15";
    if (platform == "zumapro" || platform == "laguna") return "6.1";
    if (rmaj <= 0)  return "5.15";
    if (rmaj <= 12) return "5.10";
    if (rmaj <= 14) return "5.15";
    return "6.1";
}

inline const char* clang_for(int rmaj) {
    if (rmaj <= 12) return "14.0.6";
    if (rmaj == 13) return "16.0.2";
    if (rmaj == 14) return "17.0.4";
    return "18.0.1";
}

inline std::string synth_proc_version(const std::string& release,
                                      const std::string& incremental,
                                      const std::string& platform,
                                      const std::string& host,
                                      uint64_t seed) {
    int rmaj = release_major(release);
    int aver = rmaj > 0 ? rmaj : 14;
    const char* kbase = kernel_base(platform, rmaj);
    const char* clang = clang_for(rmaj);

    unsigned ksub = 100u + static_cast<unsigned>(seed % 120u);
    unsigned krev = 1u + static_cast<unsigned>((seed >> 8) % 15u);

    char ghash[13];
    uint64_t gh = splitmix64(seed);
    for (int i = 0; i < 12; ++i) ghash[i] = hex_lc(static_cast<unsigned>(gh >> (i * 4)));
    ghash[12] = '\0';

    std::string ab;
    for (char c : incremental) if (c >= '0' && c <= '9') ab.push_back(c);
    if (ab.size() < 6 || ab.size() > 12) {
        char b[16];
        std::snprintf(b, sizeof(b), "%08llu",
                      static_cast<unsigned long long>(10000000ULL + (seed % 90000000ULL)));
        ab = b;
    }

    std::string bhost = host.empty() ? std::string("abfarm-release-01") : host;

    char out[1024];
    int n = std::snprintf(out, sizeof(out),
        "Linux version %s.%u-android%d-%u-g%s-ab%s (kleaf@%s) "
        "(Android (based on r522817) clang version %s, LLD 18.0.1) "
        "#1 SMP PREEMPT Mon Jan 1 00:00:00 UTC 2024",
        kbase, ksub, aver, krev, ghash, ab.c_str(), bhost.c_str(), clang);
    if (n < 0) n = 0;
    if (static_cast<size_t>(n) >= sizeof(out)) n = static_cast<int>(sizeof(out) - 1);
    return std::string(out, static_cast<size_t>(n));
}

inline int pixel_ram_gb(const std::string& model) {
    struct M { const char* model; int gb; };
    static const M tbl[] = {
        {"Pixel 6", 8}, {"Pixel 6 Pro", 12}, {"Pixel 6a", 6},
        {"Pixel 7", 8}, {"Pixel 7 Pro", 12}, {"Pixel 7a", 8},
        {"Pixel 8", 8}, {"Pixel 8 Pro", 12}, {"Pixel 8a", 8},
        {"Pixel 9", 12}, {"Pixel 9 Pro", 16}, {"Pixel 9 Pro XL", 16},
        {"Pixel 9 Pro Fold", 16}, {"Pixel 9a", 8},
        {"Pixel 10", 12}, {"Pixel 10 Pro", 16}, {"Pixel 10 Pro XL", 16},
        {"Pixel Fold", 12},
    };
    for (const auto& e : tbl) if (model == e.model) return e.gb;
    return 0;
}

inline uint64_t ram_gb_to_memtotal_kb(int gb) {
    return static_cast<uint64_t>(gb) * 1024ULL * 1024ULL * 955ULL / 1000ULL;
}

inline uint64_t round_up_marketing_gb(uint64_t real_kb) {
    static const int tiers[] = {2, 3, 4, 6, 8, 12, 16, 18, 24};

    uint64_t gib = (real_kb + 1048575ULL) / 1048576ULL;
    for (int t : tiers) if (static_cast<uint64_t>(t) >= gib) return static_cast<uint64_t>(t);
    return gib;
}

inline std::string patch_meminfo(const std::string& real, int target_gb) {
    size_t pos = real.find("MemTotal:");
    if (pos != 0 && (pos == std::string::npos || real[pos - 1] != '\n')) {

        size_t p = real.find("\nMemTotal:");
        if (p == std::string::npos) return real;
        pos = p + 1;
    }
    size_t eol = real.find('\n', pos);
    if (eol == std::string::npos) eol = real.size();

    uint64_t target_kb;
    if (target_gb > 0) {
        target_kb = ram_gb_to_memtotal_kb(target_gb);
    } else {

        uint64_t real_kb = 0;
        const char* p = real.c_str() + pos;
        while (*p && (*p < '0' || *p > '9')) ++p;
        real_kb = std::strtoull(p, nullptr, 10);
        if (real_kb == 0) return real;
        target_kb = ram_gb_to_memtotal_kb(static_cast<int>(round_up_marketing_gb(real_kb)));
    }

    char line[64];
    std::snprintf(line, sizeof(line), "MemTotal:       %llu kB",
                  static_cast<unsigned long long>(target_kb));
    std::string out;
    out.reserve(real.size() + 8);
    out.append(real, 0, pos);
    out.append(line);
    out.append(real, eol, std::string::npos);
    return out;
}

// /proc/uptime: "UPTIME IDLE\n". L8 menggeser boottime +off detik, jadi
// perangkat tampak sudah menyala lebih lama; tambahkan off ke field pertama
// (uptime). Field kedua (idle) dibiarkan.
inline std::string patch_uptime(const std::string& real, long long off_sec) {
    if (off_sec <= 0) return real;
    size_t i = 0, n = real.size();
    while (i < n && (real[i] == ' ' || real[i] == '\t')) ++i;
    size_t start = i;
    while (i < n && real[i] != ' ' && real[i] != '\t' && real[i] != '\n') ++i;
    if (i == start) return real;
    double up = std::strtod(real.substr(start, i - start).c_str(), nullptr);
    if (up <= 0.0) return real;
    up += static_cast<double>(off_sec);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.2f", up);
    std::string out;
    out.reserve(real.size() + 8);
    out.append(real, 0, start);
    out.append(buf);
    out.append(real, i, std::string::npos);
    return out;
}

// /proc/stat: baris "btime <epoch>". Boottime yang digeser maju +off berarti
// sistem seolah boot lebih awal, jadi btime dikurangi off detik agar konsisten
// dengan elapsedRealtime yang bertambah (hindari mismatch mustahil).
inline std::string patch_stat_btime(const std::string& real, long long off_sec) {
    if (off_sec <= 0) return real;
    size_t pos = real.find("btime ");
    while (pos != std::string::npos && pos != 0 && real[pos - 1] != '\n')
        pos = real.find("btime ", pos + 1);
    if (pos == std::string::npos) return real;
    size_t vstart = pos + 6;
    size_t vend = vstart;
    while (vend < real.size() && real[vend] >= '0' && real[vend] <= '9') ++vend;
    if (vend == vstart) return real;
    unsigned long long bt =
        std::strtoull(real.substr(vstart, vend - vstart).c_str(), nullptr, 10);
    if (bt == 0) return real;
    unsigned long long ub = static_cast<unsigned long long>(off_sec);
    unsigned long long nb = (bt > ub) ? bt - ub : bt;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llu", nb);
    std::string out;
    out.reserve(real.size() + 4);
    out.append(real, 0, vstart);
    out.append(buf);
    out.append(real, vend, std::string::npos);
    return out;
}

enum CpuAction { CPU_NONE = 0, CPU_QUALCOMM = 1, CPU_MTK = 2, CPU_STRIP = 3 };

inline bool ci_contains(const std::string& hay, const char* needle) {
    size_t nl = std::strlen(needle);
    if (nl == 0) return true;
    if (hay.size() < nl) return false;
    for (size_t i = 0; i + nl <= hay.size(); ++i) {
        size_t j = 0;
        while (j < nl) {
            unsigned char a = static_cast<unsigned char>(hay[i + j]);
            unsigned char b = static_cast<unsigned char>(needle[j]);
            if (std::tolower(a) != std::tolower(b)) break;
            ++j;
        }
        if (j == nl) return true;
    }
    return false;
}

inline bool starts_with(const std::string& s, const char* p) {
    size_t n = std::strlen(p);
    return s.size() >= n && std::memcmp(s.data(), p, n) == 0;
}

inline int cpu_action_for(const std::string& soc_manuf, const std::string& soc_model,
                          std::string& repl_out) {
    repl_out.clear();
    bool qcom = ci_contains(soc_manuf, "qualcomm") ||
                starts_with(soc_model, "SM") || starts_with(soc_model, "MSM") ||
                starts_with(soc_model, "SDM") || starts_with(soc_model, "QCM") ||
                starts_with(soc_model, "APQ");
    bool mtk  = ci_contains(soc_manuf, "mediatek") || starts_with(soc_model, "MT");
    if (qcom) {
        repl_out = soc_model.empty() ? std::string("Qualcomm Technologies, Inc")
                                     : ("Qualcomm Technologies, Inc " + soc_model);
        return CPU_QUALCOMM;
    }
    if (mtk) {
        repl_out = soc_model.empty() ? std::string("MT6893") : soc_model;
        return CPU_MTK;
    }

    return CPU_STRIP;
}

inline bool patch_cpuinfo(const std::string& real, int action,
                          const std::string& repl, std::string& out) {
    if (action == CPU_NONE) return false;
    out.clear();
    out.reserve(real.size() + 16);
    bool changed = false;
    size_t i = 0, n = real.size();
    while (i < n) {
        size_t eol = real.find('\n', i);
        size_t line_end = (eol == std::string::npos) ? n : eol;

        bool is_hw = false;
        if (line_end - i >= 8 && std::memcmp(real.data() + i, "Hardware", 8) == 0) {
            size_t j = i + 8;
            while (j < line_end && (real[j] == ' ' || real[j] == '\t')) ++j;
            if (j < line_end && real[j] == ':') is_hw = true;
        }
        if (is_hw) {
            changed = true;
            if (action != CPU_STRIP) {
                out.append("Hardware\t: ");
                out.append(repl);
                if (eol != std::string::npos) out.push_back('\n');
            }

        } else {
            out.append(real, i, line_end - i);
            if (eol != std::string::npos) out.push_back('\n');
        }
        if (eol == std::string::npos) break;
        i = eol + 1;
    }
    if (!changed) { out.clear(); return false; }
    return true;
}

enum Kind {
    NONE = 0, BOOTID, MAC, VERSION, MEMINFO, CPUINFO, SELINUX_ENFORCE,
    ARP, UPTIME, STAT,

    APPLOG_XML,
    BD_RAW_DID,
    BD_RAW_IID,
    BD_RAW_OPENUDID,
    BD_RAW_CLIENTUDID,
    BD_RAW_CDID,
};

inline bool ends_with(const char* s, size_t sl, const char* suffix) {
    size_t xl = std::strlen(suffix);
    return sl >= xl && std::memcmp(s + sl - xl, suffix, xl) == 0;
}

inline bool ends_with(const std::string& s, const char* suffix) {
    return ends_with(s.c_str(), s.size(), suffix);
}

// Hanya file yang peta ID-nya memang kanonis yang boleh disintesis dari nol
// ketika belum ada di disk. Untuk file lain (mis. header_custom) sintesis stub
// justru salah bentuk, jadi kita hanya patch bila file sudah eksis.
inline bool applog_xml_is_synthable(const char* path) {
    if (!path) return false;
    size_t n = std::strlen(path);
    return ends_with(path, n, "/shared_prefs/applog.xml") ||
           ends_with(path, n, "/shared_prefs/applog_stats.xml") ||
           ends_with(path, n, "/shared_prefs/snssdk_openudid.xml") ||
           ends_with(path, n, "/shared_prefs/snssdk_did.xml") ||
           ends_with(path, n, "/shared_prefs/bd_device_info.xml");
}

inline Kind classify(const char* path) {
    if (!path) return NONE;
    const size_t pl = std::strlen(path);

    if (pl > 6 && std::memcmp(path, "/proc/", 6) == 0) {
        const char* r = path + 6;
        switch (*r) {
        case 'v': if (std::strcmp(r, "version") == 0) return VERSION; break;
        case 'm': if (std::strcmp(r, "meminfo") == 0) return MEMINFO; break;
        case 'c': if (std::strcmp(r, "cpuinfo") == 0) return CPUINFO; break;
        case 'u': if (std::strcmp(r, "uptime") == 0)  return UPTIME;  break;
        case 's':
            if (std::strcmp(r, "stat") == 0) return STAT;
            if (std::strcmp(r, "sys/kernel/random/boot_id") == 0) return BOOTID;
            break;
        case 'n': if (std::strcmp(r, "net/arp") == 0) return ARP; break;
        }
        return NONE;
    }

    if (pl > 5 && std::memcmp(path, "/sys/", 5) == 0) {
        const char* r = path + 5;
        if (std::strcmp(r, "fs/selinux/enforce") == 0) return SELINUX_ENFORCE;
        if (pl > 15 && std::memcmp(r, "class/net/", 10) == 0) {
            const char* iface = r + 10;
            const char* slash = std::strchr(iface, '/');
            if (slash && std::strcmp(slash, "/address") == 0) {
                size_t iflen = static_cast<size_t>(slash - iface);
                if ((iflen >= 4 && std::strncmp(iface, "wlan", 4) == 0) ||
                    (iflen >= 3 && std::strncmp(iface, "p2p", 3) == 0))
                    return MAC;
            }
        }
        return NONE;
    }

    if (ends_with(path, pl, "/shared_prefs/applog.xml") ||
        ends_with(path, pl, "/shared_prefs/applog_stats.xml") ||
        ends_with(path, pl, "/shared_prefs/snssdk_openudid.xml") ||
        ends_with(path, pl, "/shared_prefs/snssdk_did.xml") ||
        ends_with(path, pl, "/shared_prefs/bd_device_info.xml") ||
        ends_with(path, pl, "/shared_prefs/header_custom.xml") ||
        ends_with(path, pl, "/shared_prefs/ug_install_settings_pref.xml"))
        return APPLOG_XML;
    if (ends_with(path, pl, "/files/bd_setting/device_id"))   return BD_RAW_DID;
    if (ends_with(path, pl, "/files/bd_setting/install_id"))  return BD_RAW_IID;
    if (ends_with(path, pl, "/files/bd_setting/openudid"))    return BD_RAW_OPENUDID;
    if (ends_with(path, pl, "/files/bd_setting/clientudid"))  return BD_RAW_CLIENTUDID;
    if (ends_with(path, pl, "/files/.cdid"))                  return BD_RAW_CDID;
    if (ends_with(path, pl, "/no_backup/applog_device_id.dat")) return BD_RAW_DID;
    if (ends_with(path, pl, "/no_backup/bd_device_id"))         return BD_RAW_DID;
    if (ends_with(path, pl, "/no_backup/.cdid"))                return BD_RAW_CDID;

    return NONE;
}

inline std::string selinux_enforce_content() { return std::string("1"); }

inline std::string arp_empty_content() {
    return std::string(
        "IP address       HW type     Flags       HW address            Mask     Device\n");
}

inline bool is_emulator_prop(const char* name) {
    if (!name) return false;

    static const char* const exact[] = {
        "ro.kernel.qemu",
        "ro.kernel.qemu.gles",
        "ro.boot.qemu",
        "ro.boot.qemu.gltransport",
        "ro.hardware.virtual_device",
        "qemu.hw.mainkeys",
        "init.svc.qemud",
        "init.svc.qemu-props",
        "init.svc.goldfish-logcat",
        "init.svc.goldfish-setup",
        "init.svc.ranchu-net",
    };
    for (const char* e : exact) if (std::strcmp(name, e) == 0) return true;

    if (std::strncmp(name, "qemu.", 5) == 0)            return true;
    if (std::strncmp(name, "ro.kernel.qemu.", 15) == 0) return true;
    if (std::strncmp(name, "ro.boot.qemu.", 13) == 0)   return true;
    return false;
}

inline bool is_custom_rom_prop(const char* name) {
    if (!name) return false;
    static const char* const exact[] = {
        "ro.modversion",
        "ro.cm.version",
        "ro.cm.build.date",
    };
    for (const char* e : exact) if (std::strcmp(name, e) == 0) return true;
    if (std::strncmp(name, "ro.lineage.", 11) == 0)          return true;
    if (std::strncmp(name, "lineage.", 8) == 0)              return true;
    if (std::strncmp(name, "ro.cm.", 6) == 0)                return true;
    if (std::strncmp(name, "persist.sys.lineage.", 20) == 0) return true;
    return false;
}

inline bool should_hide_prop(const char* name) {
    return is_emulator_prop(name) || is_custom_rom_prop(name);
}

inline bool is_native_unsafe_prop(const char* name) {
    if (!name) return false;

    static const char* const exact[] = {
        "ro.hardware",
        "ro.product.board",
        "ro.board.platform",
        "ro.arch",
        "ro.zygote",
        "ro.vendor.api_level",
        "persist.graphics.egl",
        "ro.product.cpu.abi",
        "ro.product.cpu.abi2",
        "ro.product.cpu.abilist",
        "ro.product.cpu.abilist32",
        "ro.product.cpu.abilist64",
    };
    for (const char* e : exact) if (std::strcmp(name, e) == 0) return true;

    if (std::strncmp(name, "ro.hardware.", 12) == 0)      return true;
    if (std::strncmp(name, "ro.dalvik.vm.isa.", 17) == 0) return true;
    if (std::strncmp(name, "dalvik.vm.isa.", 14) == 0)    return true;
    return false;
}

}
