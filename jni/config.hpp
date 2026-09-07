#pragma once

#include <cstdint>
#include <cstddef>
#include <unistd.h>
#include <cerrno>

namespace sandboxid {

#ifndef SBX_MODULE_ID
#define SBX_MODULE_ID "sandboxid"
#endif
#define SBX_MODDIR "/data/adb/modules/" SBX_MODULE_ID

inline constexpr char MODDIR[]        = SBX_MODDIR;
inline constexpr char IDENTITY_FILE[] = SBX_MODDIR "/identity.prop";
inline constexpr char MOUNTDIR[]      = SBX_MODDIR "/mount";
inline constexpr char TARGET_FILE[]   = SBX_MODDIR "/target.txt";

inline constexpr char PERSONAS_FILE[] = SBX_MODDIR "/personas.tsv";

inline constexpr char PERSONA_OVERRIDE[] = SBX_MODDIR "/persona.override";

inline constexpr char IDENTITY_BAK[]  = SBX_MODDIR "/identity.prop.bak";
inline constexpr char MODE_FILE[]     = SBX_MODDIR "/identity.mode";

inline constexpr char CARRIER_CONF[]  = SBX_MODDIR "/carrier.conf";
inline constexpr char CARRIERS_FILE[] = SBX_MODDIR "/carriers.tsv";
inline constexpr char RESETPROP[]     = SBX_MODDIR "/bin/resetprop-rs";

inline constexpr char ENABLE_HIDE[]   = SBX_MODDIR "/enable_hide";

enum Cmd : uint8_t {
    CMD_GET_IDENTITY = 2,
    CMD_DO_MOUNTS    = 3,
    CMD_DO_HIDE      = 4,
};

inline constexpr uint32_t MAX_IDENTITY_BLOB = 64u * 1024u;

struct BindEntry { const char* src_rel; const char* dst; };

inline constexpr BindEntry BIND_ENTRIES[] = {
    {"system/build.prop",     "/system/build.prop"},
    {"vendor/build.prop",     "/vendor/build.prop"},
    {"odm/build.prop",        "/odm/etc/build.prop"},
    {"odm/build.prop",        "/odm/build.prop"},
    {"product/build.prop",    "/product/etc/build.prop"},
    {"product/build.prop",    "/product/build.prop"},
    {"system_ext/build.prop", "/system_ext/etc/build.prop"},
    {"system_ext/build.prop", "/system_ext/build.prop"},

    {"settings_secure.xml",   "/data/system/users/0/settings_secure.xml"},
};
inline constexpr size_t BIND_ENTRIES_N = sizeof(BIND_ENTRIES) / sizeof(BIND_ENTRIES[0]);

inline constexpr const char* MOUNT_PARTS[] = {"system", "vendor", "odm", "product", "system_ext"};
inline constexpr size_t MOUNT_PARTS_N = sizeof(MOUNT_PARTS) / sizeof(MOUNT_PARTS[0]);

struct KV { const char* k; const char* v; };

inline constexpr KV VAL_DEFAULTS[] = {
    {"SYS_BOOT_COMPLETED",     "1"},
    {"GSM_OPERATOR_NUMERIC",   "51010"},
    {"GSM_OPERATOR_ALPHA",     "Telkomsel"},
    {"GSM_OPERATOR_ISO",       "id"},
    {"GSM_CARRIER_ID",         "787"},
    {"GSM_SIM_STATE",          ""},
    {"BUILD_CHARACTERISTICS",  "default"},
    {"PERSIST_TIMEZONE",       "Asia/Jakarta"},
    {"CPU_ABI",                "arm64-v8a"},
    {"CPU_ABI2",               ""},
    {"SUPPORTED_ABIS",         "arm64-v8a,armeabi-v7a,armeabi"},
    {"SUPPORTED_64_BIT_ABIS",  "arm64-v8a"},
    {"SUPPORTED_32_BIT_ABIS",  "armeabi-v7a,armeabi"},
    {"DALVIK_HEAPGROWTHLIMIT", "256m"},
    {"MEDIACODEC_MIN_RATE",    "8000"},
    {"MEDIACODEC_MAX_RATE",    "192000"},
    {"DEBUG_FORCE_RTL",        "false"},
    {"MULTISIM_CONFIG",        ""},
};
inline constexpr size_t VAL_DEFAULTS_N = sizeof(VAL_DEFAULTS) / sizeof(VAL_DEFAULTS[0]);

struct SimCarrier { const char* alpha; const char* numeric; const char* iso; const char* carrier_id; };
inline constexpr SimCarrier ID_CARRIERS[] = {
    // Indonesia
    {"Telkomsel", "51010", "id", "787"},
    {"Indosat",   "51021", "id", "789"},
    {"XL",        "51011", "id", "788"},
    {"Axis",      "51008", "id", "788"},
    {"Tri",       "51089", "id", ""},
    {"Smartfren", "51009", "id", ""},
    // US
    {"T-Mobile",  "310260", "us", "1"},
    {"AT&T",      "310410", "us", "3"},
    {"Verizon",   "311480", "us", "4"},
    // India
    {"Jio",       "40588", "in", ""},
    {"Airtel",    "40410", "in", ""},
    {"Vi",        "40411", "in", ""},
    // EU
    {"Vodafone",  "26202", "de", ""},
    {"T-Mobile DE","26201","de", ""},
    {"O2 DE",     "26207", "de", ""},
    {"EE",        "23430", "gb", ""},
    {"Three UK",  "23420", "gb", ""},
    // Australia
    {"Telstra",   "50501", "au", ""},
    {"Optus",     "50502", "au", ""},
    // Japan
    {"NTT Docomo","44010", "jp", ""},
    {"SoftBank",  "44020", "jp", ""},
    // Brazil
    {"Claro BR",  "72405", "br", ""},
    {"Vivo BR",   "72406", "br", ""},
    // Thailand
    {"AIS",       "52001", "th", ""},
    {"TrueMove",  "52004", "th", ""},
    // Malaysia
    {"Maxis",     "50212", "my", ""},
    {"Celcom",    "50213", "my", ""},
    // Philippines
    {"Globe",     "51502", "ph", ""},
    {"Smart",     "51503", "ph", ""},
};
inline constexpr size_t ID_CARRIERS_N = sizeof(ID_CARRIERS) / sizeof(ID_CARRIERS[0]);

inline constexpr KV STATIC_PROP_DEFAULTS[] = {
    {"gsm.operator.isroaming",       "false"},
    {"ro.zygote",                    "zygote64_32"},
    {"ro.dalvik.vm.native.bridge",   "0"},
    {"ro.allow.mock.location",       "0"},
    {"dalvik.vm.isa.arm64.variant",  "generic"},
    {"dalvik.vm.isa.arm64.features", "default"},
    {"dalvik.vm.isa.arm.variant",    "generic"},
    {"dalvik.vm.isa.arm.features",   "default"},
    {"dalvik.vm.heapsize",           "512m"},
    {"ro.build.version.preview_sdk", "0"},

    {"ro.build.version.codename",       "REL"},
    {"ro.build.version.all_codenames",  "REL"},

    {"ro.boot.verifiedbootstate",       "green"},
    {"ro.boot.vbmeta.device_state",     "locked"},
    {"ro.boot.flash.locked",            "1"},
    {"ro.boot.veritymode",              "enforcing"},
    {"ro.boot.vbmeta.hash_alg",         "sha256"},
    {"ro.boot.vbmeta.avb_version",      "1.0"},
    {"ro.boot.vbmeta.invalidate_on_error", "yes"},
    {"ro.secure",                       "1"},
    {"ro.debuggable",                   "0"},
    {"ro.build.selinux",                "1"},
    {"sys.oem_unlock_allowed",          "0"},
};
inline constexpr size_t STATIC_PROP_DEFAULTS_N =
    sizeof(STATIC_PROP_DEFAULTS) / sizeof(STATIC_PROP_DEFAULTS[0]);

inline bool read_full(int fd, void* buf, size_t n) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::read(fd, p + got, n - got);
        if (r > 0) { got += static_cast<size_t>(r); continue; }
        if (r < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

inline bool write_full(int fd, const void* buf, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t put = 0;
    while (put < n) {
        ssize_t w = ::write(fd, p + put, n - put);
        if (w > 0) { put += static_cast<size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

template<typename Container>
inline void parse_target_lines(const char* data, size_t len, Container& out) {
    const char* p = data;
    const char* end = data + len;
    while (p < end) {
        const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
        if (!nl) nl = end;
        size_t ll = nl - p;
        if (ll > 0 && p[ll - 1] == '\r') --ll;
        const char* hash = static_cast<const char*>(memchr(p, '#', ll));
        if (hash) ll = hash - p;
        while (ll > 0 && (p[ll-1] == ' ' || p[ll-1] == '\t')) --ll;
        size_t s = 0;
        while (s < ll && (p[s] == ' ' || p[s] == '\t')) ++s;
        if (s < ll) {
            out.insert(out.end(), std::string(p + s, ll - s));
        }
        p = nl + 1;
    }
}

}
