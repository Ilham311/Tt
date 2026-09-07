
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "config.hpp"
#include "sbx_carrier.hpp"
#include "sbx_native_read.hpp"
#include <sys/system_properties.h>

static const char* IDENTITY_FILE  = sandboxid::IDENTITY_FILE;
static const char* IDENTITY_BAK   = sandboxid::IDENTITY_BAK;
static const char* MODE_FILE      = sandboxid::MODE_FILE;
static const char* RESETPROP      = sandboxid::RESETPROP;
static const char* MOUNTDIR       = sandboxid::MOUNTDIR;
static const char* TARGET_FILE    = sandboxid::TARGET_FILE;
static const char* PERSONAS_FILE  = sandboxid::PERSONAS_FILE;
static const char* PERSONA_OVERRIDE = sandboxid::PERSONA_OVERRIDE;
static const char* CARRIER_CONF   = sandboxid::CARRIER_CONF;

static std::vector<std::string> load_targets() {
    std::vector<std::string> out;
    std::string data = read_file(TARGET_FILE);
    if (!data.empty())
        sandboxid::parse_target_lines(data.data(), data.size(), out);
    return out;
}

static std::string random_hex(int bytes, bool upper) {
    std::random_device rd;
    std::mt19937_64 gen(rd() ^ (uint64_t)std::chrono::steady_clock::now()
                              .time_since_epoch().count());
    std::uniform_int_distribution<int> d(0, 15);
    const char* al = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string s;
    s.reserve(bytes * 2);
    for (int i = 0; i < bytes * 2; ++i) s.push_back(al[d(gen)]);
    return s;
}

static bool atomic_write(const std::string& p, const std::string& data) {
    std::string tmp = p + ".tmp." + std::to_string((long)::getpid());
    ::unlink(tmp.c_str());

    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    bool ok = true;
    for (size_t off = 0; off < data.size(); ) {
        ssize_t w = ::write(fd, data.data() + off, data.size() - off);
        if (w < 0) { if (errno == EINTR) continue; ok = false; break; }
        off += (size_t)w;
    }
    ::fsync(fd);
    ::close(fd);
    if (!ok) { ::unlink(tmp.c_str()); return false; }
    if (::rename(tmp.c_str(), p.c_str()) != 0) { ::unlink(tmp.c_str()); return false; }
    size_t slash = p.find_last_of('/');
    std::string dir = (slash == std::string::npos) ? std::string(".")
                      : (slash == 0 ? std::string("/") : p.substr(0, slash));
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    return true;
}

static std::string read_file(const std::string& p) {
    std::ifstream f(p);
    if (!f) return "";
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string trim(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    size_t st = s.find_first_not_of(" \t");
    if (st != std::string::npos) s = s.substr(st);
    return s;
}

static int run_bin(const char* path, std::vector<const char*> argv, bool null_io = false) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (null_io) {
            int nul = ::open("/dev/null", O_RDWR | O_CLOEXEC);
            if (nul >= 0) {
                dup2(nul, STDIN_FILENO);
                dup2(nul, STDOUT_FILENO);
                dup2(nul, STDERR_FILENO);
                if (nul > STDERR_FILENO) ::close(nul);
            }
        }
        argv.push_back(nullptr);
        execv(path, const_cast<char* const*>(argv.data()));
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int run_bin_path(const char* file, std::vector<const char*> argv) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        argv.push_back(nullptr);
        execvp(file, const_cast<char* const*>(argv.data()));
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void wait_boot_completed(int max_ms) {
    char b[PROP_VALUE_MAX];
    for (int waited = 0; waited < max_ms; waited += 200) {
        b[0] = 0;
        if (__system_property_get("sys.boot_completed", b) > 0 && b[0] == '1')
            return;
        ::usleep(200 * 1000);
    }
}

static int run_framework(const char* path, std::vector<const char*> argv,
                         const std::string& label) {
    const int attempts = 2;
    int rc = -1;
    for (int i = 0; i < attempts; ++i) {
        rc = run_bin(path, argv, true);
        if (rc == 0) return 0;
        if (i + 1 < attempts) ::usleep(200 * 1000);
    }
    fprintf(stderr, "! %s gagal (exit=%d) setelah %d percobaan — binder transaction ditolak (SELinux/FD)\n",
            label.c_str(), rc, attempts);
    return rc;
}

struct Identity {
    std::map<std::string, std::string> kv;

    std::string serialize() const {
        static const std::vector<std::string> order = {
            "BRAND","MANUFACTURER","MODEL","MARKETNAME","DEVICE","PRODUCT",
            "BOARD","HARDWARE","BOARD_PLATFORM","SOC_MANUFACTURER","SOC_MODEL",
            "FINGERPRINT","ID","DISPLAY","DESCRIPTION",
            "BOOTLOADER","HOST","USER","TYPE","TAGS",
            "INCREMENTAL","RELEASE","SDK_INT","SECURITY_PATCH",
            "SERIAL","RADIO","ANDROID_ID","GOOGLE_AID",
            "GSM_OPERATOR_NUMERIC","GSM_OPERATOR_ALPHA","GSM_OPERATOR_ISO","GSM_SIM_STATE",
            "VBMETA_DIGEST",

            "SUPPORTED_ABIS","SUPPORTED_64_BIT_ABIS","SUPPORTED_32_BIT_ABIS",
            "CPU_ABI","CPU_ABI2","SKU","ODM_SKU","BASE_OS",
            "MEDIA_PERFORMANCE_CLASS","PREVIEW_SDK_INT","PREVIEW_SDK_FINGERPRINT",

            "BUILD_TIME_UTC","BUILD_DATE",

            "FLAVOR",

            "APPLOG_EPOCH",
        };
        std::string out;
        for (const auto& k : order) {
            auto it = kv.find(k);
            if (it != kv.end()) out += k + "=" + it->second + "\n";
        }

        for (const auto& kvp : kv) {
            bool known = false;
            for (const auto& k : order) if (k == kvp.first) { known = true; break; }
            if (!known) out += kvp.first + "=" + kvp.second + "\n";
        }
        return out;
    }
};

static std::string uuid_v4() {
    std::string h = random_hex(16, false);
    h.insert(20, "-");
    h.insert(16, "-");
    h.insert(12, "-");
    h.insert(8, "-");
    h[14] = '4';
    static const char* v = "89ab";
    std::random_device rd;
    std::mt19937 g(rd());
    h[19] = v[g() % 4];
    return h;
}

static int device_sdk() {
    char b[PROP_VALUE_MAX] = {0};
    if (__system_property_get("ro.build.version.sdk", b) > 0) return atoi(b);
    return 0;
}

static std::string gen_host_suffix() {
    std::random_device rd;
    std::mt19937 g(rd());
    static const char* prefixes[] = {
        "abfarm", "abfarm-release", "abfarm-server", "build", "build-server",
        "release", "release-server", "farm", "buildfarm",
    };
    constexpr int n_prefixes = sizeof(prefixes) / sizeof(prefixes[0]);
    std::string host = prefixes[g() % n_prefixes];

    host += "-";
    host += std::to_string(g() % 900 + 100);
    return host;
}

struct PixelEntry {
    std::string model, device, product, board, platform;
    int         sdk = 0;
    std::string release, id, incremental, security_patch;

    std::string brand, manufacturer, marketname, soc_manufacturer, soc_model, radio;
};

static bool is_tensor_platform(const std::string& plat) {
    return plat == "gs101" || plat == "gs201" || plat == "zuma" ||
           plat == "zumapro" || plat == "laguna";
}

static long long build_utc_from_patch(const std::string& patch,
                                      const std::string& incremental) {
    if (patch.size() < 10 || patch[4] != '-' || patch[7] != '-') return 0;
    const int y = atoi(patch.substr(0, 4).c_str());
    const int m = atoi(patch.substr(5, 2).c_str());
    const int d = atoi(patch.substr(8, 2).c_str());
    if (y < 2008 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return 0;

    int digits = 0;
    for (char c : incremental) if (c >= '0' && c <= '9') digits += c - '0';

    struct tm tmv{};
    tmv.tm_year = y - 1900;
    tmv.tm_mon  = m - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = 3;
    time_t t = timegm(&tmv);
    if (t == (time_t)-1) return 0;

    t -= (time_t)(1 + digits % 6) * 86400;
    t += (time_t)(digits % 60) * 60 + (time_t)(digits % 37);
    return (long long)t;
}

static std::string build_date_string(long long utc) {
    if (utc <= 0) return "";
    time_t t = (time_t)utc;
    struct tm tmv{};
    if (!gmtime_r(&t, &tmv)) return "";
    char buf[64];
    if (strftime(buf, sizeof(buf), "%a %b %e %H:%M:%S UTC %Y", &tmv) == 0) return "";
    return buf;
}

static std::vector<PixelEntry> builtin_personas() {
    std::vector<PixelEntry> v;

    auto add = [&](const char* mo, const char* de, const char* pl, int sd,
                   const char* re, const char* id, const char* in, const char* sp) {
        PixelEntry e; e.model = mo; e.device = de; e.product = de; e.board = de;
        e.platform = pl; e.sdk = sd; e.release = re; e.id = id;
        e.incremental = in; e.security_patch = sp; v.push_back(std::move(e));
    };
    add("Pixel 6",  "oriole",  "gs101",  31, "12", "SD1A.210817.036", "7805805",  "2021-10-05");
    add("Pixel 6",  "oriole",  "gs101",  33, "13", "TQ3A.230901.001", "10750268", "2023-09-05");
    add("Pixel 8",  "shiba",   "zuma",   35, "15", "AP3A.240905.015", "12244875", "2024-09-05");
    add("Pixel 10", "frankel", "laguna", 36, "16", "BP1A.250705.006", "13051207", "2025-07-05");
    return v;
}

static bool parse_persona_line(const std::string& raw, PixelEntry& out) {
    std::string line = raw;
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    if (line.empty() || line[0] == '#') return false;

    std::vector<std::string> col;
    std::string cur;
    std::istringstream ss(line);
    while (std::getline(ss, cur, '\t')) col.push_back(cur);
    if (col.size() < 10) return false;

    out.model          = col[0];
    out.device         = col[1];
    out.product        = col[2];
    out.board          = col[3];
    out.platform       = col[4];
    out.sdk            = atoi(col[5].c_str());
    out.release        = col[6];
    out.id             = col[7];
    out.incremental    = col[8];
    out.security_patch = col[9];

    if (col.size() > 10) out.brand            = col[10];
    if (col.size() > 11) out.manufacturer     = col[11];
    if (col.size() > 12) out.marketname       = col[12];
    if (col.size() > 13) out.soc_manufacturer = col[13];
    if (col.size() > 14) out.soc_model        = col[14];
    if (col.size() > 15) out.radio            = col[15];

    if (out.device.empty() || out.sdk <= 0) return false;

    if (!is_tensor_platform(out.platform)) {
        if (out.brand.empty() || out.soc_model.empty()) {
            fprintf(stderr,
                    "! persona '%s' has non-Tensor platform '%s' but is missing "
                    "brand/soc_model columns — skipping\n",
                    out.device.c_str(), out.platform.c_str());
            return false;
        }
    }
    return true;
}

static std::vector<PixelEntry> load_personas() {
    std::vector<PixelEntry> pool;
    std::ifstream f(PERSONAS_FILE);
    std::string line;
    while (std::getline(f, line)) {
        PixelEntry e;
        if (parse_persona_line(line, e)) pool.push_back(std::move(e));
    }
    if (pool.empty()) {
        fprintf(stderr,
                "! persona pool empty/unreadable (%s) — using built-in fallback\n",
                PERSONAS_FILE);
        pool = builtin_personas();
    }
    return pool;
}

static PixelEntry pick_persona() {
    std::random_device rd;
    std::mt19937 g(rd());

    std::vector<PixelEntry> pool = load_personas();
    const size_t N = pool.size();

    int dev = device_sdk();

    std::vector<size_t> cand;
    for (size_t i = 0; i < N; ++i)
        if (dev > 0 && pool[i].sdk == dev) cand.push_back(i);

    if (cand.empty()) {

        fprintf(stderr, "! tidak ada persona SDK %d persis — fallback SDK lebih rendah, "
                "TERIMA RISIKO inkonsistensi lintas-permukaan "
                "(SDK_INT vs RELEASE vs FINGERPRINT)\n", dev);
        for (size_t i = 0; i < N; ++i)
            if (dev > 0 && pool[i].sdk <= dev) cand.push_back(i);
    }

    size_t idx;
    if (!cand.empty()) {
        idx = cand[g() % cand.size()];
    } else {

        idx = 0;
        for (size_t i = 1; i < N; ++i) if (pool[i].sdk < pool[idx].sdk) idx = i;
        fprintf(stderr, "! device SDK %d below all personas; using SDK %d (upgrade, risky)\n",
                dev, pool[idx].sdk);
    }
    return pool[idx];
}

static Identity derive_identity(const PixelEntry& p) {
    const bool tensor = is_tensor_platform(p.platform);

    auto tensor_soc_model = [](const std::string& plat) -> const char* {
        if (plat == "gs101")   return "GS101";
        if (plat == "gs201")   return "GS201";
        if (plat == "zuma")    return "GS301";
        if (plat == "zumapro") return "GS401";
        if (plat == "laguna")  return "GS501";
        return "unknown";
    };
    auto tensor_modem_prefix = [](const std::string& plat) -> const char* {
        if (plat == "gs101")   return "g5123b";
        if (plat == "gs201")   return "g5300b";
        if (plat == "zuma")    return "g5300q";
        if (plat == "zumapro") return "g5400";
        if (plat == "laguna")  return "g5500";
        return "unknown";
    };

    const std::string brand   = p.brand.empty()        ? "google" : p.brand;
    const std::string manuf   = p.manufacturer.empty() ? "Google" : p.manufacturer;
    const std::string soc_man = !p.soc_manufacturer.empty() ? p.soc_manufacturer
                                : (tensor ? "Google" : std::string());
    const std::string soc_mod = !p.soc_model.empty() ? p.soc_model
                                : (tensor ? tensor_soc_model(p.platform) : std::string());

    Identity id;
    id.kv["BRAND"]           = brand;
    id.kv["MANUFACTURER"]    = manuf;
    id.kv["MODEL"]           = p.model;

    id.kv["MARKETNAME"]      = p.marketname.empty() ? p.model : p.marketname;
    id.kv["DEVICE"]          = p.device;
    id.kv["PRODUCT"]         = p.product;
    id.kv["BOARD"]           = p.board;
    id.kv["HARDWARE"]        = p.board;
    id.kv["BOARD_PLATFORM"]  = p.platform;
    id.kv["SOC_MANUFACTURER"] = soc_man;
    id.kv["SOC_MODEL"]       = soc_mod;
    id.kv["ID"]              = p.id;
    id.kv["INCREMENTAL"]     = p.incremental;
    id.kv["RELEASE"]         = p.release;
    id.kv["SDK_INT"]         = std::to_string(p.sdk);
    id.kv["SECURITY_PATCH"]  = p.security_patch;
    id.kv["BOOTLOADER"]      = "unknown";
    id.kv["HOST"]            = gen_host_suffix();
    id.kv["USER"]            = "android-build";
    id.kv["TYPE"]            = "user";
    id.kv["TAGS"]            = "release-keys";

    id.kv["FLAVOR"]          = p.product + "-" + id.kv["TYPE"];

    char fp[512];
    snprintf(fp, sizeof(fp), "%s/%s/%s:%s/%s/%s:user/release-keys",
             brand.c_str(), p.product.c_str(), p.device.c_str(),
             p.release.c_str(), p.id.c_str(), p.incremental.c_str());
    id.kv["FINGERPRINT"] = fp;
    id.kv["DISPLAY"]     = p.id;

    char desc[512];
    snprintf(desc, sizeof(desc), "%s-user %s %s %s release-keys",
             p.product.c_str(), p.release.c_str(), p.id.c_str(), p.incremental.c_str());
    id.kv["DESCRIPTION"] = desc;

    if (!p.radio.empty()) {
        id.kv["RADIO"] = p.radio;
    } else if (tensor) {
        char pdate[8] = "000000";
        if (p.security_patch.size() >= 10) {
            pdate[0] = p.security_patch[2]; pdate[1] = p.security_patch[3];
            pdate[2] = p.security_patch[5]; pdate[3] = p.security_patch[6];
            pdate[4] = p.security_patch[8]; pdate[5] = p.security_patch[9];
        }
        char rad[128];
        snprintf(rad, sizeof(rad), "%s-%s-B-%s",
                 tensor_modem_prefix(p.platform), pdate, p.incremental.c_str());
        id.kv["RADIO"] = rad;
    }

    id.kv["SERIAL"]     = random_hex(8, true);
    id.kv["ANDROID_ID"] = random_hex(8, false);
    id.kv["GOOGLE_AID"] = uuid_v4();

    {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::system_clock::now().time_since_epoch()).count();
        if (now_ms <= 0) now_ms = 1700000000000LL;
        id.kv["APPLOG_EPOCH"] = std::to_string(now_ms);
    }

    {
        long long utc = build_utc_from_patch(p.security_patch, p.incremental);
        if (utc > 0) {
            id.kv["BUILD_TIME_UTC"] = std::to_string(utc);
            id.kv["BUILD_DATE"]     = build_date_string(utc);
        }
    }

    id.kv["VBMETA_DIGEST"] =
        sbxnr::hex_from_seed(sbxnr::fnv1a(id.kv["FINGERPRINT"] + "|" + id.kv["SERIAL"]), 32);

    id.kv["SUPPORTED_ABIS"]        = "arm64-v8a,armeabi-v7a,armeabi";
    id.kv["SUPPORTED_64_BIT_ABIS"] = "arm64-v8a";
    id.kv["SUPPORTED_32_BIT_ABIS"] = "armeabi-v7a,armeabi";
    id.kv["CPU_ABI"]               = "arm64-v8a";
    id.kv["CPU_ABI2"]              = "";

    id.kv["BASE_OS"] = "";

    auto mpc_for_model = [](const std::string& m) -> const char* {
        if (m.rfind("Pixel 9", 0) == 0)  return "35";
        if (m.rfind("Pixel 8", 0) == 0)  return "34";
        if (m.rfind("Pixel 7", 0) == 0)  return "33";
        if (m.rfind("Pixel 6", 0) == 0)  return "31";
        return "";
    };
    id.kv["MEDIA_PERFORMANCE_CLASS"] = mpc_for_model(p.model);

    id.kv["SKU"]     = "";
    id.kv["ODM_SKU"] = "";

    id.kv["PREVIEW_SDK_INT"]         = "0";
    id.kv["PREVIEW_SDK_FINGERPRINT"] = "REL";

    return id;
}

static Identity gen_identity() {
    return derive_identity(pick_persona());
}

static bool take_persona_override(PixelEntry& out) {
    std::string raw = read_file(PERSONA_OVERRIDE);
    if (raw.empty()) return false;
    bool ok = false;
    std::istringstream ss(raw);
    std::string line;
    while (std::getline(ss, line)) {
        if (parse_persona_line(line, out)) { ok = true; break; }
    }
    ::unlink(PERSONA_OVERRIDE);
    return ok;
}

#ifdef SBX_DEBUG
#define SBX_VARIANT_TAG "debug"
#define DBG(fmt, ...) fprintf(stderr, "[D] " fmt "\n", ##__VA_ARGS__)
#else
#define SBX_VARIANT_TAG "release"
#define DBG(...) ((void)0)
#endif

static void apply_native(const Identity& id) {
    DBG("apply_native: enter (identity has %zu kv pairs)", id.kv.size());
    auto get = [&](const char* k) -> std::string {
        auto it = id.kv.find(k);
        return it != id.kv.end() ? it->second : std::string();
    };

    struct Rp { const char* key; std::string val; bool del_if_empty = false; };

    const std::string SERIAL       = get("SERIAL");
    const std::string MODEL        = get("MODEL");
    const std::string BRAND        = get("BRAND");
    const std::string MANUFACTURER = get("MANUFACTURER");
    const std::string DEVICE       = get("DEVICE");
    const std::string PRODUCT      = get("PRODUCT");
    const std::string ID_          = get("ID");
    const std::string FP           = get("FINGERPRINT");
    const std::string DISPLAY      = get("DISPLAY");
    const std::string DESC         = get("DESCRIPTION");
    const std::string RELEASE      = get("RELEASE");
    const std::string SECPATCH     = get("SECURITY_PATCH");
    const std::string INCREMENTAL  = get("INCREMENTAL");
    const std::string RADIO        = get("RADIO");
    const std::string TAGS         = get("TAGS");
    const std::string TYPE         = get("TYPE");
    const std::string USER_        = get("USER");
    const std::string HOST         = get("HOST");
    const std::string SOC_MANUF    = get("SOC_MANUFACTURER");
    const std::string SOC_MODEL    = get("SOC_MODEL");
    const std::string MARKETNAME   = get("MARKETNAME");

    const std::string SKU        = get("SKU");
    const std::string ODM_SKU    = get("ODM_SKU");
    const std::string BASE_OS    = get("BASE_OS");
    const std::string MPC        = get("MEDIA_PERFORMANCE_CLASS");

    const std::string FLAVOR     = get("FLAVOR");
    const std::string BUILD_UTC  = get("BUILD_TIME_UTC");
    const std::string BUILD_DATE = get("BUILD_DATE");

    std::vector<Rp> rp = {
        {"ro.serialno",                        SERIAL},
        {"ro.boot.serialno",                   SERIAL},

        {"ro.build.fingerprint",               FP},
        {"ro.bootimage.build.fingerprint",     FP},
        {"ro.system.build.fingerprint",        FP},
        {"ro.vendor.build.fingerprint",        FP},
        {"ro.odm.build.fingerprint",           FP},
        {"ro.product.build.fingerprint",       FP},
        {"ro.system_ext.build.fingerprint",    FP},
        {"ro.vendor_dlkm.build.fingerprint",   FP},
        {"ro.odm_dlkm.build.fingerprint",      FP},

        {"ro.product.model",                   MODEL},
        {"ro.product.system.model",            MODEL},
        {"ro.product.vendor.model",            MODEL},
        {"ro.product.odm.model",               MODEL},
        {"ro.product.product.model",           MODEL},
        {"ro.product.system_ext.model",        MODEL},

        {"ro.product.brand",                   BRAND},
        {"ro.product.system.brand",            BRAND},
        {"ro.product.vendor.brand",            BRAND},
        {"ro.product.odm.brand",               BRAND},
        {"ro.product.product.brand",           BRAND},
        {"ro.product.system_ext.brand",        BRAND},

        {"ro.product.manufacturer",            MANUFACTURER},
        {"ro.product.system.manufacturer",     MANUFACTURER},
        {"ro.product.vendor.manufacturer",     MANUFACTURER},
        {"ro.product.odm.manufacturer",        MANUFACTURER},
        {"ro.product.product.manufacturer",    MANUFACTURER},
        {"ro.product.system_ext.manufacturer", MANUFACTURER},

        {"ro.product.device",                  DEVICE},
        {"ro.product.system.device",           DEVICE},
        {"ro.product.vendor.device",           DEVICE},
        {"ro.product.odm.device",              DEVICE},
        {"ro.product.product.device",          DEVICE},
        {"ro.product.system_ext.device",       DEVICE},

        {"ro.product.name",                    PRODUCT},
        {"ro.product.system.name",             PRODUCT},
        {"ro.product.vendor.name",             PRODUCT},
        {"ro.product.odm.name",                PRODUCT},
        {"ro.product.product.name",            PRODUCT},
        {"ro.product.system_ext.name",         PRODUCT},

        {"ro.build.product",                   DEVICE},

        {"ro.soc.manufacturer",                SOC_MANUF},
        {"ro.soc.model",                       SOC_MODEL},
        {"ro.product.marketname",              MARKETNAME},

        {"ro.product.brand_for_attestation",        BRAND},
        {"ro.product.name_for_attestation",         PRODUCT},
        {"ro.product.device_for_attestation",       DEVICE},
        {"ro.product.model_for_attestation",        MODEL},
        {"ro.product.manufacturer_for_attestation", MANUFACTURER},

        {"ro.build.id",                        ID_},
        {"ro.build.display.id",                DISPLAY},
        {"ro.build.description",               DESC},
        {"ro.build.tags",                      TAGS},
        {"ro.build.type",                      TYPE},
        {"ro.build.user",                      USER_},
        {"ro.build.host",                      HOST},
        {"ro.build.flavor",                    FLAVOR},
        {"ro.build.date.utc",                  BUILD_UTC},
        {"ro.build.date",                      BUILD_DATE},

        {"ro.build.version.codename",          std::string("REL")},
        {"ro.build.version.all_codenames",     std::string("REL")},

        {"ro.build.version.release",           RELEASE},
        {"ro.build.version.release_or_codename", RELEASE},
        {"ro.build.version.security_patch",    SECPATCH},
        {"ro.vendor.build.security_patch",     SECPATCH},
        {"ro.build.version.incremental",       INCREMENTAL},

        {"gsm.version.baseband",               RADIO, true},
        {"ro.build.expect.baseband",           RADIO, true},

        {"ro.bootloader",                      std::string("unknown")},
        {"ro.boot.bootloader",                 std::string("unknown")},

        {"ro.boot.verifiedbootstate",          std::string("green")},
        {"ro.boot.vbmeta.device_state",        std::string("locked")},
        {"ro.boot.flash.locked",               std::string("1")},
        {"ro.boot.veritymode",                 std::string("enforcing")},
        {"ro.boot.vbmeta.hash_alg",            std::string("sha256")},
        {"ro.boot.vbmeta.avb_version",         std::string("1.0")},
        {"ro.boot.vbmeta.invalidate_on_error", std::string("yes")},
        {"ro.boot.vbmeta.digest",              get("VBMETA_DIGEST")},
        {"ro.secure",                          std::string("1")},
        {"ro.debuggable",                      std::string("0")},
        {"ro.build.selinux",                   std::string("1")},

        {"sys.oem_unlock_allowed",             std::string("0")},

        {"ro.boot.hardware.sku",               SKU},
        {"ro.boot.product.hardware.sku",       ODM_SKU},

        {"ro.build.version.base_os",           BASE_OS},
        {"ro.build.version.preview_sdk",       std::string("0")},
        {"ro.build.version.preview_sdk_fingerprint", std::string("REL")},

        {"ro.odm.build.media_performance_class", MPC},
    };

    bool have_bundled = (::access(RESETPROP, X_OK) == 0);
    {
        // H07: batch all resetprop calls into a single fork+shell instead of 70 fork+exec
        std::string script = "#!/system/bin/sh\nA=0;F=0\n";
        auto shq = [](const std::string& s) -> std::string {
            std::string o = "'";
            for (char c : s) {
                if (c == '\'') o += "'\\''";
                else o += c;
            }
            o += "'";
            return o;
        };
        std::string rp_bin;
        if (have_bundled) {
            rp_bin = RESETPROP;
        } else {
            rp_bin = "resetprop-rs";
            script += "command -v resetprop-rs >/dev/null 2>&1 || ";
            script += "{ command -v resetprop >/dev/null 2>&1 && rp=resetprop; }\n";
        }

        int prop_count = 0;
        for (const auto& r : rp) {
            if (r.val.empty() && !r.del_if_empty) continue;
            prop_count++;
            if (r.val.empty()) {
                script += shq(rp_bin) + " --delete " + shq(r.key) + " && A=$((A+1)) || F=$((F+1))\n";
            } else {
                script += shq(rp_bin) + " -n " + shq(r.key) + " " + shq(r.val) + " && A=$((A+1)) || F=$((F+1))\n";
            }
        }
        script += "printf '%d %d' \"$A\" \"$F\"\n";

        if (prop_count > 0) {
            std::string tmp = std::string(MODDIR) + "/.apply_props.sh";
            {
                int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
                if (fd >= 0) {
                    ::write(fd, script.data(), script.size());
                    ::close(fd);
                }
            }
            int pipefd[2];
            bool piped = (::pipe(pipefd) == 0);
            pid_t pid = ::fork();
            if (pid == 0) {
                if (piped) {
                    ::close(pipefd[0]);
                    ::dup2(pipefd[1], STDOUT_FILENO);
                    ::close(pipefd[1]);
                }
                ::execl("/system/bin/sh", "sh", tmp.c_str(), nullptr);
                ::_exit(127);
            }
            int applied = 0, failed = 0;
            if (pid > 0) {
                if (piped) ::close(pipefd[1]);
                char buf[64] = {};
                if (piped) {
                    ssize_t n = ::read(pipefd[0], buf, sizeof(buf) - 1);
                    if (n > 0) buf[n] = '\0';
                    ::close(pipefd[0]);
                }
                ::waitpid(pid, nullptr, 0);
                ::sscanf(buf, "%d %d", &applied, &failed);
            } else {
                if (piped) { ::close(pipefd[0]); ::close(pipefd[1]); }
            }
            ::unlink(tmp.c_str());
            printf("  Native prop: %d ok, %d gagal%s\n", applied, failed,
                   have_bundled ? "" : " [fallback PATH]");
            if (applied == 0 && failed > 0)
                fprintf(stderr, "! SEMUA resetprop gagal%s — cek ketersediaan resetprop / resetprop-rs\n",
                        have_bundled ? "" : " (bundled absent + PATH fallback gagal)");
        }
    }

    std::string aid = get("ANDROID_ID");
    if (!aid.empty() || !MODEL.empty()) {
        wait_boot_completed(5000);
        int sok = 0, sfail = 0;
        if (!aid.empty()) {
            int rc = run_framework("/system/bin/settings",
                    {"settings", "put", "--user", "0", "secure", "android_id", aid.c_str()},
                    "settings put secure android_id");
            if (rc == 0) sok++; else sfail++;
        }
        if (!MODEL.empty()) {

            int rc1 = run_framework("/system/bin/settings",
                    {"settings", "put", "--user", "0", "global", "device_name", MODEL.c_str()},
                    "settings put global device_name");
            if (rc1 == 0) sok++; else sfail++;

            int rc2 = run_framework("/system/bin/settings",
                    {"settings", "put", "--user", "0", "system", "device_name", MODEL.c_str()},
                    "settings put system device_name");

            if (rc2 == 0) {
                sok++;
            } else if (rc1 != 0) {
                sfail++;
            }
        }
        printf("  Settings put: %d ok, %d gagal\n", sok, sfail);
    }
}

static void generate_mount_files(const Identity& id) {
    DBG("generate_mount_files: MOUNTDIR=%s", MOUNTDIR);
    auto g = [&](const char* k) -> std::string {
        auto it = id.kv.find(k);
        return it != id.kv.end() ? it->second : std::string();
    };

    ::mkdir(MOUNTDIR, 0755);
    for (size_t i = 0; i < sandboxid::MOUNT_PARTS_N; ++i) {
        std::string d = std::string(MOUNTDIR) + "/" + sandboxid::MOUNT_PARTS[i];
        ::mkdir(d.c_str(), 0755);
    }

    const std::string SERIAL       = g("SERIAL");
    const std::string MODEL        = g("MODEL");
    const std::string BRAND        = g("BRAND");
    const std::string MANUFACTURER = g("MANUFACTURER");
    const std::string DEVICE       = g("DEVICE");
    const std::string PRODUCT      = g("PRODUCT");
    const std::string BOARD        = g("BOARD");
    const std::string ID_          = g("ID");
    const std::string FP           = g("FINGERPRINT");
    const std::string DISPLAY      = g("DISPLAY");
    const std::string DESC         = g("DESCRIPTION");
    const std::string RELEASE      = g("RELEASE");
    const std::string SDK          = g("SDK_INT");
    const std::string SECPATCH     = g("SECURITY_PATCH");
    const std::string INCREMENTAL  = g("INCREMENTAL");
    const std::string RADIO        = g("RADIO");
    const std::string TAGS         = g("TAGS");
    const std::string TYPE         = g("TYPE");
    const std::string USER_        = g("USER");
    const std::string HOST         = g("HOST");
    const std::string HARDWARE     = g("HARDWARE");
    const std::string PLATFORM     = g("BOARD_PLATFORM");
    const std::string SOC_MANUF    = g("SOC_MANUFACTURER");
    const std::string SOC_MODEL    = g("SOC_MODEL");
    const std::string MARKETNAME   = g("MARKETNAME");

    std::string base;
    base += "# begin build properties\n";
    auto add = [&](const char* k, const std::string& v) {
        if (!v.empty()) { base += k; base += '='; base += v; base += '\n'; }
    };
    add("ro.serialno",                        SERIAL);
    add("ro.boot.serialno",                   SERIAL);
    add("ro.build.fingerprint",               FP);
    add("ro.bootimage.build.fingerprint",     FP);
    add("ro.system.build.fingerprint",        FP);
    add("ro.vendor.build.fingerprint",        FP);
    add("ro.odm.build.fingerprint",           FP);
    add("ro.product.build.fingerprint",       FP);
    add("ro.system_ext.build.fingerprint",    FP);
    add("ro.vendor_dlkm.build.fingerprint",   FP);
    add("ro.odm_dlkm.build.fingerprint",      FP);
    add("ro.product.model",                   MODEL);
    add("ro.product.brand",                   BRAND);
    add("ro.product.manufacturer",            MANUFACTURER);
    add("ro.product.device",                  DEVICE);
    add("ro.product.name",                    PRODUCT);
    add("ro.product.board",                   BOARD);
    add("ro.hardware",                        HARDWARE);
    add("ro.board.platform",                  PLATFORM);
    add("ro.soc.manufacturer",                SOC_MANUF);
    add("ro.soc.model",                       SOC_MODEL);
    add("ro.product.marketname",              MARKETNAME);
    add("ro.product.brand_for_attestation",        BRAND);
    add("ro.product.name_for_attestation",         PRODUCT);
    add("ro.product.device_for_attestation",       DEVICE);
    add("ro.product.model_for_attestation",        MODEL);
    add("ro.product.manufacturer_for_attestation", MANUFACTURER);
    add("ro.build.id",                        ID_);
    add("ro.build.display.id",                DISPLAY);
    add("ro.build.description",               DESC);
    add("ro.build.tags",                      TAGS);
    add("ro.build.type",                      TYPE);
    add("ro.build.user",                      USER_);
    add("ro.build.host",                      HOST);
    add("ro.build.flavor",                    g("FLAVOR"));
    add("ro.build.date.utc",                  g("BUILD_TIME_UTC"));
    add("ro.build.date",                      g("BUILD_DATE"));
    add("ro.build.version.codename",          std::string("REL"));
    add("ro.build.version.all_codenames",     std::string("REL"));
    add("ro.build.version.release",           RELEASE);
    add("ro.build.version.release_or_codename", RELEASE);
    add("ro.build.version.sdk",               SDK);
    add("ro.build.version.security_patch",    SECPATCH);
    add("ro.build.version.incremental",       INCREMENTAL);

    add("ro.build.version.base_os",           g("BASE_OS"));
    add("ro.build.version.preview_sdk",       std::string("0"));
    add("ro.build.version.preview_sdk_fingerprint", std::string("REL"));
    add("ro.odm.build.media_performance_class", g("MEDIA_PERFORMANCE_CLASS"));

    add("ro.product.cpu.abilist",             g("SUPPORTED_ABIS"));
    add("ro.product.cpu.abilist32",           g("SUPPORTED_32_BIT_ABIS"));
    add("ro.product.cpu.abilist64",           g("SUPPORTED_64_BIT_ABIS"));
    add("ro.product.cpu.abi",                 g("CPU_ABI"));
    add("ro.product.cpu.abi2",                g("CPU_ABI2"));
    add("ro.boot.hardware.sku",               g("SKU"));
    add("ro.boot.product.hardware.sku",       g("ODM_SKU"));

    add("ro.bootloader",                      std::string("unknown"));
    add("ro.boot.bootloader",                 std::string("unknown"));
    add("ro.build.product",                   DEVICE);
    add("gsm.version.baseband",               RADIO);
    add("ro.build.expect.baseband",           RADIO);

    add("ro.boot.verifiedbootstate",          std::string("green"));
    add("ro.boot.vbmeta.device_state",        std::string("locked"));
    add("ro.boot.flash.locked",               std::string("1"));
    add("ro.boot.veritymode",                 std::string("enforcing"));
    add("ro.boot.vbmeta.hash_alg",            std::string("sha256"));
    add("ro.boot.vbmeta.avb_version",         std::string("1.0"));
    add("ro.boot.vbmeta.invalidate_on_error", std::string("yes"));
    add("ro.boot.vbmeta.digest",              g("VBMETA_DIGEST"));
    add("ro.secure",                          std::string("1"));
    add("ro.debuggable",                      std::string("0"));
    add("ro.build.selinux",                   std::string("1"));

    struct { const char* dir; const char* pfx; } parts[] = {
        {"system",     "ro.product.system."},
        {"vendor",     "ro.product.vendor."},
        {"odm",        "ro.product.odm."},
        {"product",    "ro.product.product."},
        {"system_ext", "ro.product.system_ext."},
    };
    for (const auto& p : parts) {
        std::string c = base;
        std::string pfx = p.pfx;
        if (!MODEL.empty())        c += pfx + "model="        + MODEL        + "\n";
        if (!BRAND.empty())        c += pfx + "brand="        + BRAND        + "\n";
        if (!MANUFACTURER.empty()) c += pfx + "manufacturer=" + MANUFACTURER + "\n";
        if (!DEVICE.empty())       c += pfx + "device="       + DEVICE       + "\n";
        if (!PRODUCT.empty())      c += pfx + "name="         + PRODUCT      + "\n";
        std::string path = std::string(MOUNTDIR) + "/" + p.dir + "/build.prop";
        atomic_write(path, c);
        ::chmod(path.c_str(), 0644);
    }

    std::string aid  = g("ANDROID_ID");
    std::string gaid = g("GOOGLE_AID");
    if (aid.empty()) aid = "0000000000000000";

    std::string xml;
    xml += "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n";
    xml += "<settings version=\"217\">\n";
    xml += "  <setting id=\"1\" name=\"android_id\" value=\"" + aid
         + "\" package=\"android\" defaultValue=\"" + aid
         + "\" defaultSysSet=\"true\" />\n";
    if (!gaid.empty()) {
        xml += "  <setting id=\"2\" name=\"advertising_id\" value=\"" + gaid
             + "\" package=\"com.google.android.gms\" />\n";
        xml += "  <setting id=\"3\" name=\"limit_ad_tracking\" value=\"0\" "
               "package=\"com.google.android.gms\" />\n";
    }
    xml += "</settings>\n";

    std::string xml_path = std::string(MOUNTDIR) + "/settings_secure.xml";
    atomic_write(xml_path, xml);

    ::chmod(xml_path.c_str(), 0600);
    ::chown(xml_path.c_str(), 1000, 1000);

    struct { const char* sub; const char* ctx; } part_ctx[] = {
        {"system",     "u:object_r:system_file:s0"},
        {"vendor",     "u:object_r:vendor_file:s0"},
        {"odm",        "u:object_r:vendor_file:s0"},
        {"product",    "u:object_r:system_file:s0"},
        {"system_ext", "u:object_r:system_file:s0"},
    };
    for (const auto& pc : part_ctx) {
        std::string p = std::string(MOUNTDIR) + "/" + pc.sub + "/build.prop";
        run_bin("/system/bin/chcon", {"chcon", pc.ctx, p.c_str()});
    }
    run_bin("/system/bin/chcon", {"chcon", "u:object_r:system_data_file:s0",
            xml_path.c_str()});

    printf("  Mount overlay: 5 build.prop + settings_secure.xml -> %s\n", MOUNTDIR);
}

static int wipe_target_data() {
    auto pkgs = load_targets();
    if (pkgs.empty()) return 0;
    wait_boot_completed(5000);

    int fail = 0;
    for (const auto& pkg : pkgs) {

        run_framework("/system/bin/am",
                {"am", "force-stop", "--user", "0", pkg.c_str()},
                "am force-stop " + pkg);
        int rc_clear = run_framework("/system/bin/pm",
                {"pm", "clear", "--user", "0", pkg.c_str()},
                "pm clear " + pkg);
        if (rc_clear != 0) {
            fail++;
            fprintf(stderr, "! %s: pm clear gagal (rc=%d)\n", pkg.c_str(), rc_clear);
        }
    }
    return fail;
}

static int cmd_targets() {
    auto pkgs = load_targets();
    struct stat st{};
    bool have_file = (::stat(TARGET_FILE, &st) == 0);

    printf("target.txt : %s%s\n",
           TARGET_FILE,
           have_file ? "" : "  (missing — no targets configured; module idle)");
    printf("count      : %zu\n\n", pkgs.size());
    for (const auto& p : pkgs) printf("  %s\n", p.c_str());
    return 0;
}

static Identity load_identity() {
    Identity id;
    std::istringstream iss(read_file(IDENTITY_FILE));
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = line.substr(eq + 1);
        while (!v.empty() && (v.back()=='\r' || v.back()=='\n' || v.back()==' '))
            v.pop_back();
        if (!k.empty()) id.kv[k] = v;
    }
    return id;
}

static bool merge_carrier(Identity& id) {

    sbxcarrier::CarrierSel sel = sbxcarrier::parse_carrier_conf(read_file(CARRIER_CONF));
    return sbxcarrier::apply_carrier(id.kv, sel);
}

static bool ensure_root() {
    if (geteuid() != 0) {
        fprintf(stderr, "! sandboxid must run as root. Use: su -c sandboxid <cmd>\n");
        return false;
    }
    return true;
}

static int cmd_freshen() {
    DBG("cmd_freshen: build=%s", SBX_VARIANT_TAG);
    if (!ensure_root()) return 1;

    std::string mode = trim(read_file(MODE_FILE));
    if (mode == "locked") {
        printf("LOCKED: run `sandboxid unlock` first\n");
        return 1;
    }

    std::string old = read_file(IDENTITY_FILE);
    if (!old.empty()) atomic_write(IDENTITY_BAK, old);

    PixelEntry ov;
    Identity id;
    const int dev_sdk = device_sdk();
    if (take_persona_override(ov)) {
        if (dev_sdk > 0 && ov.sdk > dev_sdk) {
            fprintf(stderr,
                    "! autopif persona %s (SDK %d) is newer than device SDK %d — "
                    "refusing upgrade-spoof (would crash/leak on this Android "
                    "version); using SDK-matched pool pick instead\n",
                    ov.model.c_str(), ov.sdk, dev_sdk);
            id = gen_identity();
        } else {
            fprintf(stderr, "* autopif persona: %s (%s/%s, SDK %d) — applied directly, no pool pick\n",
                    ov.model.c_str(), ov.device.c_str(), ov.platform.c_str(), ov.sdk);
            id = derive_identity(ov);
        }
    } else {
        id = gen_identity();
    }

    merge_carrier(id);
    if (!atomic_write(IDENTITY_FILE, id.serialize())) {
        fprintf(stderr, "! failed to write identity.prop\n");
        return 1;
    }

    apply_native(id);
    generate_mount_files(id);
    int wipe_fail = wipe_target_data();

    printf("OK - fresh persona ready\n");
    printf("  MODEL       : %s\n", id.kv["MODEL"].c_str());
    printf("  DEVICE      : %s\n", id.kv["DEVICE"].c_str());
    printf("  RELEASE     : %s (SDK %s)\n",
           id.kv["RELEASE"].c_str(), id.kv["SDK_INT"].c_str());
    printf("  FINGERPRINT : %s\n", id.kv["FINGERPRINT"].c_str());
    printf("  SERIAL      : %s\n", id.kv["SERIAL"].c_str());
    printf("  ANDROID_ID  : %s\n", id.kv["ANDROID_ID"].c_str());
    printf("  GAID        : %s\n", id.kv["GOOGLE_AID"].c_str());
    printf("  SEC PATCH   : %s\n", id.kv["SECURITY_PATCH"].c_str());
    printf("  HOST        : %s\n", id.kv["HOST"].c_str());
    printf("  RADIO       : %s\n", id.kv["RADIO"].c_str());

    auto pkgs = load_targets();
    printf("  Wiped: %zu pkg(s) from target.txt\n", pkgs.size());
    for (const auto& p : pkgs) printf("    - %s\n", p.c_str());
    if (wipe_fail > 0)
        fprintf(stderr, "! WARN: %d wipe step(s) gagal (pm clear/am force-stop) — lihat log di atas\n",
                wipe_fail);
    return 0;
}

static int cmd_status() {
    std::string d = read_file(IDENTITY_FILE);
    if (d.empty()) {
        printf("no identity yet - run `sandboxid freshen`\n");
        return 0;
    }
    fputs(d.c_str(), stdout);
    return 0;
}

static int cmd_apply_boot() {
    if (!ensure_root()) return 1;
    Identity id = load_identity();
    if (id.kv.empty()) {
        printf("no identity yet\n");
        return 0;
    }
    apply_native(id);
    generate_mount_files(id);
    printf("OK: native prop re-applied + mount overlay refreshed\n");
    return 0;
}

static int cmd_seed() {
    if (!ensure_root()) return 1;
    Identity id;
    std::string existing = read_file(IDENTITY_FILE);
    if (!existing.empty()) {
        id = load_identity();
        DBG("seed: reusing existing identity (%zu keys)", id.kv.size());
    } else {
        DBG("seed: no identity yet, generating fresh");
        id = gen_identity();
        merge_carrier(id);
        if (!atomic_write(IDENTITY_FILE, id.serialize())) {
            fprintf(stderr, "! seed: failed to write %s\n", IDENTITY_FILE);
            return 1;
        }
    }
    generate_mount_files(id);
    printf("OK: seed complete (mount overlay ready at %s)\n", MOUNTDIR);
    return 0;
}

static int cmd_lock() {
    if (!ensure_root()) return 1;
    atomic_write(MODE_FILE, "locked\n");
    printf("OK: locked\n");
    return 0;
}

static int cmd_unlock() {
    if (!ensure_root()) return 1;
    atomic_write(MODE_FILE, "fresh\n");
    printf("OK: unlocked\n");
    return 0;
}

static int cmd_rollback() {
    if (!ensure_root()) return 1;
    std::string d = read_file(IDENTITY_BAK);
    if (d.empty()) {
        printf("no backup\n");
        return 1;
    }
    atomic_write(IDENTITY_FILE, d);
    Identity rid = load_identity();
    apply_native(rid);
    generate_mount_files(rid);
    wipe_target_data();
    printf("OK: rolled back + wiped\n");
    return 0;
}

static int cmd_applog_ids(const char* pkg) {
    if (!pkg || !*pkg) {
        fprintf(stderr, "applog-ids: butuh nama package\n");
        return 2;
    }
    Identity id = load_identity();
    auto g = [&](const char* k) -> std::string {
        auto it = id.kv.find(k);
        return it != id.kv.end() ? it->second : std::string();
    };
    uint64_t epoch_ms = strtoull(g("APPLOG_EPOCH").c_str(), nullptr, 10);
    if (epoch_ms == 0) epoch_ms = 1700000000000ULL;
    uint64_t seed = sbxnr::fnv1a(g("FINGERPRINT") + "|" + g("SERIAL") + "|" +
                                 g("ANDROID_ID") + "|" + std::string(pkg));
    sbxnr::ApplogIds ids = sbxnr::make_applog_ids(seed, epoch_ms);
    printf("PKG=%s\n",        pkg);
    printf("EPOCH=%llu\n",    (unsigned long long)epoch_ms);
    printf("DID=%s\n",        ids.did.c_str());
    printf("IID=%s\n",        ids.iid.c_str());
    printf("SSID=%s\n",       ids.ssid.c_str());
    printf("OPENUDID=%s\n",   ids.openudid.c_str());
    printf("CLIENTUDID=%s\n", ids.clientudid.c_str());
    printf("CDID=%s\n",       ids.cdid.c_str());
    return 0;
}

static void usage(const char* p) {
    fprintf(stderr,
        "SandboxID — Android device identifier privacy research module\n\n"
        "Usage: %s <command>\n\n"
        "  freshen      Rotate identity + wipe target app data (main action)\n"
        "  status       Print current identity.prop\n"
        "  rollback     Restore previous identity from backup\n"
        "  lock         Prevent freshen (safety)\n"
        "  unlock       Re-enable freshen\n"
        "  apply-boot   Re-apply native prop (used by service.sh)\n"
        "  seed         Fast bootstrap: identity + mount overlay only\n"
        "               (used by post-fs-data.sh, no native/wipe)\n"
        "  targets      List current target packages from target.txt\n"
        "  applog-ids <pkg>\n"
        "               Print the AppLog IDs the L9 hook serves for <pkg>\n",
        p);
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    const char* c = argv[1];
    if (!strcmp(c, "freshen"))    return cmd_freshen();
    if (!strcmp(c, "status"))     return cmd_status();
    if (!strcmp(c, "rollback"))   return cmd_rollback();
    if (!strcmp(c, "lock"))       return cmd_lock();
    if (!strcmp(c, "unlock"))     return cmd_unlock();
    if (!strcmp(c, "apply-boot")) return cmd_apply_boot();
    if (!strcmp(c, "seed"))       return cmd_seed();
    if (!strcmp(c, "targets"))    return cmd_targets();
    if (!strcmp(c, "applog-ids")) return cmd_applog_ids(argc > 2 ? argv[2] : nullptr);
    usage(argv[0]);
    return 1;
}
