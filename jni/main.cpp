
#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdarg>
#include <sys/system_properties.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <linux/sockios.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <utility>
#include <signal.h>
#include <ctime>
#include <thread>
#include <atomic>
#include "zygisk.hpp"
#include "config.hpp"
#include "sbx_lsplant.hpp"
#include "sbx_native_read.hpp"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef __NR_memfd_create
# if defined(__aarch64__)
#  define __NR_memfd_create 279
# elif defined(__arm__)
#  define __NR_memfd_create 385
# elif defined(__x86_64__)
#  define __NR_memfd_create 319
# elif defined(__i386__)
#  define __NR_memfd_create 356
# endif
#endif
#ifndef __NR_sysinfo
# if defined(__aarch64__)
#  define __NR_sysinfo 179
# elif defined(__arm__)
#  define __NR_sysinfo 116
# elif defined(__x86_64__)
#  define __NR_sysinfo 99
# elif defined(__i386__)
#  define __NR_sysinfo 116
# endif
#endif

#define LOG_TAG "SandboxID"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifdef SBX_DEBUG
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[D] " fmt, ##__VA_ARGS__)
#define SBX_VARIANT_TAG "debug"
#else
#define LOGD(...) ((void)0)
#define SBX_VARIANT_TAG "release"
#endif

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

static constexpr struct timeval SBX_IO_TIMEOUT = {2, 0};

static std::unordered_map<std::string, std::string> g_identity;

static const std::string& val(const std::string& k) {
    static const std::string empty;
    auto it = g_identity.find(k);
    if (it != g_identity.end() && !it->second.empty()) return it->second;

    static const std::unordered_map<std::string, std::string> defaults = [] {
        std::unordered_map<std::string, std::string> m;
        m.reserve(sandboxid::VAL_DEFAULTS_N);
        for (size_t i = 0; i < sandboxid::VAL_DEFAULTS_N; ++i)
            m.emplace(sandboxid::VAL_DEFAULTS[i].k, sandboxid::VAL_DEFAULTS[i].v);
        return m;
    }();
    auto d = defaults.find(k);
    if (d != defaults.end()) return d->second;
    return empty;
}

static void rotate_sim_operator() {
    auto it = g_identity.find("GSM_OPERATOR_NUMERIC");
    if (it != g_identity.end() && !it->second.empty()) {
        LOGD("SIM: operator pinned by persona (%s) — skipping auto-rotate",
             it->second.c_str());
        return;
    }
    uint64_t seed = sbxnr::fnv1a(val("FINGERPRINT") + "|" + val("SERIAL") + "|" +
                                 val("ANDROID_ID"));
    uint64_t s = seed ^ 0x53494D53454CULL;
    const auto& c = sandboxid::ID_CARRIERS[sbxnr::splitmix64(s) % sandboxid::ID_CARRIERS_N];
    g_identity["GSM_OPERATOR_NUMERIC"] = c.numeric;
    g_identity["GSM_OPERATOR_ALPHA"]   = c.alpha;
    g_identity["GSM_OPERATOR_ISO"]     = c.iso;
    if (c.carrier_id[0]) g_identity["GSM_CARRIER_ID"] = c.carrier_id;
    else                 g_identity.erase("GSM_CARRIER_ID");
    LOGI("SIM auto-rotate: %s (%s%s)", c.alpha, c.numeric,
         c.carrier_id[0] ? "" : ", cid=UNKNOWN");
}

static jstring (*orig_native_get)(JNIEnv*, jclass, jstring, jstring) = nullptr;
static const std::map<std::string, std::string>& prop_to_identity_map() {
    static const std::map<std::string, std::string> m = {
        {"ro.serialno",                     "SERIAL"},
        {"ro.boot.serialno",                "SERIAL"},
        {"ro.build.fingerprint",            "FINGERPRINT"},
        {"ro.bootimage.build.fingerprint",  "FINGERPRINT"},
        {"ro.product.model",                "MODEL"},
        {"ro.product.brand",                "BRAND"},
        {"ro.product.manufacturer",         "MANUFACTURER"},
        {"ro.product.device",               "DEVICE"},
        {"ro.product.name",                 "PRODUCT"},
        {"ro.product.marketname",           "MARKETNAME"},
        {"ro.product.vendor.marketname",    "MARKETNAME"},

        {"ro.product.system.marketname",    "MARKETNAME"},
        {"ro.product.odm.marketname",       "MARKETNAME"},
        {"ro.product.product.marketname",   "MARKETNAME"},
        {"ro.product.board",                "BOARD"},
        {"ro.hardware",                     "HARDWARE"},
        {"ro.board.platform",               "BOARD_PLATFORM"},
        {"ro.soc.manufacturer",             "SOC_MANUFACTURER"},
        {"ro.soc.model",                    "SOC_MODEL"},
        {"ro.build.id",                     "ID"},
        {"ro.build.display.id",             "DISPLAY"},
        {"ro.build.description",            "DESCRIPTION"},
        {"ro.build.version.release",        "RELEASE"},
        {"ro.build.version.sdk",            "SDK_INT"},
        {"ro.build.version.security_patch", "SECURITY_PATCH"},
        {"ro.build.version.incremental",    "INCREMENTAL"},
        {"gsm.version.baseband",            "RADIO"},
        {"sys.boot_completed",              "SYS_BOOT_COMPLETED"},
        {"debug.force_rtl",                 "DEBUG_FORCE_RTL"},
        {"persist.radio.multisim.config",   "MULTISIM_CONFIG"},
        {"gsm.operator.numeric",            "GSM_OPERATOR_NUMERIC"},
        {"gsm.sim.operator.numeric",        "GSM_OPERATOR_NUMERIC"},
        {"gsm.operator.alpha",              "GSM_OPERATOR_ALPHA"},
        {"gsm.sim.operator.alpha",          "GSM_OPERATOR_ALPHA"},
        {"gsm.operator.iso-country",        "GSM_OPERATOR_ISO"},
        {"gsm.sim.operator.iso-country",    "GSM_OPERATOR_ISO"},
        {"gsm.sim.state",                   "GSM_SIM_STATE"},
        {"gsm.sim.state.ril",               "GSM_SIM_STATE"},
        {"ro.build.characteristics",        "BUILD_CHARACTERISTICS"},
        {"persist.sys.timezone",            "PERSIST_TIMEZONE"},

        {"ro.product.cpu.abi",              "CPU_ABI"},
        {"ro.product.cpu.abi2",             "CPU_ABI2"},
        {"ro.product.cpu.abilist",          "SUPPORTED_ABIS"},
        {"ro.product.cpu.abilist64",        "SUPPORTED_64_BIT_ABIS"},
        {"ro.product.cpu.abilist32",        "SUPPORTED_32_BIT_ABIS"},
        {"dalvik.vm.heapgrowthlimit",       "DALVIK_HEAPGROWTHLIMIT"},
        {"ro.mediacodec.min_sample_rate",   "MEDIACODEC_MIN_RATE"},
        {"ro.mediacodec.max_sample_rate",   "MEDIACODEC_MAX_RATE"},
        {"ro.build.user",                   "USER"},
        {"ro.build.host",                   "HOST"},
        {"ro.build.tags",                   "TAGS"},
        {"ro.build.type",                   "TYPE"},

        {"ro.build.date.utc",               "BUILD_TIME_UTC"},
        {"ro.build.date",                   "BUILD_DATE"},

        {"ro.build.flavor",                 "FLAVOR"},

        {"ro.boot.vbmeta.digest",           "VBMETA_DIGEST"},
        {"ro.build.product",                     "DEVICE"},
        {"ro.build.version.release_or_codename", "RELEASE"},
        {"ro.vendor.build.security_patch",       "SECURITY_PATCH"},

        {"ro.system.build.fingerprint",     "FINGERPRINT"},
        {"ro.vendor.build.fingerprint",     "FINGERPRINT"},
        {"ro.odm.build.fingerprint",        "FINGERPRINT"},
        {"ro.product.build.fingerprint",    "FINGERPRINT"},
        {"ro.system_ext.build.fingerprint", "FINGERPRINT"},
        {"ro.vendor_dlkm.build.fingerprint", "FINGERPRINT"},
        {"ro.odm_dlkm.build.fingerprint",   "FINGERPRINT"},

        {"ro.product.system.model",         "MODEL"},
        {"ro.product.vendor.model",         "MODEL"},
        {"ro.product.odm.model",            "MODEL"},
        {"ro.product.product.model",        "MODEL"},
        {"ro.product.system_ext.model",     "MODEL"},

        {"ro.product.system.brand",         "BRAND"},
        {"ro.product.vendor.brand",         "BRAND"},
        {"ro.product.odm.brand",            "BRAND"},
        {"ro.product.product.brand",        "BRAND"},
        {"ro.product.system_ext.brand",     "BRAND"},

        {"ro.product.system.manufacturer",     "MANUFACTURER"},
        {"ro.product.vendor.manufacturer",     "MANUFACTURER"},
        {"ro.product.odm.manufacturer",        "MANUFACTURER"},
        {"ro.product.product.manufacturer",    "MANUFACTURER"},
        {"ro.product.system_ext.manufacturer", "MANUFACTURER"},

        {"ro.product.system.device",        "DEVICE"},
        {"ro.product.vendor.device",        "DEVICE"},
        {"ro.product.odm.device",           "DEVICE"},
        {"ro.product.product.device",       "DEVICE"},
        {"ro.product.system_ext.device",    "DEVICE"},

        {"ro.product.system.name",          "PRODUCT"},
        {"ro.product.vendor.name",          "PRODUCT"},
        {"ro.product.odm.name",             "PRODUCT"},
        {"ro.product.product.name",         "PRODUCT"},
        {"ro.product.system_ext.name",      "PRODUCT"},

        {"ro.boot.hardware.sku",                     "SKU"},
        {"ro.boot.product.hardware.sku",             "ODM_SKU"},
        {"ro.build.version.base_os",                 "BASE_OS"},
        {"ro.build.version.preview_sdk",             "PREVIEW_SDK_INT"},
        {"ro.build.version.preview_sdk_fingerprint", "PREVIEW_SDK_FINGERPRINT"},
        {"ro.odm.build.media_performance_class",     "MEDIA_PERFORMANCE_CLASS"},
    };
    return m;
}

static const std::unordered_map<std::string, std::string>& static_prop_defaults_map() {
    static const std::unordered_map<std::string, std::string> m = [] {
        std::unordered_map<std::string, std::string> t;
        t.reserve(sandboxid::STATIC_PROP_DEFAULTS_N);
        for (size_t i = 0; i < sandboxid::STATIC_PROP_DEFAULTS_N; ++i)
            t.emplace(sandboxid::STATIC_PROP_DEFAULTS[i].k, sandboxid::STATIC_PROP_DEFAULTS[i].v);
        return t;
    }();
    return m;
}

static bool spoof_prop_value(const std::string& k, std::string& out) {
    const auto& map = prop_to_identity_map();
    auto it = map.find(k);
    if (it != map.end()) {
        const std::string& v = val(it->second);
        if (!v.empty()) { out = v; return true; }
    }
    const auto& smap = static_prop_defaults_map();
    auto sit = smap.find(k);
    if (sit != smap.end()) { out = sit->second; return true; }
    return false;
}

static inline bool sbx_prop_hidden(const char* name) {
    return name && sbxnr::should_hide_prop(name);
}

static jstring hook_prop_get(JNIEnv* env, jclass clazz, jstring j_key, jstring j_def) {
    if (!j_key) return j_def;

    const char* raw = env->GetStringUTFChars(j_key, nullptr);
    if (!raw) { if (env->ExceptionCheck()) env->ExceptionClear(); return j_def; }
    std::string k(raw);
    env->ReleaseStringUTFChars(j_key, raw);
    LOGD("L2 native_get('%s')", k.c_str());

    std::string v;
    if (spoof_prop_value(k, v)) {
        LOGD("L2 SPOOF '%s' -> '%s'", k.c_str(), v.c_str());
        jstring js = env->NewStringUTF(v.c_str());
        if (!js) { if (env->ExceptionCheck()) env->ExceptionClear(); return j_def; }
        return js;
    }

    if (sbx_prop_hidden(k.c_str())) {
        LOGD("L2 HIDE '%s' (report absent)", k.c_str());
        return j_def;
    }

    if (orig_native_get) return orig_native_get(env, clazz, j_key, j_def);

    char buf[PROP_VALUE_MAX] = {0};
    if (__system_property_get(k.c_str(), buf) > 0) {
        jstring js = env->NewStringUTF(buf);
        if (!js) { if (env->ExceptionCheck()) env->ExceptionClear(); return j_def; }
        return js;
    }
    return j_def;
}

static void install_prop_hook(Api* api, JNIEnv* env) {
    JNINativeMethod m = {
        const_cast<char*>("native_get"),
        const_cast<char*>("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
        reinterpret_cast<void*>(hook_prop_get),
    };

    api->hookJniNativeMethods(env, "android/os/SystemProperties", &m, 1);
    if (env->ExceptionCheck())
        env->ExceptionClear();
    orig_native_get = reinterpret_cast<jstring (*)(JNIEnv*, jclass, jstring, jstring)>(m.fnPtr);
    if (!orig_native_get)
        LOGE("L2: native_get hook FAILED (fnPtr null) — prop spoofing off for this process");
    else
        LOGD("L2 native_get hooked (orig=%p)", reinterpret_cast<void*>(orig_native_get));
}

static jint     (*orig_get_int)(JNIEnv*, jclass, jstring, jint)     = nullptr;
static jlong    (*orig_get_long)(JNIEnv*, jclass, jstring, jlong)   = nullptr;
static jboolean (*orig_get_bool)(JNIEnv*, jclass, jstring, jboolean)= nullptr;

static const std::map<std::string, jboolean>& sbx_bool_spoof() {
    static const std::map<std::string, jboolean> m = {
        {"sys.boot_completed",                       JNI_TRUE},
        {"debug.force_rtl",                          JNI_FALSE},
        {"framework.pause_bg_animations.enabled",    JNI_FALSE},
        {"dalvik.vm.dexopt.secondary",               JNI_TRUE},
        {"viewroot.profile_rendering",               JNI_FALSE},
        {"debug.sqlite.no_double_quoted_strs",       JNI_TRUE},
        {"persist.sys.activity_anim_perf_override",  JNI_FALSE},
        {"persist.sys.lmk.reportkills",              JNI_FALSE},
        {"debug.layout",                             JNI_FALSE},
    };
    return m;
}
static const std::map<std::string, jint>& sbx_int_spoof() {
    static const std::map<std::string, jint> m = {
        {"ro.mediacodec.min_sample_rate",         8000},
        {"ro.mediacodec.max_sample_rate",         192000},
        {"debug.sqlite.wal.autocheckpoint",       100},
        {"debug.sqlite.pagesize",                 4096},
        {"debug.sqlite.journalsizelimit",         524288},
        {"debug.sqlite.wal.truncatesize",         1048576},
        {"debug.sqlite.wal.poolsize",             0},
        {"debug.hwui.fps_divisor",                1},
        {"persist.wm.debug.ext_version_override", 0},
        {"build.version.extensions.r",            3},
        {"build.version.extensions.s",            4},
        {"build.version.extensions.t",            4},
        {"build.version.extensions.u",            13},
        {"build.version.extensions.v",            13},
        {"build.version.extensions.ad_services",  15},
        {"debug.am.run_gc_trim_level",            2147483647},
        {"debug.am.run_mallopt_trim_level",       2147483647},
        {"debug.adservices.binder_timeout",       10000},

        {"ro.build.version.preview_sdk",          0},
    };
    return m;
}
static const std::map<std::string, jlong>& sbx_long_spoof() {
    static const std::map<std::string, jlong> m = {
        {"ro.gfx.driver_build_time",              1704067200LL},
    };
    return m;
}

static bool sbx_should_suppress_key(const std::string& k) {
    if (k.size() >= 11 + 5 &&
        k.compare(0, 11, "log.looper.") == 0 &&
        k.compare(k.size() - 5, 5, ".slow") == 0)
        return true;
    if (k.compare(0, 13, "debug.watson.") == 0)
        return true;
    return false;
}

static bool sbx_parse_longlong(const std::string& v, long long& out) {
    if (v.empty()) return false;
    errno = 0;
    const char* s = v.c_str();

    if (*s == '+' || *s == '-') ++s;
    if (!*s) return false;
    char* end = nullptr;
    long long n = std::strtoll(v.c_str(), &end, 10);
    if (end == v.c_str() || *end != '\0' || errno == ERANGE) return false;
    out = n;
    return true;
}

static jint hook_prop_get_int(JNIEnv* env, jclass clazz, jstring j_key, jint def) {
    if (!j_key) return def;
    const char* r = env->GetStringUTFChars(j_key, nullptr);
    if (!r) { if (env->ExceptionCheck()) env->ExceptionClear(); return def; }
    std::string k(r);
    env->ReleaseStringUTFChars(j_key, r);

    std::string v;
    if (spoof_prop_value(k, v)) {
        long long n = 0;
        if (sbx_parse_longlong(v, n)) { LOGD("L7 SPI(id) '%s' -> %d", k.c_str(), (int)n); return (jint)n; }
    }

    const auto& m = sbx_int_spoof();
    auto it = m.find(k);
    if (it != m.end()) { LOGD("L7 SPI '%s' -> %d", k.c_str(), it->second); return it->second; }
    if (sbx_should_suppress_key(k)) { LOGD("L7 SPI SUPPRESS '%s'", k.c_str()); return def; }
    return orig_get_int ? orig_get_int(env, clazz, j_key, def) : def;
}
static jlong hook_prop_get_long(JNIEnv* env, jclass clazz, jstring j_key, jlong def) {
    if (!j_key) return def;
    const char* r = env->GetStringUTFChars(j_key, nullptr);
    if (!r) { if (env->ExceptionCheck()) env->ExceptionClear(); return def; }
    std::string k(r);
    env->ReleaseStringUTFChars(j_key, r);

    std::string v;
    if (spoof_prop_value(k, v)) {
        long long n = 0;
        if (sbx_parse_longlong(v, n)) { LOGD("L7 SPL(id) '%s' -> %lld", k.c_str(), (long long)n); return (jlong)n; }
    }

    const auto& m = sbx_long_spoof();
    auto it = m.find(k);
    if (it != m.end()) { LOGD("L7 SPL '%s' -> %lld", k.c_str(), (long long)it->second); return it->second; }
    if (sbx_should_suppress_key(k)) { LOGD("L7 SPL SUPPRESS '%s'", k.c_str()); return def; }
    return orig_get_long ? orig_get_long(env, clazz, j_key, def) : def;
}
static jboolean hook_prop_get_bool(JNIEnv* env, jclass clazz, jstring j_key, jboolean def) {
    if (!j_key) return def;
    const char* r = env->GetStringUTFChars(j_key, nullptr);
    if (!r) { if (env->ExceptionCheck()) env->ExceptionClear(); return def; }
    std::string k(r);
    env->ReleaseStringUTFChars(j_key, r);
    const auto& m = sbx_bool_spoof();
    auto it = m.find(k);
    if (it != m.end()) { LOGD("L7 SPB '%s' -> %d", k.c_str(), (int)it->second); return it->second; }
    if (sbx_should_suppress_key(k)) { LOGD("L7 SPB SUPPRESS '%s'", k.c_str()); return def; }
    return orig_get_bool ? orig_get_bool(env, clazz, j_key, def) : def;
}

static void install_leak_sensors(Api* api, JNIEnv* env) {
    JNINativeMethod m[3] = {
        {const_cast<char*>("native_get_int"),
         const_cast<char*>("(Ljava/lang/String;I)I"),
         reinterpret_cast<void*>(hook_prop_get_int)},
        {const_cast<char*>("native_get_long"),
         const_cast<char*>("(Ljava/lang/String;J)J"),
         reinterpret_cast<void*>(hook_prop_get_long)},
        {const_cast<char*>("native_get_boolean"),
         const_cast<char*>("(Ljava/lang/String;Z)Z"),
         reinterpret_cast<void*>(hook_prop_get_bool)},
    };

    api->hookJniNativeMethods(env, "android/os/SystemProperties", m, 3);
    if (env->ExceptionCheck())
        env->ExceptionClear();
    if (!m[0].fnPtr || !m[1].fnPtr || !m[2].fnPtr)
        LOGE("L7: leak-sensor hooks FAILED (fnPtr null: %d/%d/%d) — typed getters unspoofed",
             m[0].fnPtr ? 1 : 0, m[1].fnPtr ? 1 : 0, m[2].fnPtr ? 1 : 0);
    orig_get_int  = reinterpret_cast<jint (*)(JNIEnv*, jclass, jstring, jint)>(m[0].fnPtr);
    orig_get_long = reinterpret_cast<jlong (*)(JNIEnv*, jclass, jstring, jlong)>(m[1].fnPtr);
    orig_get_bool = reinterpret_cast<jboolean (*)(JNIEnv*, jclass, jstring, jboolean)>(m[2].fnPtr);
    LOGD("L7 leak sensors installed (int/long/bool)");
}

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif
#ifndef CLOCK_BOOTTIME_ALARM
#define CLOCK_BOOTTIME_ALARM 9
#endif

static int (*orig_clock_gettime)(clockid_t, struct timespec*) = nullptr;
static int64_t g_boot_off_sec = 0;

static int sbx_hooked_clock_gettime(clockid_t clk, struct timespec* ts) {
    int r = orig_clock_gettime ? orig_clock_gettime(clk, ts) : clock_gettime(clk, ts);
    if (r == 0 && ts && (clk == CLOCK_BOOTTIME || clk == CLOCK_BOOTTIME_ALARM))
        ts->tv_sec += g_boot_off_sec;
    return r;
}

static bool sbx_find_lib_dev_inode(const char* suffix, dev_t* out_dev, ino_t* out_ino) {
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return false;

    char*  line = nullptr;
    size_t cap  = 0;
    ssize_t n;
    size_t sl = strlen(suffix);
    bool found = false;
    while ((n = getline(&line, &cap, f)) != -1) {
        char* path = strchr(line, '/');
        if (!path) continue;
        size_t pl = strlen(path);
        if (pl && path[pl - 1] == '\n') path[--pl] = '\0';
        if (pl >= sl && strcmp(path + pl - sl, suffix) == 0) {
            struct stat st;
            if (stat(path, &st) == 0) { *out_dev = st.st_dev; *out_ino = st.st_ino; found = true; }
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

static void install_uptime_hook(Api* api, JNIEnv*  ) {
    const std::string& us = val("UPTIME_SECONDS");
    if (us.empty()) return;
    char* end = nullptr;
    long long secs = std::strtoll(us.c_str(), &end, 10);
    if (end == us.c_str() || secs <= 0) return;
    g_boot_off_sec = (int64_t)secs;

    static const char* const kLibs[] = {
        "/libutils.so",
        "/libandroid_runtime.so",
    };
    int registered = 0;
    if (!orig_clock_gettime)
        orig_clock_gettime = reinterpret_cast<int (*)(clockid_t, timespec*)>(
            dlsym(RTLD_DEFAULT, "clock_gettime"));
    for (size_t i = 0; i < sizeof(kLibs) / sizeof(kLibs[0]); ++i) {
        dev_t dev = 0; ino_t ino = 0;
        if (!sbx_find_lib_dev_inode(kLibs[i], &dev, &ino)) continue;
        api->pltHookRegister(dev, ino, "clock_gettime",
                             reinterpret_cast<void*>(sbx_hooked_clock_gettime),
                             reinterpret_cast<void**>(&orig_clock_gettime));
        ++registered;
    }
    if (registered == 0) {
        g_boot_off_sec = 0;
        LOGW("L8: chokepoint lib tak ketemu (scanned %zu) — uptime tak dispoof",
             sizeof(kLibs) / sizeof(kLibs[0]));
        return;
    }
    if (!api->pltHookCommit()) {

        g_boot_off_sec = 0;
        LOGW("L8: pltHookCommit gagal (%d/%zu libs registered) — offset dinolkan, "
             "semua reader lihat jam asli (divergensi hang dihindari)",
             registered, sizeof(kLibs) / sizeof(kLibs[0]));
        return;
    }
    if (orig_clock_gettime == nullptr) {

        g_boot_off_sec = 0;
        return;
    }
    LOGD("L8 boottime PLT hook aktif (+%llds, %d/%zu lib mapped) orig=%p",
         (long long)secs, registered, sizeof(kLibs) / sizeof(kLibs[0]),
         reinterpret_cast<void*>(orig_clock_gettime));
}

#ifndef O_TMPFILE
#define O_TMPFILE 0
#endif

typedef int   (*sbx_open_fn)(const char*, int, ...);
typedef int   (*sbx_openat_fn)(int, const char*, int, ...);
typedef FILE* (*sbx_fopen_fn)(const char*, const char*);
typedef int   (*sbx_sysprop_get_fn)(const char*, char*);
typedef int   (*sbx_sysprop_read_fn)(const void*, char*, char*);
typedef void  (*sbx_sysprop_cb)(void*, const char*, const char*, uint32_t);
typedef void  (*sbx_sysprop_read_cb_fn)(const void*, sbx_sysprop_cb, void*);
typedef int   (*sbx_ioctl_fn)(int, unsigned long, void*);
typedef int   (*sbx_getifaddrs_fn)(struct ifaddrs**);
typedef int   (*sbx_sysinfo_fn)(struct sysinfo*);

static sbx_open_fn   orig_open   = nullptr;
static sbx_openat_fn orig_openat = nullptr;
static sbx_fopen_fn  orig_fopen  = nullptr;
static sbx_sysprop_get_fn    orig_sysprop_get    = nullptr;
static sbx_sysprop_read_fn    orig_sysprop_read    = nullptr;
static sbx_sysprop_read_cb_fn  orig_sysprop_read_cb  = nullptr;
static sbx_ioctl_fn      orig_ioctl      = nullptr;
static sbx_getifaddrs_fn orig_getifaddrs = nullptr;
static sbx_sysinfo_fn    orig_sysinfo    = nullptr;

static std::atomic<bool> g_native_read_active{false};
static std::string g_boot_id;
static std::string g_wifi_mac;
static std::string g_proc_version;
static std::string g_cpu_repl;
static int         g_ram_gb    = 0;
static int         g_cpu_action = sbxnr::CPU_NONE;

static std::string    g_pkg;
static sbxnr::ApplogIds g_applog;
static bool           g_applog_ok = false;

static int sbx_fill_prop(char* value, const std::string& v) {
    size_t n = v.size();
    if (n > PROP_VALUE_MAX - 1) n = PROP_VALUE_MAX - 1;
    memcpy(value, v.data(), n);
    value[n] = '\0';
    return (int)n;
}

static inline bool sbx_nr_spoofable(const char* name) {
    return g_native_read_active && name && !sbxnr::is_native_unsafe_prop(name);
}

static int sbx_sysprop_get(const char* name, char* value) {
    if (sbx_nr_spoofable(name) && value) {
        if (sbx_prop_hidden(name)) { value[0] = '\0'; return 0; }
        std::string v;
        if (spoof_prop_value(name, v)) { return sbx_fill_prop(value, v); }
    }
    if (orig_sysprop_get) return orig_sysprop_get(name, value);
    if (value) value[0] = '\0';
    return 0;
}

static int sbx_sysprop_read(const void* pi, char* name, char* value) {
    int r = orig_sysprop_read ? orig_sysprop_read(pi, name, value) : -1;
    if (r >= 0 && sbx_nr_spoofable(name) && value) {
        if (sbx_prop_hidden(name)) { value[0] = '\0'; return 0; }
        std::string v;
        if (spoof_prop_value(name, v)) { return sbx_fill_prop(value, v); }
    }
    return r;
}

struct SbxSyspropCbCtx { sbx_sysprop_cb cb; void* cookie; };
static void sbx_sysprop_cb_trampoline(void* cookie, const char* name, const char* value, uint32_t serial) {
    SbxSyspropCbCtx* c = static_cast<SbxSyspropCbCtx*>(cookie);
    std::string v;
    if (sbx_nr_spoofable(name) && sbx_prop_hidden(name))
        return;
    else if (sbx_nr_spoofable(name) && spoof_prop_value(name, v))
        c->cb(c->cookie, name, v.c_str(), serial);
    else
        c->cb(c->cookie, name, value, serial);
}
static void sbx_sysprop_read_cb(const void* pi, sbx_sysprop_cb cb, void* cookie) {
    if (!orig_sysprop_read_cb) return;
    if (!cb) { orig_sysprop_read_cb(pi, cb, cookie); return; }
    SbxSyspropCbCtx ctx{cb, cookie};
    orig_sysprop_read_cb(pi, sbx_sysprop_cb_trampoline, &ctx);
}

static int sbx_make_memfd(const std::string& content) {
#ifdef __NR_memfd_create

    int fd = (int)syscall(__NR_memfd_create, "", (unsigned)MFD_CLOEXEC);
    if (fd < 0) return -1;
    if (!sandboxid::write_full(fd, content.data(), content.size())) { ::close(fd); return -1; }
    if (::lseek(fd, 0, SEEK_SET) != 0) { ::close(fd); return -1; }
    return fd;
#else
    (void)content;
    return -1;
#endif
}

static std::string sbx_read_real(const char* path) {
    if (!orig_openat) return "";
    int fd = orig_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "";
    std::string data;
    char buf[4096];
    for (;;) {
        ssize_t r = ::read(fd, buf, sizeof(buf));
        if (r > 0) { data.append(buf, (size_t)r); continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    ::close(fd);
    return data;
}

static bool sbx_build_content(sbxnr::Kind kind, const char* path, std::string& out) {
    switch (kind) {
        case sbxnr::BOOTID:  out = g_boot_id;      out.push_back('\n'); return true;
        case sbxnr::MAC:     out = g_wifi_mac;     out.push_back('\n'); return true;
        case sbxnr::VERSION: out = g_proc_version; out.push_back('\n'); return true;
        case sbxnr::SELINUX_ENFORCE:

            out = sbxnr::selinux_enforce_content();
            return true;
        case sbxnr::ARP:
            out = sbxnr::arp_empty_content();
            return true;
        case sbxnr::MEMINFO: {
            std::string real = sbx_read_real("/proc/meminfo");
            if (real.empty()) return false;
            out = sbxnr::patch_meminfo(real, g_ram_gb);
            return true;
        }
        case sbxnr::CPUINFO: {
            if (g_cpu_action == sbxnr::CPU_NONE) return false;
            std::string real = sbx_read_real("/proc/cpuinfo");
            if (real.empty()) return false;
            return sbxnr::patch_cpuinfo(real, g_cpu_action, g_cpu_repl, out);
        }
        case sbxnr::UPTIME: {
            if (g_boot_off_sec <= 0) return false;
            std::string real = sbx_read_real("/proc/uptime");
            if (real.empty()) return false;
            out = sbxnr::patch_uptime(real, static_cast<long long>(g_boot_off_sec));
            return true;
        }
        case sbxnr::STAT: {
            if (g_boot_off_sec <= 0) return false;
            std::string real = sbx_read_real("/proc/stat");
            if (real.empty()) return false;
            out = sbxnr::patch_stat_btime(real, static_cast<long long>(g_boot_off_sec));
            return true;
        }
        case sbxnr::APPLOG_XML: {
            if (!g_applog_ok) return false;
            std::string real = sbx_read_real(path);
            if (real.empty()) {
                // Hanya sintesis stub untuk file yang memang peta ID kanonis;
                // file lain (header_custom, dsb.) hanya di-patch bila sudah ada.
                if (!sbxnr::applog_xml_is_synthable(path)) return false;
                out = sbxnr::applog_xml_synth(g_applog);
                return true;
            }
            return sbxnr::patch_applog_xml(real, g_applog, out);
        }
        case sbxnr::BD_RAW_DID:        if (g_applog_ok) { out = g_applog.did;        out.push_back('\n'); return true; } return false;
        case sbxnr::BD_RAW_IID:        if (g_applog_ok) { out = g_applog.iid;        out.push_back('\n'); return true; } return false;
        case sbxnr::BD_RAW_OPENUDID:   if (g_applog_ok) { out = g_applog.openudid;   out.push_back('\n'); return true; } return false;
        case sbxnr::BD_RAW_CLIENTUDID: if (g_applog_ok) { out = g_applog.clientudid; out.push_back('\n'); return true; } return false;
        case sbxnr::BD_RAW_CDID:       if (g_applog_ok) { out = g_applog.cdid;       out.push_back('\n'); return true; } return false;
        default: return false;
    }
}

static int sbx_spoof_fd(const char* path) {
    sbxnr::Kind kind = sbxnr::classify(path);
    if (kind == sbxnr::NONE) return -1;
    std::string content;
    if (!sbx_build_content(kind, path, content)) return -1;
    int fd = sbx_make_memfd(content);
    if (fd >= 0) LOGD("L9 redirect '%s' -> memfd (%zu B)", path, content.size());
    return fd;
}

static inline bool sbx_is_pure_read(int flags) {
    return (flags & O_ACCMODE) == O_RDONLY && !(flags & (O_CREAT | O_TMPFILE));
}

static int sbx_openat(int dirfd, const char* pathname, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & (O_CREAT | O_TMPFILE)) != 0;
    if (has_mode) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }

    if (g_native_read_active && pathname && sbx_is_pure_read(flags)) {
        int fd = sbx_spoof_fd(pathname);
        if (fd >= 0) return fd;
    }
    if (orig_openat)
        return has_mode ? orig_openat(dirfd, pathname, flags, mode)
                        : orig_openat(dirfd, pathname, flags);
    return (int)syscall(__NR_openat, dirfd, pathname, flags, mode);
}

static int sbx_open(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & (O_CREAT | O_TMPFILE)) != 0;
    if (has_mode) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }

    if (g_native_read_active && pathname && sbx_is_pure_read(flags)) {
        int fd = sbx_spoof_fd(pathname);
        if (fd >= 0) return fd;
    }
    if (orig_open)
        return has_mode ? orig_open(pathname, flags, mode) : orig_open(pathname, flags);
    if (orig_openat)
        return has_mode ? orig_openat(AT_FDCWD, pathname, flags, mode)
                        : orig_openat(AT_FDCWD, pathname, flags);
    return (int)syscall(__NR_openat, AT_FDCWD, pathname, flags, mode);
}

static int sbx_fopen_flags(const char* mode) {
    bool plus = mode && std::strchr(mode, '+');
    switch (mode ? mode[0] : 'r') {
        case 'w': return (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
        case 'a': return (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
        default:  return plus ? O_RDWR : O_RDONLY;
    }
}

static FILE* sbx_fopen(const char* path, const char* mode) {

    if (g_native_read_active && path && mode && mode[0] == 'r' && !strchr(mode, '+')) {
        int fd = sbx_spoof_fd(path);
        if (fd >= 0) {
            FILE* fp = fdopen(fd, "r");
            if (fp) return fp;
            ::close(fd);
        }
    }
    if (orig_fopen) return orig_fopen(path, mode);

    int fl = sbx_fopen_flags(mode);
    int fd = -1;
    if (orig_openat)      fd = orig_openat(AT_FDCWD, path, fl, 0666);
    else if (orig_open)   fd = orig_open(path, fl, 0666);
    else                  fd = (int)syscall(__NR_openat, AT_FDCWD, path, fl, 0666);
    if (fd < 0) return nullptr;
    FILE* fp = fdopen(fd, mode);
    if (!fp) { ::close(fd); return nullptr; }
    return fp;
}

static int sbx_ioctl(int fd, unsigned long request, void* argp) {
    int r = orig_ioctl ? orig_ioctl(fd, request, argp)
                       : (int)syscall(__NR_ioctl, fd, request, argp);
    if (r == 0 && g_native_read_active && argp && request == SIOCGIFHWADDR) {
        struct ifreq* ifr = static_cast<struct ifreq*>(argp);
        if (sbxnr::is_wifi_iface(ifr->ifr_name)) {
            uint8_t mac[6];
            if (sbxnr::mac_str_to_bytes(g_wifi_mac, mac)) {
                memcpy(ifr->ifr_hwaddr.sa_data, mac, 6);
                ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
            }
        }
    }
    return r;
}

static int sbx_getifaddrs(struct ifaddrs** ifap) {
    int r = orig_getifaddrs ? orig_getifaddrs(ifap) : -1;
    if (r != 0 || !ifap || !*ifap || !g_native_read_active) return r;
    uint8_t mac[6];
    if (!sbxnr::mac_str_to_bytes(g_wifi_mac, mac)) return r;
    for (struct ifaddrs* ifa = *ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_PACKET) continue;
        if (!sbxnr::is_wifi_iface(ifa->ifa_name)) continue;
        struct sockaddr_ll* sll = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
        if (sll->sll_halen == 6) memcpy(sll->sll_addr, mac, 6);
    }
    return r;
}

static int sbx_sysinfo(struct sysinfo* info) {
    int r = orig_sysinfo ? orig_sysinfo(info)
                         : (int)syscall(__NR_sysinfo, info);
    if (r != 0 || !info || !g_native_read_active) return r;
    // Selaraskan totalram dengan /proc/meminfo (tier marketing yang sama) dan
    // uptime dengan offset boottime L8, supaya sysinfo(2) tak membocorkan RAM
    // asli atau uptime asli ketika app membacanya lewat jalur syscall langsung.
    unsigned long unit = info->mem_unit ? info->mem_unit : 1UL;
    uint64_t target_kb = 0;
    if (g_ram_gb > 0) {
        target_kb = sbxnr::ram_gb_to_memtotal_kb(g_ram_gb);
    } else if (info->totalram) {
        uint64_t real_kb = static_cast<uint64_t>(info->totalram) * unit / 1024ULL;
        target_kb = sbxnr::ram_gb_to_memtotal_kb(
            static_cast<int>(sbxnr::round_up_marketing_gb(real_kb)));
    }
    if (target_kb) {
        uint64_t target_bytes = target_kb * 1024ULL;
        info->totalram = static_cast<unsigned long>(target_bytes / unit);
        if (info->freeram > info->totalram) info->freeram = info->totalram;
    }
    if (g_boot_off_sec > 0) info->uptime += static_cast<long>(g_boot_off_sec);
    return r;
}

static void sbx_register_lib_hooks(Api* api, dev_t dev, ino_t ino, bool capture_orig) {
    void** p_open       = capture_orig ? reinterpret_cast<void**>(&orig_open)       : nullptr;
    void** p_openat     = capture_orig ? reinterpret_cast<void**>(&orig_openat)     : nullptr;
    void** p_fopen      = capture_orig ? reinterpret_cast<void**>(&orig_fopen)      : nullptr;
    void** p_spget      = capture_orig ? reinterpret_cast<void**>(&orig_sysprop_get)     : nullptr;
    void** p_spread     = capture_orig ? reinterpret_cast<void**>(&orig_sysprop_read)    : nullptr;
    void** p_spreadcb   = capture_orig ? reinterpret_cast<void**>(&orig_sysprop_read_cb) : nullptr;
    void** p_ioctl      = capture_orig ? reinterpret_cast<void**>(&orig_ioctl)      : nullptr;
    void** p_getifaddrs = capture_orig ? reinterpret_cast<void**>(&orig_getifaddrs) : nullptr;
    void** p_sysinfo    = capture_orig ? reinterpret_cast<void**>(&orig_sysinfo)    : nullptr;

    api->pltHookRegister(dev, ino, "__system_property_get",
                         reinterpret_cast<void*>(sbx_sysprop_get),  p_spget);
    api->pltHookRegister(dev, ino, "__system_property_read",
                         reinterpret_cast<void*>(sbx_sysprop_read),  p_spread);
    api->pltHookRegister(dev, ino, "__system_property_read_callback",
                         reinterpret_cast<void*>(sbx_sysprop_read_cb), p_spreadcb);
    api->pltHookRegister(dev, ino, "open",
                         reinterpret_cast<void*>(sbx_open),   p_open);
    api->pltHookRegister(dev, ino, "openat",
                         reinterpret_cast<void*>(sbx_openat), p_openat);
    api->pltHookRegister(dev, ino, "fopen",
                         reinterpret_cast<void*>(sbx_fopen),  p_fopen);
    api->pltHookRegister(dev, ino, "open64",
                         reinterpret_cast<void*>(sbx_open),   nullptr);
    api->pltHookRegister(dev, ino, "openat64",
                         reinterpret_cast<void*>(sbx_openat), nullptr);
    api->pltHookRegister(dev, ino, "fopen64",
                         reinterpret_cast<void*>(sbx_fopen),  nullptr);
    api->pltHookRegister(dev, ino, "ioctl",
                         reinterpret_cast<void*>(sbx_ioctl),  p_ioctl);
    api->pltHookRegister(dev, ino, "getifaddrs",
                         reinterpret_cast<void*>(sbx_getifaddrs), p_getifaddrs);
    api->pltHookRegister(dev, ino, "sysinfo",
                         reinterpret_cast<void*>(sbx_sysinfo), p_sysinfo);
}

static int sbx_register_across_libs(Api* api) {
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    struct DevInoHash {
        size_t operator()(const std::pair<dev_t, ino_t>& p) const {
            return std::hash<uint64_t>()(((uint64_t)p.first << 32) | (uint64_t)p.second);
        }
    };
    std::unordered_set<std::pair<dev_t, ino_t>, DevInoHash> seen;
    bool first = true;
    char*  line = nullptr;
    size_t cap  = 0;
    ssize_t n;
    while ((n = getline(&line, &cap, f)) != -1) {
        char* path = strchr(line, '/');
        if (!path) continue;
        size_t pl = strlen(path);
        if (pl && path[pl - 1] == '\n') path[--pl] = '\0';
        if (pl < 3 || strcmp(path + pl - 3, ".so") != 0) continue;
        if (strstr(path, "sandboxid")) continue;

        unsigned dev_major = 0, dev_minor = 0;
        unsigned long ino_val = 0;
        char* p = line;
        for (int skip = 0; skip < 3 && *p; ++p)
            if (*p == ' ') ++skip;
        if (sscanf(p, "%x:%x %lu", &dev_major, &dev_minor, &ino_val) != 3) continue;
        dev_t dev = makedev(dev_major, dev_minor);
        ino_t ino = (ino_t)ino_val;
        if (!seen.insert(std::make_pair(dev, ino)).second) continue;
        sbx_register_lib_hooks(api, dev, ino, first);
        first = false;
    }
    free(line);
    fclose(f);
    return (int)seen.size();
}

static void install_native_read_hooks(Api* api) {

    if (val("SBX_NATIVE_READ") == "0") { LOGD("L9 disabled via kill switch"); return; }

    uint64_t seed = sbxnr::fnv1a(val("FINGERPRINT") + "|" + val("SERIAL") + "|" + val("ANDROID_ID"));
    g_boot_id = sbxnr::uuid_from_seed(seed);

    const std::string& pmac = val("WIFI_MAC");
    g_wifi_mac = sbxnr::is_valid_mac(pmac) ? pmac
                                           : sbxnr::mac_from_seed(seed ^ 0x9E3779B97F4A7C15ULL);

    g_proc_version = sbxnr::synth_proc_version(val("RELEASE"), val("INCREMENTAL"),
                                               val("BOARD_PLATFORM"), val("HOST"), seed);
    int persona_ram = std::atoi(val("RAM_GB").c_str());
    g_ram_gb     = persona_ram > 0 ? persona_ram : sbxnr::pixel_ram_gb(val("MODEL"));
    g_cpu_action = sbxnr::cpu_action_for(val("SOC_MANUFACTURER"), val("SOC_MODEL"), g_cpu_repl);

    if (!g_pkg.empty()) {
        uint64_t epoch_ms = strtoull(val("APPLOG_EPOCH").c_str(), nullptr, 10);
        if (epoch_ms <= 0) epoch_ms = 1700000000000ULL;
        uint64_t aseed = sbxnr::fnv1a(val("FINGERPRINT") + "|" + val("SERIAL") + "|" +
                                      val("ANDROID_ID") + "|" + g_pkg);
        g_applog    = sbxnr::make_applog_ids(aseed, epoch_ms);
        g_applog_ok = true;
        LOGD("L9 applog: pkg=%s did=…%s (per-pkg, epoch=%llu)",
             g_pkg.c_str(), g_applog.did.substr(g_applog.did.size() - 4).c_str(),
             (unsigned long long)epoch_ms);
    }

    if (!orig_sysprop_get)    orig_sysprop_get    = reinterpret_cast<sbx_sysprop_get_fn>(dlsym(RTLD_DEFAULT, "__system_property_get"));
    if (!orig_sysprop_read)    orig_sysprop_read    = reinterpret_cast<sbx_sysprop_read_fn>(dlsym(RTLD_DEFAULT, "__system_property_read"));
    if (!orig_sysprop_read_cb)  orig_sysprop_read_cb  = reinterpret_cast<sbx_sysprop_read_cb_fn>(dlsym(RTLD_DEFAULT, "__system_property_read_callback"));
    if (!orig_open)   orig_open   = reinterpret_cast<sbx_open_fn>(dlsym(RTLD_DEFAULT, "open"));
    if (!orig_openat) orig_openat = reinterpret_cast<sbx_openat_fn>(dlsym(RTLD_DEFAULT, "openat"));
    if (!orig_fopen)  orig_fopen  = reinterpret_cast<sbx_fopen_fn>(dlsym(RTLD_DEFAULT, "fopen"));
    if (!orig_ioctl)      orig_ioctl      = reinterpret_cast<sbx_ioctl_fn>(dlsym(RTLD_DEFAULT, "ioctl"));
    if (!orig_getifaddrs) orig_getifaddrs = reinterpret_cast<sbx_getifaddrs_fn>(dlsym(RTLD_DEFAULT, "getifaddrs"));
    if (!orig_sysinfo)    orig_sysinfo    = reinterpret_cast<sbx_sysinfo_fn>(dlsym(RTLD_DEFAULT, "sysinfo"));

    int libs = sbx_register_across_libs(api);
    if (libs == 0) {
        LOGW("L9: no mapped .so to hook — native reads not spoofed (kill-switch keeps flag off)");
        return;
    }
    if (!api->pltHookCommit()) {
        LOGW("L9: pltHookCommit gagal sebagian (%d libs registered) — coverage "
             "mungkin parsial, wrapper tetap aman (orig_* via dlsym)", libs);
    }
    g_native_read_active = orig_sysprop_get || orig_sysprop_read || orig_sysprop_read_cb ||
                  orig_open || orig_openat || orig_fopen;
    if (!g_native_read_active) {
        LOGW("L9: no real implementation resolvable — native reads not spoofed");
        return;
    }
    LOGD("L9 aktif (%d lib): boot_id=%s mac=%s ram=%dGB cpu=%d "
         "[open=%p openat=%p fopen=%p sysprop_get=%p sysprop_read=%p sysprop_read_cb=%p]",
         libs, g_boot_id.c_str(), g_wifi_mac.c_str(), g_ram_gb, g_cpu_action,
         reinterpret_cast<void*>(orig_open),   reinterpret_cast<void*>(orig_openat),
         reinterpret_cast<void*>(orig_fopen),  reinterpret_cast<void*>(orig_sysprop_get),
         reinterpret_cast<void*>(orig_sysprop_read),    reinterpret_cast<void*>(orig_sysprop_read_cb));
}

struct SbxCrashRec {
    uint32_t magic;
    int32_t  sig;
    int32_t  code;
    int32_t  sender;
    int32_t  pid;
    int32_t  hit;
    int64_t  alive_ms;
    void*    addr;
};
static const uint32_t SBX_CRASH_MAGIC = 0x54544352u;

static int         g_crash_pipe[2] = {-1, -1};
static char        g_watchdog_pkg_buf[128] = {0};
static int64_t     g_load_time_ms = 0;
static struct sigaction g_prev_sig[NSIG];
static std::atomic<int>      g_crash_count[NSIG];
static const int   CRASH_LIMIT = 3;

static int64_t sbx_now_ms() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const char* sbx_sig_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGABRT: return "SIGABRT";
        case SIGBUS:  return "SIGBUS";
        case SIGILL:  return "SIGILL";
        case SIGFPE:  return "SIGFPE";
        case SIGSYS:  return "SIGSYS";
        default:      return "?";
    }
}

static void sbx_crash_drain_loop() {
    SbxCrashRec rec;
    while (sandboxid::read_full(g_crash_pipe[0], &rec, sizeof(rec))) {
        if (rec.magic != SBX_CRASH_MAGIC) continue;
        LOGE("CRASH [%s] pkg=%s pid=%d signal=%d(%s) code=%d addr=%p sender=%d alive=%lldms hit=%d/%d",
             SBX_VARIANT_TAG, g_watchdog_pkg_buf, rec.pid, rec.sig, sbx_sig_name(rec.sig),
             rec.code, rec.addr, rec.sender, (long long)rec.alive_ms, rec.hit, CRASH_LIMIT);
    }
}

static void sbx_signal_handler(int sig, siginfo_t* info, void* ctx) {
    int n = 0;
    if (sig >= 0 && sig < NSIG) {

        n = g_crash_count[sig].fetch_add(1, std::memory_order_relaxed) + 1;
    }

    if (n <= CRASH_LIMIT && g_crash_pipe[1] >= 0) {

        int saved_errno = errno;
        struct timespec ts;
        syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &ts);
        SbxCrashRec rec;
        rec.magic    = SBX_CRASH_MAGIC;
        rec.sig      = sig;
        rec.code     = info ? info->si_code : 0;
        rec.sender   = info ? info->si_pid  : 0;
        rec.pid      = (int)getpid();
        rec.hit      = n;
        rec.alive_ms = ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000) - g_load_time_ms;
        rec.addr     = info ? info->si_addr : nullptr;
        ssize_t wr = ::write(g_crash_pipe[1], &rec, sizeof(rec));
        (void)wr;
        errno = saved_errno;
    }

    if (sig >= 0 && sig < NSIG) {
        struct sigaction* p = &g_prev_sig[sig];
        if ((p->sa_flags & SA_SIGINFO) && p->sa_sigaction) {
            p->sa_sigaction(sig, info, ctx);
        } else if (!(p->sa_flags & SA_SIGINFO) && p->sa_handler &&
                   p->sa_handler != SIG_DFL && p->sa_handler != SIG_IGN) {
            p->sa_handler(sig);
        } else {

            signal(sig, SIG_DFL);
            sigset_t ss;
            sigemptyset(&ss);
            sigaddset(&ss, sig);
            sigprocmask(SIG_UNBLOCK, &ss, nullptr);
            raise(sig);
        }
    }
}

static void install_crash_watchdog(const std::string& pkg) {
    static bool armed = false;
    if (armed) return;

    strncpy(g_watchdog_pkg_buf, pkg.c_str(), sizeof(g_watchdog_pkg_buf) - 1);
    g_load_time_ms = sbx_now_ms();

    if (pipe2(g_crash_pipe, O_CLOEXEC) == 0) {
        int fl = fcntl(g_crash_pipe[1], F_GETFL, 0);
        if (fl >= 0) fcntl(g_crash_pipe[1], F_SETFL, fl | O_NONBLOCK);
        std::thread(sbx_crash_drain_loop).detach();
    } else {
        g_crash_pipe[0] = g_crash_pipe[1] = -1;
        LOGE("crash watchdog: pipe2 failed errno=%d (logging disabled, chaining still armed)", errno);
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_flags     = SA_SIGINFO;
    sa.sa_sigaction = sbx_signal_handler;
    sigemptyset(&sa.sa_mask);

    static const int sigs[] = { SIGABRT, SIGFPE, SIGILL };
    for (int s : sigs) {
        g_crash_count[s] = 0;
        sigaction(s, &sa, &g_prev_sig[s]);
    }
    armed = true;
    LOGD("crash watchdog armed for %s (ABRT/FPE/ILL, limit=%d)", pkg.c_str(), CRASH_LIMIT);
}

static void set_str(JNIEnv* env, jclass c, const char* f, const std::string& v) {
    if (v.empty()) return;
    jfieldID id = env->GetStaticFieldID(c, f, "Ljava/lang/String;");
    if (!id || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jstring j = env->NewStringUTF(v.c_str());
    if (!j || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    env->SetStaticObjectField(c, id, j);
    if (env->ExceptionCheck()) env->ExceptionClear();
    env->DeleteLocalRef(j);
}

static void set_int(JNIEnv* env, jclass c, const char* f, int v) {
    jfieldID id = env->GetStaticFieldID(c, f, "I");
    if (!id || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    env->SetStaticIntField(c, id, v);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

static void set_long(JNIEnv* env, jclass c, const char* f, jlong v) {
    jfieldID id = env->GetStaticFieldID(c, f, "J");
    if (!id || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    env->SetStaticLongField(c, id, v);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0, n = s.size();
    while (i < n) {
        size_t j = s.find(',', i);
        if (j == std::string::npos) j = n;

        size_t a = i;
        while (a < j && (s[a] == ' ' || s[a] == '\t')) ++a;
        size_t b = j;
        while (b > a && (s[b-1] == ' ' || s[b-1] == '\t')) --b;
        if (b > a) out.emplace_back(s.data() + a, b - a);
        i = j + 1;
    }
    return out;
}

static void set_str_array(JNIEnv* env, jclass c, const char* f, const std::string& v) {
    if (v.empty()) return;
    std::vector<std::string> parts = split_csv(v);
    if (parts.empty()) return;

    jfieldID id = env->GetStaticFieldID(c, f, "[Ljava/lang/String;");
    if (!id || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    jclass str_cls = env->FindClass("java/lang/String");
    if (!str_cls || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(parts.size()), str_cls, nullptr);
    if (!arr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(str_cls);
        return;
    }
    for (size_t i = 0; i < parts.size(); ++i) {
        jstring j = env->NewStringUTF(parts[i].c_str());
        if (!j || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), j);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(j);
    }
    env->SetStaticObjectField(c, id, arr);
    if (env->ExceptionCheck()) env->ExceptionClear();

    env->DeleteLocalRef(arr);
    env->DeleteLocalRef(str_cls);
}

static void install_build_hook(JNIEnv* env) {
    jclass build = env->FindClass("android/os/Build");
    if (build && !env->ExceptionCheck()) {

        static const std::pair<const char*, const char*> f[] = {
            {"BRAND","BRAND"}, {"MANUFACTURER","MANUFACTURER"},
            {"MODEL","MODEL"}, {"DEVICE","DEVICE"}, {"PRODUCT","PRODUCT"},
            {"BOARD","BOARD"}, {"HARDWARE","HARDWARE"},
            {"SOC_MANUFACTURER","SOC_MANUFACTURER"}, {"SOC_MODEL","SOC_MODEL"},
            {"FINGERPRINT","FINGERPRINT"}, {"ID","ID"},
            {"DISPLAY","DISPLAY"}, {"BOOTLOADER","BOOTLOADER"},
            {"HOST","HOST"}, {"USER","USER"}, {"TYPE","TYPE"},
            {"TAGS","TAGS"}, {"RADIO","RADIO"},

            {"SERIAL","SERIAL"},
            {"SKU","SKU"},
            {"ODM_SKU","ODM_SKU"},
            {"CPU_ABI","CPU_ABI"},
            {"CPU_ABI2","CPU_ABI2"},
        };
        for (const auto& [fn, k] : f) set_str(env, build, fn, val(k));

        const std::string& butc = val("BUILD_TIME_UTC");
        if (!butc.empty()) {
            long long t = 0;
            if (sbx_parse_longlong(butc, t) && t > 0)
                set_long(env, build, "TIME", (jlong)t * 1000);
        }

        set_str_array(env, build, "SUPPORTED_ABIS",        val("SUPPORTED_ABIS"));
        set_str_array(env, build, "SUPPORTED_32_BIT_ABIS", val("SUPPORTED_32_BIT_ABIS"));
        set_str_array(env, build, "SUPPORTED_64_BIT_ABIS", val("SUPPORTED_64_BIT_ABIS"));

        env->DeleteLocalRef(build);
    } else env->ExceptionClear();

    jclass ver = env->FindClass("android/os/Build$VERSION");
    if (ver && !env->ExceptionCheck()) {
        set_str(env, ver, "RELEASE",        val("RELEASE"));

        set_str(env, ver, "CODENAME",       std::string("REL"));
        set_str(env, ver, "INCREMENTAL",    val("INCREMENTAL"));
        set_str(env, ver, "SECURITY_PATCH", val("SECURITY_PATCH"));

        set_str(env, ver, "BASE_OS",        val("BASE_OS"));

        const std::string& rel = val("RELEASE");
        if (!rel.empty()) {
            set_str(env, ver, "RELEASE_OR_CODENAME",        rel);
            set_str(env, ver, "RELEASE_OR_PREVIEW_DISPLAY", rel);
        }

        set_str(env, ver, "PREVIEW_SDK_FINGERPRINT", std::string("REL"));

        const std::string& s = val("SDK_INT");
        if (!s.empty()) {
            int sdk = std::atoi(s.c_str());
            if (sdk > 0) set_int(env, ver, "SDK_INT", sdk);
        }

        set_int(env, ver, "PREVIEW_SDK_INT", 0);

        const std::string& mpc = val("MEDIA_PERFORMANCE_CLASS");
        if (!mpc.empty()) {
            int v = std::atoi(mpc.c_str());
            if (v >= 0) set_int(env, ver, "MEDIA_PERFORMANCE_CLASS", v);
        }

        env->DeleteLocalRef(ver);
    } else env->ExceptionClear();
}

static void request_companion_mounts(int fd) {
    uint8_t cmd  = sandboxid::CMD_DO_MOUNTS;
    uint32_t pid = (uint32_t)::getpid();
    if (!sandboxid::write_full(fd, &cmd, 1) || !sandboxid::write_full(fd, &pid, sizeof(pid))) {

        LOGW("companion DO_MOUNTS write failed (socket unusable post-specialize?)");
        return;
    }
    uint32_t ok = 0;
    if (!sandboxid::read_full(fd, &ok, sizeof(ok))) { LOGW("companion mount ack failed"); return; }
    LOGI("bind-mount via companion: %u ok (pid=%u)", ok, pid);
}

static void request_companion_hide(int fd) {
    uint8_t cmd  = sandboxid::CMD_DO_HIDE;
    uint32_t pid = (uint32_t)::getpid();
    if (!sandboxid::write_full(fd, &cmd, 1) || !sandboxid::write_full(fd, &pid, sizeof(pid))) {
        LOGW("companion DO_HIDE write failed (socket unusable post-specialize?)");
        return;
    }
    uint32_t n = 0;
    if (!sandboxid::read_full(fd, &n, sizeof(n))) { LOGW("companion hide ack failed"); return; }
    LOGI("root/mount-trace hide via companion: %u detached (pid=%u)", n, pid);
}

class SandboxID : public zygisk::ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override {
        api_ = api; env_ = env;
        LOGD("onLoad build=%s pid=%d uid=%d", SBX_VARIANT_TAG, getpid(), getuid());
    }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        std::string pkg;
        if (args && args->nice_name) {
            const char* raw = env_->GetStringUTFChars(args->nice_name, nullptr);
            if (env_->ExceptionCheck()) env_->ExceptionClear();
            pkg = raw ? raw : "";
            if (raw) env_->ReleaseStringUTFChars(args->nice_name, raw);
        }
        LOGD("preAppSpecialize pkg='%s' pid=%d", pkg.c_str(), getpid());
        if (pkg.empty()) { unload(); return; }

        int fd = api_->connectCompanion();
        LOGD("connectCompanion() -> fd=%d", fd);
        if (fd < 0) { unload(); return; }

        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &SBX_IO_TIMEOUT, sizeof(SBX_IO_TIMEOUT));
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &SBX_IO_TIMEOUT, sizeof(SBX_IO_TIMEOUT));

        uint8_t cmd   = sandboxid::CMD_GET_IDENTITY;
        uint16_t plen = (uint16_t)pkg.size();
        if (!sandboxid::write_full(fd, &cmd, 1) ||
            !sandboxid::write_full(fd, &plen, sizeof(plen)) ||
            (plen && !sandboxid::write_full(fd, pkg.data(), plen))) {
            ::close(fd); unload(); return;
        }

        uint32_t len = 0;
        if (!sandboxid::read_full(fd, &len, sizeof(len)) || len > sandboxid::MAX_IDENTITY_BLOB) {
            ::close(fd); unload(); return;
        }
        if (len == 0) {
            LOGD("pkg='%s' not a target", pkg.c_str());
            ::close(fd); unload(); return;
        }

        blob_.resize(len);
        if (!sandboxid::read_full(fd, blob_.data(), len)) { ::close(fd); unload(); return; }

        // connectCompanion() HANYA boleh dipanggil di pre*Specialize (lihat
        // jni/zygisk.hpp:213 — "This API only works in the pre[XXX]Specialize
        // methods due to SELinux restrictions"). DO_MOUNTS wajib pasca-specialize
        // (butuh pid app + mount-ns app sudah jadi untuk setns), jadi socket ini
        // HARUS dibawa melewati specialize. exemptFd melindunginya dari fd-sweep
        // zygote (jni/zygisk.hpp:250-256); tanpa itu child akan crash karena fd
        // bocor (ZygiskNext wiki: leaked pre-specialize fd → forked child crash).
        // Gap sampai DO_MOUNTS ditoleransi di sisi companion (SBX_IDLE_TIMEOUT).
        if (api_->exemptFd(fd)) {
            comp_fd_ = fd;
        } else {
            LOGW("exemptFd(fd=%d) gagal — socket akan disapu zygote; bind-mount "
                 "dilewati untuk proses ini", fd);
            ::close(fd);
            comp_fd_ = -1;
        }

        active_  = true;
        pkg_     = pkg;

        LOGI("target active (%u B) [%s]", len, SBX_VARIANT_TAG);
        LOGD("target pkg='%s'", pkg.c_str());
    }

    void postAppSpecialize(const AppSpecializeArgs*) override {
        if (!active_) return;

        parse_blob();
        std::atomic_thread_fence(std::memory_order_release);
        LOGD("parse_blob: %zu identity keys", g_identity.size());
        rotate_sim_operator();

        install_build_hook(env_);
        install_prop_hook(api_, env_);
        install_leak_sensors(api_, env_);
        install_uptime_hook(api_, env_);
        g_pkg = pkg_;
        install_native_read_hooks(api_);
#ifdef SBX_DEBUG
        for (auto& kv : g_identity) LOGD("  [id] %s = %s", kv.first.c_str(), kv.second.c_str());
#endif
        install_crash_watchdog(pkg_);

#ifdef SBX_ENABLE_LSPLANT
        {

            sbxlsp::HookValues hv;
            hv.android_id = val("ANDROID_ID");
            hv.serial     = val("SERIAL");
            hv.wifi_mac   = val("WIFI_MAC");
            hv.bt_addr    = val("BLUETOOTH_ADDR");
            hv.op_num     = val("GSM_OPERATOR_NUMERIC");
            hv.op_alpha   = val("GSM_OPERATOR_ALPHA");
            hv.op_iso     = val("GSM_OPERATOR_ISO");
            hv.carrier_id = val("GSM_CARRIER_ID");
            hv.gaid       = val("GOOGLE_AID");
            hv.app_set_id = val("APP_SET_ID");
            hv.model      = val("MODEL");
            hv.build_time_utc = val("BUILD_TIME_UTC");
            // Nama proses bisa berimbuhan ":suffix"; getPackageInfo dipanggil
            // dengan nama paket dasar, jadi ambil bagian sebelum ':'.
            hv.self_pkg   = pkg_.substr(0, pkg_.find(':'));
            hv.seed       = sbxnr::fnv1a(val("FINGERPRINT") + "|" + val("SERIAL") + "|" +
                                         val("ANDROID_ID"));

            hv.gms_watch  = (val("SBX_GMS_HOOK") == "1");
            if (!sbxlsp::install_all(env_, hv))
                LOGE("L3 hooks not installed (continuing with L1/L2/L9)");

            if (!sbxdrm::install(hv.seed))
                LOGD("NDK MediaDrm hook not armed (Java MediaDrm hook still covers the common path)");
        }
#endif

        // Kirim DO_MOUNTS/DO_HIDE lewat socket companion yang dibawa dari
        // preAppSpecialize (connectCompanion tak bisa dipanggil di sini).
        // Companion menahan koneksi selama gap specialize via SBX_IDLE_TIMEOUT.
        if (comp_fd_ >= 0) {
            request_companion_mounts(comp_fd_);
            if (val("SBX_HIDE") == "1") request_companion_hide(comp_fd_);
            ::close(comp_fd_);
            comp_fd_ = -1;
        } else {
            LOGW("socket companion tak tersedia (exemptFd gagal) — bind-mount dilewati");
        }
    }

    void preServerSpecialize(ServerSpecializeArgs*) override { unload(); }

private:
    Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    int comp_fd_ = -1;
    std::string pkg_;
    bool active_ = false;
    std::vector<uint8_t> blob_;

    void unload() {
        if (api_) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void parse_blob() {
        const char* ptr = reinterpret_cast<const char*>(blob_.data());
        const char* end = ptr + blob_.size();
        while (ptr < end) {
            const char* nl = static_cast<const char*>(memchr(ptr, '\n', end - ptr));
            if (!nl) nl = end;
            size_t len = nl - ptr;
            if (len > 0 && ptr[len - 1] == '\r') --len;
            if (len == 0 || ptr[0] == '#') { ptr = nl + 1; continue; }
            const char* eq = static_cast<const char*>(memchr(ptr, '=', len));
            if (!eq) { ptr = nl + 1; continue; }
            size_t kend = eq - ptr;
            while (kend > 0 && (ptr[kend-1] == ' ' || ptr[kend-1] == '\t')) --kend;
            size_t kstart = 0;
            while (kstart < kend && (ptr[kstart] == ' ' || ptr[kstart] == '\t')) ++kstart;
            if (kstart >= kend) { ptr = nl + 1; continue; }
            const char* vptr = eq + 1;
            size_t vlen = len - (vptr - ptr);
            size_t vs = 0;
            while (vs < vlen && (vptr[vs] == ' ' || vptr[vs] == '\t')) ++vs;
            size_t ve = vlen;
            while (ve > vs && (vptr[ve-1] == ' ' || vptr[ve-1] == '\r' || vptr[ve-1] == '\n')) --ve;
            g_identity[std::string(ptr + kstart, kend - kstart)] = std::string(vptr + vs, ve - vs);
            ptr = nl + 1;
        }
    }
};

REGISTER_ZYGISK_MODULE(SandboxID)

extern "C" void sandboxid_companion(int client);
REGISTER_ZYGISK_COMPANION(sandboxid_companion)
