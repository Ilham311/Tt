#!/system/bin/sh

MODDIR="${MODDIR:-${0%/*}}"
IDENTITY="${IDENTITY:-$MODDIR/identity.prop}"

PASS=0; WARN=0; FAIL=0; INFO=0

emit() {
    case "$2" in
        PASS) PASS=$((PASS + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        INFO) INFO=$((INFO + 1)) ;;
    esac
    printf 'SELFTEST %s %s %s\n' "$1" "$2" "$3"
}

gp() { getprop "$1" 2>/dev/null; }

id_get() {
    [ -f "$IDENTITY" ] || return 1
    awk -F= -v k="$1" '$1==k { sub(/^[^=]*=/, ""); print; exit }' "$IDENTITY" 2>/dev/null
}

_fp="$(id_get FINGERPRINT)"
if [ -n "$_fp" ]; then
    emit identitas PASS "persona aktif: $_fp"
else
    emit identitas WARN "belum ada persona — tekan Acak perangkat baru"
fi

if [ -n "$_fp" ]; then
    _brand="$(id_get BRAND)";     _product="$(id_get PRODUCT)"
    _device="$(id_get DEVICE)";   _release="$(id_get RELEASE)"
    _bid="$(id_get ID)";          _incr="$(id_get INCREMENTAL)"
    _sdk="$(id_get SDK_INT)";     _patch="$(id_get SECURITY_PATCH)"
    _plat="$(id_get BOARD_PLATFORM)"
    _socman="$(id_get SOC_MANUFACTURER)"; _socmod="$(id_get SOC_MODEL)"
    _type="$(id_get TYPE)";       _tags="$(id_get TAGS)"

    _expfp="${_brand}/${_product}/${_device}:${_release}/${_bid}/${_incr}:user/release-keys"
    if [ "$_fp" = "$_expfp" ]; then
        emit koherensi PASS "fingerprint konsisten dengan field Build"
    else
        emit koherensi FAIL "fingerprint tidak cocok dengan BRAND/PRODUCT/DEVICE/RELEASE/ID/INCREMENTAL"
    fi

    case "$_sdk" in
        30) _exprel=11 ;;
        31) _exprel=12 ;;
        32) _exprel=12 ;;
        33) _exprel=13 ;;
        34) _exprel=14 ;;
        35) _exprel=15 ;;
        36) _exprel=16 ;;
        *)  _exprel="" ;;
    esac
    _relmaj="${_release%%.*}"
    if [ -z "$_sdk" ]; then
        emit koherensi WARN "SDK_INT kosong"
    elif [ -z "$_exprel" ]; then
        emit koherensi WARN "SDK_INT=$_sdk di luar rentang yang dipetakan (30-36)"
    elif [ "$_relmaj" = "$_exprel" ]; then
        emit koherensi PASS "SDK_INT=$_sdk cocok dengan RELEASE=$_release"
    else
        emit koherensi FAIL "SDK_INT=$_sdk tapi RELEASE=$_release (harusnya Android $_exprel)"
    fi

    _pd="$(printf '%s' "$_patch" | tr -d '0-9')"
    if [ "${#_patch}" -eq 10 ] && [ "$_pd" = "--" ]; then
        emit koherensi PASS "security_patch berformat YYYY-MM-DD ($_patch)"
    else
        emit koherensi WARN "security_patch bentuk tak lazim (${_patch:-kosong})"
    fi

    if [ "$_type" = "user" ] && [ "$_tags" = "release-keys" ]; then
        emit koherensi PASS "TYPE=user TAGS=release-keys"
    else
        emit koherensi WARN "TYPE=${_type:-kosong} TAGS=${_tags:-kosong} (bukan user/release-keys)"
    fi

    case "$_plat" in
        gs101|gs201|zuma|zumapro|laguna)
            case "$_socmod" in
                GS[0-9][0-9][0-9])
                    if [ "$_socman" = "Google" ]; then
                        emit koherensi PASS "SoC Tensor konsisten ($_socman $_socmod / $_plat)"
                    else
                        emit koherensi WARN "platform Tensor $_plat tapi SOC_MANUFACTURER=$_socman (bukan Google)"
                    fi
                    ;;
                *) emit koherensi FAIL "platform Tensor $_plat tapi SOC_MODEL=${_socmod:-kosong} (bukan GS*)" ;;
            esac
            ;;
        "") emit koherensi INFO "BOARD_PLATFORM kosong — lewati cek SoC" ;;
        *)
            if [ -n "$_socmod" ]; then
                emit koherensi PASS "SoC non-Tensor terisi ($_socman $_socmod / $_plat)"
            else
                emit koherensi WARN "SOC_MODEL kosong untuk platform $_plat"
            fi
            ;;
    esac

    _flavor="$(id_get FLAVOR)"
    if [ -n "$_flavor" ]; then
        if [ "$_flavor" = "${_product}-${_type}" ]; then
            emit koherensi PASS "FLAVOR konsisten ($_flavor)"
        else
            emit koherensi FAIL "FLAVOR='$_flavor' != PRODUCT-TYPE (${_product}-${_type})"
        fi
    fi

    _butc="$(id_get BUILD_TIME_UTC)"
    _nowts="$(date +%s 2>/dev/null)"
    case "$_butc" in
        '') emit koherensi WARN "BUILD_TIME_UTC kosong — Build.Time tidak dispoof (persona lama?)" ;;
        *[!0-9]*)
            emit koherensi FAIL "BUILD_TIME_UTC bukan angka ($_butc)" ;;
        *)
            if [ -n "$_nowts" ] && [ "$_butc" -ge 1230768000 ] && [ "$_butc" -le "$_nowts" ]; then
                emit koherensi PASS "BUILD_TIME_UTC masuk rentang wajar ($_butc)"
            else
                emit koherensi FAIL "BUILD_TIME_UTC di luar rentang wajar ($_butc)"
            fi
            ;;
    esac
fi

_vbs="$(gp ro.boot.verifiedbootstate)"
case "$_vbs" in
    green)             emit vbmeta PASS "verifiedbootstate=green" ;;
    orange|yellow|red) emit vbmeta FAIL "verifiedbootstate=$_vbs (bootloader tidak terkunci/termodifikasi)" ;;
    "")                emit vbmeta WARN "verifiedbootstate kosong — apply-boot belum jalan?" ;;
    *)                 emit vbmeta WARN "verifiedbootstate=$_vbs (tak dikenal)" ;;
esac

_ds="$(gp ro.boot.vbmeta.device_state)"
case "$_ds" in
    locked)   emit vbmeta PASS "vbmeta.device_state=locked" ;;
    unlocked) emit vbmeta FAIL "vbmeta.device_state=unlocked" ;;
    "")       emit vbmeta WARN "vbmeta.device_state kosong" ;;
    *)        emit vbmeta WARN "vbmeta.device_state=$_ds" ;;
esac

_fl="$(gp ro.boot.flash.locked)"
case "$_fl" in
    1)  emit vbmeta PASS "flash.locked=1" ;;
    0)  emit vbmeta FAIL "flash.locked=0 (bootloader terbuka)" ;;
    "") emit vbmeta WARN "flash.locked kosong" ;;
    *)  emit vbmeta WARN "flash.locked=$_fl" ;;
esac

_vm="$(gp ro.boot.veritymode)"
case "$_vm" in
    enforcing) emit vbmeta PASS "veritymode=enforcing" ;;
    "")        emit vbmeta WARN "veritymode kosong" ;;
    *)         emit vbmeta WARN "veritymode=$_vm (bukan enforcing)" ;;
esac

_dig="$(gp ro.boot.vbmeta.digest)"
case "$_dig" in
    "") emit vbmeta WARN "vbmeta.digest kosong" ;;
    *)
        _clean="$(printf '%s' "$_dig" | tr -d '0-9a-f')"
        if [ -z "$_clean" ] && [ "${#_dig}" -eq 64 ]; then
            emit vbmeta PASS "vbmeta.digest terpasang (64-hex)"
        else
            emit vbmeta WARN "vbmeta.digest bentuk tak lazim (len=${#_dig})"
        fi
        ;;
esac

_bt="$(gp ro.build.type)"
case "$_bt" in
    user)          emit build PASS "ro.build.type=user" ;;
    userdebug|eng) emit build FAIL "ro.build.type=$_bt (build non-rilis)" ;;
    "")            emit build WARN "ro.build.type kosong" ;;
    *)             emit build WARN "ro.build.type=$_bt" ;;
esac

_tg="$(gp ro.build.tags)"
case "$_tg" in
    release-keys) emit build PASS "ro.build.tags=release-keys" ;;
    *test-keys*)  emit build FAIL "ro.build.tags=$_tg (test-keys)" ;;
    "")           emit build WARN "ro.build.tags kosong" ;;
    *)            emit build WARN "ro.build.tags=$_tg" ;;
esac

_dbg="$(gp ro.debuggable)"
case "$_dbg" in
    0)  emit build PASS "ro.debuggable=0" ;;
    1)  emit build FAIL "ro.debuggable=1 (debuggable)" ;;
    *)  emit build WARN "ro.debuggable=${_dbg:-kosong}" ;;
esac

_sec="$(gp ro.secure)"
case "$_sec" in
    1)  emit build PASS "ro.secure=1" ;;
    0)  emit build FAIL "ro.secure=0" ;;
    *)  emit build WARN "ro.secure=${_sec:-kosong}" ;;
esac

_oem="$(gp sys.oem_unlock_allowed)"
case "$_oem" in
    0)  emit build PASS "sys.oem_unlock_allowed=0" ;;
    1)  emit build WARN "sys.oem_unlock_allowed=1 (OEM unlock diizinkan)" ;;
    *)  emit build INFO "sys.oem_unlock_allowed=${_oem:-kosong}" ;;
esac

_se="$(getenforce 2>/dev/null)"
case "$_se" in
    Enforcing)  emit selinux PASS "getenforce=Enforcing" ;;
    Permissive) emit selinux WARN "getenforce=Permissive (tell global; modul tidak mengubahnya)" ;;
    "")         emit selinux INFO "getenforce tidak tersedia" ;;
    *)          emit selinux INFO "getenforce=$_se" ;;
esac
emit selinux INFO "ro.build.selinux + node enforce di-mask per-app — verifikasi di dalam app target"

_qemu="$(gp ro.kernel.qemu)$(gp ro.boot.qemu)"
_hw="$(gp ro.hardware)"
if [ -n "$_qemu" ] || [ "$_hw" = "goldfish" ] || [ "$_hw" = "ranchu" ]; then
    emit rom FAIL "prop emulator/qemu terdeteksi device-wide (hw=$_hw)"
else
    emit rom PASS "tidak ada prop qemu device-wide"
fi

_lin="$(gp ro.modversion)$(gp ro.lineage.version)$(gp ro.cm.version)"
if [ -n "$_lin" ]; then
    emit rom WARN "prop custom-ROM device-wide ada (di-mask per-app oleh hook)"
else
    emit rom PASS "tidak ada prop custom-ROM device-wide"
fi

if command -v su >/dev/null 2>&1; then
    emit root INFO "biner su terlihat dari root shell (disembunyikan di app target hanya bila hider aktif)"
else
    emit root INFO "su tidak di PATH shell ini"
fi

_mgr=""
[ -d /data/adb/magisk ]      && _mgr="$_mgr magisk"
[ -d /data/adb/ksu ] || [ -e /data/adb/ksud ] && _mgr="$_mgr kernelsu"
[ -d /data/adb/ap ]  || [ -d /data/adb/apatch ] && _mgr="$_mgr apatch"
_mgr="${_mgr# }"
emit root INFO "root solution: ${_mgr:-tidak terdeteksi di /data/adb}"

if [ -f "$MODDIR/enable_hide" ]; then
    emit root INFO "hider mount-trace: AKTIF (opt-in) — berlaku di dalam app target"
else
    emit root INFO "hider mount-trace: nonaktif (default) — touch enable_hide untuk mengaktifkan"
fi

_mi=/proc/self/mountinfo
if [ -r "$_mi" ]; then
    _n="$(grep -c -E 'magisk|/data/adb|debug_ramdisk|worker| overlay | tmpfs ' "$_mi" 2>/dev/null)"
    [ -n "$_n" ] || _n=0
    emit mount INFO "$_n baris mount mencurigakan di root ns (di app target di-detach hanya bila hider aktif)"
else
    emit mount INFO "mountinfo tidak terbaca"
fi

if [ -r /system/etc/hosts ]; then
    _hn="$(grep -c -v -E '^[[:space:]]*(#|$)' /system/etc/hosts 2>/dev/null)"
    [ -n "$_hn" ] || _hn=0
    if [ "$_hn" -gt 10 ]; then
        emit hosts WARN "/system/etc/hosts punya $_hn entri (kemungkinan hosts adblock)"
    else
        emit hosts PASS "/system/etc/hosts wajar ($_hn entri)"
    fi
else
    emit hosts INFO "/system/etc/hosts tidak terbaca"
fi

_nnr="nonaktif"; [ -f "$MODDIR/no_native_read" ] && _nnr="AKTIF (native-read dimatikan)"
emit hooks INFO "redirect baca /proc,/sys (boot_id, MAC, /proc/version, meminfo, cpuinfo, enforce): kill-switch no_native_read=$_nnr"
emit hooks INFO "hook properti L2/L9 + bind build.prop: hanya di app target — verifikasi dengan app detektor"

_l3="nonaktif"
if [ -f "$MODDIR/enable_l3" ] || [ -f "$MODDIR/l3_status" ]; then
    _l3st="$(cat "$MODDIR/l3_status" 2>/dev/null)"
    case "$_l3st" in
        active*) _l3="aktif ($_l3st)" ;;
        skipped*|blocked*) _l3="dilewati ($_l3st)" ;;
        *) _l3="enable_l3 ada, status: ${_l3st:-tidak diketahui}" ;;
    esac
fi
emit hooks INFO "L3 (LSPlant Java method hook): $_l3 — verifikasi dengan VD-Infos/YASNAC di app target"

# M05: L3/LSPlant artifact verification
_l3_lib=""
for _abi in arm64-v8a armeabi-v7a x86_64 x86; do
    [ -f "$MODDIR/lib/$_abi/liblsplant.so" ] && { _l3_lib="$_abi"; break; }
done
if [ -n "$_l3_lib" ]; then
    emit hooks PASS "LSPlant library ditemukan (ABI: $_l3_lib)"
else
    if [ -f "$MODDIR/enable_l3" ]; then
        emit hooks WARN "enable_l3 ada tapi liblsplant.so tidak ditemukan — L3 hook tidak akan bekerja"
    else
        emit hooks INFO "LSPlant library tidak ada (L3 nonaktif, wajar)"
    fi
fi
if [ -f "$MODDIR/enable_l3" ]; then
    _hookcount="$(cat "$MODDIR/l3_hook_count" 2>/dev/null)"
    if [ -n "$_hookcount" ] && [ "$_hookcount" -gt 0 ] 2>/dev/null; then
        emit hooks PASS "L3 hook count: $_hookcount method(s) hooked"
    elif [ -n "$_l3st" ] && echo "$_l3st" | grep -q "active"; then
        emit hooks WARN "L3 aktif tapi hook_count tidak terbaca (periksa l3_hook_count)"
    fi
fi

printf 'SELFTEST SUMMARY pass=%d warn=%d fail=%d info=%d\n' "$PASS" "$WARN" "$FAIL" "$INFO"
