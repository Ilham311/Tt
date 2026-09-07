#!/system/bin/sh

MODDIR="${MODDIR:-/data/adb/modules/sandboxid}"
LOGFILE="${LOGFILE:-/cache/sandboxid-boot.log}"
IDENTITY_FILE="${IDENTITY_FILE:-$MODDIR/identity.prop}"
CARRIER_CONF="${CARRIER_CONF:-$MODDIR/carrier.conf}"
CARRIERS_FILE="${CARRIERS_FILE:-$MODDIR/carriers.tsv}"
BACKUP_DIR_ROOT="${BACKUP_DIR_ROOT:-$MODDIR/backups}"

mkdir -p "$BACKUP_DIR_ROOT" 2>/dev/null
chmod 0700 "$BACKUP_DIR_ROOT" 2>/dev/null

[ -w "$(dirname "$LOGFILE")" ] || LOGFILE="$MODDIR/sandboxid-boot.log"
touch "$LOGFILE" 2>/dev/null

_now() { date '+%Y-%m-%d %H:%M:%S'; }
_log() { printf '[%s] %s\n' "$(_now)" "$*" | tee -a "$LOGFILE"; }
log_step() { _log "==> $*"; }
log_info() { _log "    $*"; }
log_ok()   { _log "[OK] $*"; }
log_warn() { _log "[WARN] $*"; }
log_err()  { _log "[ERR] $*"; }

mask_id() {
    _v="$1"
    [ -z "$_v" ] && { printf '(empty)'; return; }
    _len=${#_v}
    if [ "$_len" -le 6 ]; then
        printf '******'
    else
        printf '%s****%s' "$(printf '%s' "$_v" | cut -c1-4)" "$(printf '%s' "$_v" | cut -c$((_len-1))-)"
    fi
}

_SE_REF=0
_SE_PRIOR=""
se_permissive() {
    if [ "$_SE_REF" -eq 0 ]; then
        _SE_PRIOR="$(getenforce 2>/dev/null || echo Unknown)"
        setenforce 0 2>/dev/null || true

        trap 'se_restore' EXIT INT TERM HUP
    fi
    _SE_REF=$((_SE_REF + 1))
}
se_restore() {
    [ "$_SE_REF" -gt 0 ] && _SE_REF=$((_SE_REF - 1))
    if [ "$_SE_REF" -eq 0 ] && [ "$_SE_PRIOR" = "Enforcing" ]; then
        setenforce 1 2>/dev/null || true
    fi
}

get_users() {
    if [ -d /data/system/users ]; then
        for d in /data/system/users/[0-9]*; do
            [ -d "$d" ] || continue
            basename "$d"
        done
    else
        echo 0
    fi
}

generate_uuid() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
        return
    fi
    r=$(od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' | cut -c1-32)
    printf '%s-%s-4%s-%s-%s\n' \
        "$(echo "$r" | cut -c1-8)" \
        "$(echo "$r" | cut -c9-12)" \
        "$(echo "$r" | cut -c14-16)" \
        "$(echo "$r" | cut -c17-20)" \
        "$(echo "$r" | cut -c21-32)"
}

generate_mac() {
    b=$(od -An -N5 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
    printf '02:%s:%s:%s:%s:%s\n' \
        "$(echo "$b" | cut -c1-2)" \
        "$(echo "$b" | cut -c3-4)" \
        "$(echo "$b" | cut -c5-6)" \
        "$(echo "$b" | cut -c7-8)" \
        "$(echo "$b" | cut -c9-10)"
}

_fw_run() {
    _n=0
    while [ "$_n" -lt 2 ]; do
        "$@" </dev/null >/dev/null 2>&1 && return 0
        _n=$((_n + 1))
        [ "$_n" -lt 2 ] && sleep 1
    done
    return 1
}

settings_put() {
    scope="$1"; key="$2"; val="$3"
    command -v settings >/dev/null 2>&1 || return 1
    _fw_run settings put --user 0 "$scope" "$key" "$val"
}

rp_set() {
    key="$1"; val="$2"
    case "$key" in
        persist.*) _rpflag="-p" ;;
        *)         _rpflag="-n" ;;
    esac
    if command -v resetprop >/dev/null 2>&1; then
        resetprop "$_rpflag" "$key" "$val" 2>/dev/null && return 0
    fi
    if [ -x "$MODDIR/bin/resetprop-rs" ]; then
        "$MODDIR/bin/resetprop-rs" "$_rpflag" "$key" "$val" 2>/dev/null && return 0
    fi
    if command -v resetprop-rs >/dev/null 2>&1; then
        resetprop-rs "$_rpflag" "$key" "$val" 2>/dev/null && return 0
    fi
    setprop "$key" "$val" 2>/dev/null
}

sbx_bin() {
    _d="${MODDIR:-/data/adb/modules/sandboxid}/bin"
    if [ -x "$_d/sandboxid" ]; then
        printf '%s\n' "$_d/sandboxid"
        return 0
    fi
    _abi="$(getprop ro.product.cpu.abi 2>/dev/null)"
    case "$_abi" in
        arm64-v8a)   _abi=arm64 ;;
        armeabi-v7a) _abi=arm ;;
        x86_64)      _abi=x86_64 ;;
        x86)         _abi=x86 ;;
        *)
            case "$(uname -m 2>/dev/null)" in
                aarch64)       _abi=arm64 ;;
                armv7l|armv8l) _abi=arm ;;
                x86_64)        _abi=x86_64 ;;
                i686|i386)     _abi=x86 ;;
                *)             _abi="" ;;
            esac
            ;;
    esac
    [ -n "$_abi" ] || return 1
    if [ -x "$_d/sandboxid-$_abi" ]; then
        printf '%s\n' "$_d/sandboxid-$_abi"
        return 0
    fi
    return 1
}

force_stop() {
    pkg="$1"
    command -v am >/dev/null 2>&1 || return 1
    _fw_run am force-stop --user 0 "$pkg"
    _rc=$?
    command -v killall >/dev/null 2>&1 && killall "$pkg" 2>/dev/null
    return "$_rc"
}

identity_get() {
    key="$1"
    [ -f "$IDENTITY_FILE" ] || return 1
    awk -F= -v k="$key" '$1==k { sub(/^[^=]*=/, ""); print; exit }' "$IDENTITY_FILE" 2>/dev/null
}

identity_persist() {
    key="$1"; val="$2"
    [ -z "$key" ] && return 1
    if [ ! -f "$IDENTITY_FILE" ]; then
        touch "$IDENTITY_FILE" 2>/dev/null || return 1
    fi
    tmp="${IDENTITY_FILE}.tmp.$$"
    awk -F= -v k="$key" '$1!=k {print}' "$IDENTITY_FILE" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    printf '%s=%s\n' "$key" "$val" >> "$tmp"
    mv "$tmp" "$IDENTITY_FILE" 2>/dev/null || { rm -f "$tmp"; return 1; }
    chmod 0644 "$IDENTITY_FILE" 2>/dev/null
    return 0
}

identity_del() {
    key="$1"
    [ -z "$key" ] && return 1
    [ -f "$IDENTITY_FILE" ] || return 0
    tmp="${IDENTITY_FILE}.tmp.$$"
    awk -F= -v k="$key" '$1!=k {print}' "$IDENTITY_FILE" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$IDENTITY_FILE" 2>/dev/null || { rm -f "$tmp"; return 1; }
    chmod 0644 "$IDENTITY_FILE" 2>/dev/null
    return 0
}

backup_rotate() {
    prefix="$1"; keep="${2:-10}"
    [ -d "$BACKUP_DIR_ROOT" ] || return 0
    ls -1t "$BACKUP_DIR_ROOT"/${prefix}* 2>/dev/null | tail -n +"$((keep + 1))" | while read -r f; do
        rm -f "$f" 2>/dev/null
    done
}

_valid_pkg() {
    case "$1" in
        ''|*[!A-Za-z0-9._]*) return 1 ;;
        .*|*/) return 1 ;;
    esac
    return 0
}

applog_wipe() {
    _pkg="${1:-}"
    if [ -z "$_pkg" ]; then
        _target="${TARGET_FILE:-$MODDIR/target.txt}"
        if [ ! -r "$_target" ]; then
            log_warn "applog_wipe: target.txt not readable ($_target)"
            return 1
        fi
        _rc=1
        while IFS= read -r _line || [ -n "$_line" ]; do
            _line=${_line%%#*}
            _line=$(printf '%s' "$_line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            [ -n "$_line" ] || continue
            applog_wipe "$_line" && _rc=0
        done < "$_target"
        return "$_rc"
    fi

    if ! _valid_pkg "$_pkg"; then
        log_err "applog_wipe: package name invalid ('$_pkg') — refused"
        return 1
    fi

    _data_dir=""
    for _base in /data/data /data/user/0; do
        [ -d "$_base/$_pkg" ] && { _data_dir="$_base/$_pkg"; break; }
    done
    if [ -z "$_data_dir" ]; then
        log_info "applog_wipe: $_pkg not installed — skipped"
        return 1
    fi

    log_step "AppLog wipe: $_pkg ($_data_dir)"

    force_stop "$_pkg" >/dev/null 2>&1

    se_permissive
    _sp_dir="$_data_dir/shared_prefs"
    if [ -d "$_sp_dir" ]; then
        _ts=$(date +%s)
        _safe_pkg=$(printf '%s' "$_pkg" | tr '/. ' '___')
        _bkp="$BACKUP_DIR_ROOT/applog_${_safe_pkg}_${_ts}.tar"
        if ls "$_sp_dir"/applog*.xml "$_sp_dir"/snssdk*.xml \
              "$_sp_dir"/bd_device_info.xml "$_sp_dir"/header_custom.xml \
              "$_sp_dir"/ug_install_settings_pref.xml 2>/dev/null | \
              head -1 | grep -q . ; then
            ( cd "$_sp_dir" && tar -cf "$_bkp" \
                applog*.xml snssdk*.xml bd_device_info.xml \
                header_custom.xml ug_install_settings_pref.xml 2>/dev/null ) || :
            [ -s "$_bkp" ] && chmod 0600 "$_bkp" 2>/dev/null
        fi
    fi

    _removed=0
    for _f in \
        applog.xml applog.xml.bak \
        applog_stats.xml applog_stats.xml.bak \
        applog_last_sp_session.xml applog_last_sp_session.xml.bak \
        applog_last_data.xml applog_last_data.xml.bak \
        applog_pack.xml applog_pack.xml.bak \
        applog_easter_egg.xml applog_easter_egg.xml.bak \
        snssdk_openudid.xml snssdk_openudid.xml.bak \
        snssdk_did.xml snssdk_did.xml.bak \
        bd_device_info.xml bd_device_info.xml.bak \
        header_custom.xml header_custom.xml.bak \
        ug_install_settings_pref.xml ug_install_settings_pref.xml.bak
    do
        if [ -e "$_sp_dir/$_f" ]; then
            rm -f "$_sp_dir/$_f" 2>/dev/null && _removed=$((_removed + 1))
        fi
    done

    _files_dir="$_data_dir/files"
    if [ -n "$_data_dir" ] && [ -d "$_files_dir" ]; then
        for _p in \
            bd_setting/device_id \
            bd_setting/openudid \
            bd_setting/clientudid \
            bd_setting/install_id \
            .cdid \
            applog \
            applog_v2 \
            applog_v3 \
            bd_tracker_n
        do
            [ -n "$_p" ] || continue
            _abs="$_files_dir/$_p"
            case "$_abs" in
                "$_data_dir"/files/*) : ;;
                *) continue ;;
            esac
            if [ -e "$_abs" ]; then
                rm -rf "${_abs:?}" 2>/dev/null && _removed=$((_removed + 1))
            fi
        done
    fi

    _nb_dir="$_data_dir/no_backup"
    if [ -d "$_nb_dir" ]; then
        for _p in applog_device_id.dat bd_device_id .cdid; do
            [ -e "$_nb_dir/$_p" ] && rm -f "$_nb_dir/$_p" 2>/dev/null && _removed=$((_removed + 1))
        done
    fi

    se_restore
    backup_rotate "applog_" 20

    if [ "$_removed" -gt 0 ]; then
        log_ok "$_pkg — cleared $_removed AppLog cache entr(y|ies)"
    else
        log_info "$_pkg — no AppLog cache present (already clean)"
    fi
    return 0
}

_applog_own() {
    _t="$1"; _uid="$2"; _mode="$3"; _refctx="$4"
    [ -e "$_t" ] || return 1
    [ -n "$_uid" ] || return 1
    chown "${_uid}:${_uid}" "$_t" 2>/dev/null || return 1
    chmod "$_mode" "$_t" 2>/dev/null
    [ -n "$_refctx" ] && command -v chcon >/dev/null 2>&1 && chcon "$_refctx" "$_t" 2>/dev/null
    return 0
}

_applog_map() {
    printf "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
    while [ "$#" -ge 2 ]; do
        [ -n "$2" ] && printf '    <string name="%s">%s</string>\n' "$1" "$2"
        shift 2
    done
    printf '</map>\n'
}

_applog_put() {
    _dst="$1"; _mode="$2"; _uid="$3"; _refctx="$4"; _body="$5"
    _tmp="${_dst%/*}/.sbxseed.$$"
    if ! printf '%s\n' "$_body" > "$_tmp" 2>/dev/null || [ ! -s "$_tmp" ]; then
        rm -f "$_tmp" 2>/dev/null
        return 1
    fi
    if ! mv -f "$_tmp" "$_dst" 2>/dev/null; then
        rm -f "$_tmp" 2>/dev/null
        return 1
    fi
    _applog_own "$_dst" "$_uid" "$_mode" "$_refctx" && return 0
    rm -f "$_dst" 2>/dev/null
    return 1
}

applog_seed() {
    _pkg="${1:-}"
    [ -n "$_pkg" ] || return 1
    if ! _valid_pkg "$_pkg"; then
        log_err "applog_seed: package name invalid ('$_pkg') — refused"
        return 1
    fi

    _data_dir=""
    for _base in /data/data /data/user/0; do
        [ -d "$_base/$_pkg" ] && { _data_dir="$_base/$_pkg"; break; }
    done
    [ -n "$_data_dir" ] || return 1

    _cli="$(sbx_bin 2>/dev/null)"
    if [ -z "$_cli" ] || [ ! -x "$_cli" ]; then
        log_warn "applog_seed: binary native tidak ada — seed dilewati, hook tetap spoof saat file dibaca"
        return 1
    fi
    _ids="$("$_cli" applog-ids "$_pkg" 2>/dev/null)"
    if [ -z "$_ids" ]; then
        log_warn "applog_seed: applog-ids gagal untuk $_pkg"
        return 1
    fi
    _did=$(printf '%s\n' "$_ids"        | awk -F= '$1=="DID"{print $2;exit}')
    _iid=$(printf '%s\n' "$_ids"        | awk -F= '$1=="IID"{print $2;exit}')
    _ssid=$(printf '%s\n' "$_ids"       | awk -F= '$1=="SSID"{print $2;exit}')
    _openudid=$(printf '%s\n' "$_ids"   | awk -F= '$1=="OPENUDID"{print $2;exit}')
    _clientudid=$(printf '%s\n' "$_ids" | awk -F= '$1=="CLIENTUDID"{print $2;exit}')
    _cdid=$(printf '%s\n' "$_ids"       | awk -F= '$1=="CDID"{print $2;exit}')
    if [ -z "$_did" ] || [ -z "$_iid" ] || [ -z "$_ssid" ] || [ -z "$_cdid" ] || \
       [ -z "$_openudid" ] || [ -z "$_clientudid" ]; then
        log_warn "applog_seed: output applog-ids tidak lengkap untuk $_pkg"
        return 1
    fi

    _uid=$(stat -c '%u' "$_data_dir" 2>/dev/null)
    case "$_uid" in
        ''|*[!0-9]*)
            log_warn "applog_seed: uid $_pkg tidak terbaca (stat '$_data_dir') — seed dibatalkan, file root-owned tidak ditinggalkan"
            return 1 ;;
    esac
    _sp="$_data_dir/shared_prefs"
    _bd="$_data_dir/files/bd_setting"

    se_permissive
    mkdir -p "$_sp" "$_bd" 2>/dev/null
    _spctx=$(ls -Zd "$_data_dir" 2>/dev/null | awk '{print $1}')
    case "$_spctx" in u:object_r:*) : ;; *) _spctx="" ;; esac
    for _d in "$_sp" "$_data_dir/files" "$_bd"; do
        [ -d "$_d" ] || continue
        if ! _applog_own "$_d" "$_uid" 0771 "$_spctx"; then
            se_restore
            log_warn "applog_seed: gagal chown $_d ke uid $_uid — seed dibatalkan"
            return 1
        fi
    done

    _seeded=0
    _failed=0
    _applog_put "$_sp/applog.xml" 0660 "$_uid" "$_spctx" \
        "$(_applog_map device_id "$_did" install_id "$_iid" ssid "$_ssid" cdid "$_cdid")" \
        && _seeded=$((_seeded + 1)) || _failed=$((_failed + 1))
    _applog_put "$_sp/snssdk_openudid.xml" 0660 "$_uid" "$_spctx" \
        "$(_applog_map openudid "$_openudid" clientudid "$_clientudid")" \
        && _seeded=$((_seeded + 1)) || _failed=$((_failed + 1))

    for _pair in "device_id=$_did" "install_id=$_iid" "openudid=$_openudid" \
                 "clientudid=$_clientudid" ".cdid=$_cdid"; do
        _n=${_pair%%=*}; _v=${_pair#*=}
        [ -n "$_v" ] || continue
        case "$_n" in
            .cdid) _dst="$_data_dir/files/.cdid" ;;
            *)     _dst="$_bd/$_n" ;;
        esac
        if _applog_put "$_dst" 0600 "$_uid" "$_spctx" "$_v"; then
            _seeded=$((_seeded + 1))
        else
            _failed=$((_failed + 1))
        fi
    done
    se_restore

    if [ "$_failed" -gt 0 ]; then
        log_warn "$_pkg — seed parsial: $_seeded ok, $_failed gagal (izin/SELinux) — hook tetap spoof lewat sintesis in-process"
        return 1
    fi
    if [ "$_seeded" -gt 0 ]; then
        log_ok "$_pkg — seeded $_seeded file (did=$(mask_id "$_did"))"
        return 0
    fi
    log_warn "$_pkg — seed gagal total (izin/SELinux?)"
    return 1
}

applog_regen() {
    _pkg="${1:-}"
    if [ -z "$_pkg" ]; then
        _target="${TARGET_FILE:-$MODDIR/target.txt}"
        if [ ! -r "$_target" ]; then
            log_warn "applog_regen: target.txt not readable ($_target)"
            return 1
        fi
        _rc=1
        while IFS= read -r _line || [ -n "$_line" ]; do
            _line=${_line%%#*}
            _line=$(printf '%s' "$_line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            [ -n "$_line" ] || continue
            applog_regen "$_line" && _rc=0
        done < "$_target"
        return "$_rc"
    fi

    _found=0
    for _base in /data/data /data/user/0; do
        [ -d "$_base/$_pkg" ] && { _found=1; break; }
    done
    if [ "$_found" = 0 ]; then
        log_info "applog_regen: $_pkg not installed — skipped"
        return 1
    fi

    log_step "AppLog regen: $_pkg"

    _now_ms="$(date +%s 2>/dev/null || echo 1700000000)000"
    identity_persist APPLOG_EPOCH "$_now_ms" || {
        log_warn "applog_regen: gagal bump APPLOG_EPOCH — ID lama dipakai lagi"
        return 1
    }

    force_stop "$_pkg" >/dev/null 2>&1
    applog_wipe "$_pkg" || :
    if applog_seed "$_pkg"; then
        log_ok "$_pkg — epoch bumped + cache wiped + seed baru (ID aktif saat app dibuka)"
    else
        log_warn "$_pkg — epoch bumped + cache wiped, tapi seed disk gagal; ID tetap dispoof in-process oleh hook L9 saat app membaca cache"
    fi
    return 0
}

applog_probe() {
    _pkg="${1:-}"
    [ -n "$_pkg" ] || return 1
    _data_dir=""
    for _base in /data/data /data/user/0; do
        [ -d "$_base/$_pkg" ] && { _data_dir="$_base/$_pkg"; break; }
    done
    if [ -z "$_data_dir" ]; then
        printf '%s 0 absent\n' "$_pkg"
        return 0
    fi
    _sp="$_data_dir/shared_prefs"
    _bd="$_data_dir/files/bd_setting"
    _count=0
    for _f in \
        "$_sp/applog.xml" "$_sp/applog_stats.xml" "$_sp/snssdk_openudid.xml" \
        "$_sp/bd_device_info.xml" "$_bd/device_id" "$_bd/install_id" \
        "$_bd/openudid" "$_bd/clientudid" "$_data_dir/files/.cdid"
    do
        [ -e "$_f" ] && _count=$((_count + 1))
    done
    _state=fresh
    if [ -f "$_sp/applog.xml" ] || [ -f "$_bd/device_id" ]; then
        _state=active
    fi
    printf '%s %d %s\n' "$_pkg" "$_count" "$_state"
    return 0
}
