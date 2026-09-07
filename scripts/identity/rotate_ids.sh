#!/system/bin/sh

set -u
MODDIR="${MODDIR:-/data/adb/modules/sandboxid}"
LOGFILE="${LOGFILE:-/cache/sandboxid-boot.log}"

if [ -r "$MODDIR/helpers.sh" ]; then
    . "$MODDIR/helpers.sh"
else
    echo "[ERR] $MODDIR/helpers.sh not found" >&2
    exit 2
fi

REBOOT_NEEDED=0
FAILURES=0

wipe_ssaid() {
    log_step "Wipe SSAID (backup + surgical)"
    se_permissive
    changed=0
    for u in $(get_users); do
        f="/data/system/users/$u/settings_ssaid.xml"
        [ -f "$f" ] || continue
        cp -f "$f" "$BACKUP_DIR_ROOT/settings_ssaid.$u.$(date +%s).bak" 2>/dev/null
        rm -f "$f" "$f.bak" "$f.tmp" 2>/dev/null
        changed=1
    done
    se_restore
    backup_rotate "settings_ssaid." 10
    if [ "$changed" = "1" ]; then
        REBOOT_NEEDED=1
        log_ok "SSAID cleared (backup in $BACKUP_DIR_ROOT)"
        log_warn "REBOOT REQUIRED: system_server regenerates SSAID at boot."
    else
        log_info "No settings_ssaid.xml present"
    fi
    return 0
}

set_gaid_value() {
    newgaid="${1:-}"
    [ -z "$newgaid" ] && newgaid="$(identity_get GOOGLE_AID 2>/dev/null || true)"
    if [ -z "$newgaid" ]; then
        newgaid="$(generate_uuid)"
        identity_persist GOOGLE_AID "$newgaid"
        log_info "GAID generated + persisted to identity.prop"
    fi
    log_step "Set GAID: $(mask_id "$newgaid")"

    settings_put global advertising_id "$newgaid" || log_warn "settings put advertising_id failed"
    settings_put global limit_ad_tracking 0       || :

    force_stop com.google.android.gms
    command -v am >/dev/null 2>&1 && am kill --user 0 com.google.android.gms </dev/null >/dev/null 2>&1
    sleep 1

    se_permissive
    GMS_DIR=/data/data/com.google.android.gms
    if [ ! -d "$GMS_DIR" ]; then
        se_restore
        log_warn "GMS not installed - value queued in Settings.Global only"
        return 0
    fi

    ADID="$GMS_DIR/shared_prefs/adid_settings.xml"
    [ -f "$ADID" ] && cp -f "$ADID" "$BACKUP_DIR_ROOT/adid_settings.$(date +%s).xml" 2>/dev/null
    rm -f "$ADID" 2>/dev/null
    rm -f "$GMS_DIR"/shared_prefs/adsidentity*.xml 2>/dev/null
    rm -f "$GMS_DIR"/files/adid_cache.dat 2>/dev/null
    rm -rf "$GMS_DIR"/no_backup/adid* 2>/dev/null

    gms_uid=$(stat -c '%u' "$GMS_DIR" 2>/dev/null)
    case "$gms_uid" in
        ''|*[!0-9]*)
            se_restore
            log_warn "GAID: uid GMS tak terbaca (stat '$GMS_DIR') — adid_settings.xml root-owned tak ditinggalkan, spoof lewat Settings.Global saja"
            return 0 ;;
    esac

    mkdir -p "$GMS_DIR/shared_prefs" 2>/dev/null
    _adid_tmp="$GMS_DIR/shared_prefs/.adid_settings.$$"
    cat > "$_adid_tmp" <<XMLEOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="adid_key">$newgaid</string>
    <boolean name="enable_limit_ad_tracking" value="false" />
    <long name="last_reset_time" value="$(date +%s)000" />
</map>
XMLEOF
    if [ ! -s "$_adid_tmp" ] || ! mv -f "$_adid_tmp" "$ADID" 2>/dev/null; then
        rm -f "$_adid_tmp" 2>/dev/null
        se_restore
        log_warn "GAID: gagal menulis adid_settings.xml — spoof lewat Settings.Global saja"
        return 0
    fi
    chown "${gms_uid}:${gms_uid}" "$ADID" 2>/dev/null
    chmod 0660 "$ADID" 2>/dev/null
    if command -v chcon >/dev/null 2>&1; then
        parent_ctx=$(ls -Zd "$GMS_DIR/shared_prefs" 2>/dev/null | awk '{print $1}')
        [ -n "$parent_ctx" ] && chcon "$parent_ctx" "$ADID" 2>/dev/null
    fi
    se_restore
    backup_rotate "adid_settings." 10
    log_ok "GAID written: $(mask_id "$newgaid")"
    return 0
}

clear_gsf_id() {
    log_step "Clear GSF ID (surgical: gservices/checkin DBs)"

    GSF_DIR=""
    for _base in /data/data /data/user/0; do
        [ -d "$_base/com.google.android.gsf" ] && { GSF_DIR="$_base/com.google.android.gsf"; break; }
    done
    if [ -z "$GSF_DIR" ]; then
        log_warn "GSF (com.google.android.gsf) not installed — GSF ID clear skipped"
        return 0
    fi

    force_stop com.google.android.gsf
    command -v am >/dev/null 2>&1 && am kill --user 0 com.google.android.gsf </dev/null >/dev/null 2>&1

    se_permissive
    _ts=$(date +%s)
    _bkp="$BACKUP_DIR_ROOT/gsf_dbs.${_ts}.tar"
    _dbdir="$GSF_DIR/databases"
    _removed=0
    if [ -d "$_dbdir" ]; then
        ( cd "$_dbdir" && tar -cf "$_bkp" \
            gservices.db gservices.db-journal gservices.db-wal gservices.db-shm \
            checkin.db checkin.db-journal checkin.db-wal checkin.db-shm \
            googlesettings.db googlesettings.db-journal 2>/dev/null ) || :
        [ -s "$_bkp" ] && chmod 0600 "$_bkp" 2>/dev/null
        for _f in gservices.db gservices.db-journal gservices.db-wal gservices.db-shm \
                  checkin.db checkin.db-journal checkin.db-wal checkin.db-shm \
                  googlesettings.db googlesettings.db-journal; do
            _abs="$_dbdir/$_f"
            case "$_abs" in
                "$GSF_DIR"/databases/*) : ;;
                *) continue ;;
            esac
            [ -e "$_abs" ] && rm -f "$_abs" 2>/dev/null && _removed=$((_removed + 1))
        done
    fi
    se_restore
    backup_rotate "gsf_dbs." 10

    force_stop com.google.android.gms

    if [ "$_removed" -gt 0 ]; then
        REBOOT_NEEDED=1
        log_ok "GSF ID cleared ($_removed DB file(s), backup in $BACKUP_DIR_ROOT)"
        log_warn "REBOOT/re-check-in REQUIRED: GSF regenerates android_id at next check-in."
    else
        log_info "No GSF check-in DBs present (already clean)"
    fi
    return 0
}

randomize_wlan_mac() {
    newmac="${1:-}"
    [ -z "$newmac" ] && newmac="$(identity_get WIFI_MAC 2>/dev/null || true)"
    if [ -z "$newmac" ]; then
        newmac="$(generate_mac)"
        identity_persist WIFI_MAC "$newmac"
        log_info "wlan MAC generated + persisted to identity.prop"
    fi
    log_step "Randomize wlan0 MAC: $(mask_id "$newmac")"

    if ! command -v ip >/dev/null 2>&1; then
        log_warn "ip(8) not available; MAC only recorded in identity.prop"
        return 1
    fi
    se_permissive
    ip link set wlan0 down 2>/dev/null
    sleep 1
    if ip link set dev wlan0 address "$newmac" 2>/dev/null; then
        log_ok "MAC: $(mask_id "$newmac")"
    else
        log_warn "MAC rejected by driver (Android 10+ uses per-SSID MAC)"
    fi
    ip link set wlan0 up 2>/dev/null

    WCS=/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml
    if [ -f "$WCS" ]; then
        cp -f "$WCS" "$BACKUP_DIR_ROOT/WifiConfigStore.$(date +%s).xml" 2>/dev/null
        log_info "Backup WifiConfigStore -> $BACKUP_DIR_ROOT"
        rm -f "$WCS" "$WCS.encrypted-checkpoint" 2>/dev/null
    fi
    se_restore
    backup_rotate "WifiConfigStore." 5
    return 0
}

rotate_bluetooth_mac() {
    newbt="${1:-}"
    [ -z "$newbt" ] && newbt="$(identity_get BLUETOOTH_ADDR 2>/dev/null || true)"
    if [ -z "$newbt" ]; then
        newbt="$(generate_mac)"
        identity_persist BLUETOOTH_ADDR "$newbt"
        log_info "BT MAC generated + persisted to identity.prop"
    fi
    log_step "Rotate Bluetooth adapter MAC: $(mask_id "$newbt")"

    rp_set persist.service.bdroid.bdaddr "$newbt"
    rp_set persist.sys.bt.bdaddr         "$newbt"
    rp_set persist.bluetooth.bdaddr      "$newbt"
    rp_set bluetooth.device.mac.address  "$newbt"
    rp_set ro.boot.btmacaddr             "$newbt"

    se_permissive
    updated=0
    for btcfg in /data/misc/bluedroid/bt_config.conf \
                 /data/misc/bluetooth/bt_config.conf \
                 /data/vendor/bluetooth/bt_config.conf; do
        [ -f "$btcfg" ] || continue
        owner=$(stat -c '%U:%G' "$btcfg" 2>/dev/null)
        mode=$(stat -c '%a' "$btcfg" 2>/dev/null)
        cp -f "$btcfg" "$BACKUP_DIR_ROOT/bt_config_addr.$(date +%s).conf" 2>/dev/null
        if grep -q '^Address = ' "$btcfg" 2>/dev/null; then
            NEWBT="$newbt" awk '/^Address = / { print "Address = " ENVIRON["NEWBT"]; next } { print }' \
                "$btcfg" > "${btcfg}.tmp" 2>/dev/null
        else
            NEWBT="$newbt" awk 'BEGIN{d=0} /^\[Adapter\]/ && !d { print; print "Address = " ENVIRON["NEWBT"]; d=1; next } { print } END { if (!d) { print "[Adapter]"; print "Address = " ENVIRON["NEWBT"] } }' \
                "$btcfg" > "${btcfg}.tmp" 2>/dev/null
        fi
        if [ -s "${btcfg}.tmp" ] && grep -q '^Address = ' "${btcfg}.tmp" 2>/dev/null \
                && mv "${btcfg}.tmp" "$btcfg" 2>/dev/null; then
            [ -n "$owner" ] && chown "$owner" "$btcfg" 2>/dev/null
            [ -n "$mode" ]  && chmod "$mode"  "$btcfg" 2>/dev/null
            log_ok "Rewrote Address in $btcfg"
            updated=1
        fi
        rm -f "${btcfg}.tmp" 2>/dev/null
    done
    [ "$updated" -eq 0 ] && log_warn "No writable bt_config.conf for Address"
    se_restore
    backup_rotate "bt_config_addr." 10

    force_stop com.android.bluetooth
    pkill -f 'com\.(android|google\.android)\.bluetooth' 2>/dev/null
    sleep 1
    log_ok "BT MAC applied: $(mask_id "$newbt") (toggle BT off/on to activate)"
    return 0
}

regen_applog() {
    _arg="${1:-}"
    log_step "Regenerate ByteDance AppLog IDs${_arg:+ ($_arg)}"

    if [ -n "$_arg" ]; then
        applog_regen "$_arg"
        return $?
    fi

    if ! grep -qE '^[[:space:]]*[^[:space:]#]' "$MODDIR/target.txt" 2>/dev/null; then
        log_info "target.txt kosong — tidak ada aplikasi ByteDance yang diregenerasi"
        log_info "Hint: 'rotate_ids.sh applog <package>' atau isi target.txt dulu"
        return 0
    fi
    applog_regen
}

wipe_applog_only() {
    _arg="${1:-}"
    log_step "Wipe-only (no seed) ByteDance AppLog cache${_arg:+ ($_arg)}"
    if [ -n "$_arg" ]; then
        applog_wipe "$_arg"
        return $?
    fi
    if ! grep -qE '^[[:space:]]*[^[:space:]#]' "$MODDIR/target.txt" 2>/dev/null; then
        log_info "target.txt kosong — tidak ada yang di-wipe"
        return 0
    fi
    applog_wipe
}

sync_boot_count() {
    bc="$(identity_get BOOT_COUNT 2>/dev/null || true)"
    case "$bc" in
        ''|*[!0-9]*)
            log_info "boot_count: identity.prop belum punya angka valid — dilewati"
            return 0 ;;
    esac
    log_step "Set Settings.Global.boot_count = $bc (dari identity.prop)"
    if settings_put global boot_count "$bc"; then
        log_ok "boot_count ke $bc"
    else
        log_warn "settings put boot_count gagal (mungkin tidak diizinkan perangkat)"
        return 1
    fi
    return 0
}

sync_device_name() {
    NEW_NAME="${1:-}"
    [ -z "$NEW_NAME" ] && NEW_NAME="$(identity_get BLUETOOTH_NAME 2>/dev/null || true)"
    [ -z "$NEW_NAME" ] && NEW_NAME="$(identity_get MODEL 2>/dev/null || true)"
    if [ -z "$NEW_NAME" ]; then
        log_err "device-name: identity.prop missing MODEL/BLUETOOTH_NAME."
        log_info "Hint: 'bin/sandboxid freshen' runs first via action.sh."
        return 1
    fi
    log_step "Sync device/BT name -> $NEW_NAME (from identity.prop, persona-consistent)"
    identity_persist BLUETOOTH_NAME "$NEW_NAME"

    settings_put global bluetooth_name "$NEW_NAME" || log_warn "settings put bluetooth_name failed"
    settings_put global device_name    "$NEW_NAME" || log_warn "settings put device_name failed"
    rp_set persist.bluetooth.adaptername "$NEW_NAME"

    se_permissive
    updated=0
    for btcfg in /data/misc/bluedroid/bt_config.conf \
                 /data/misc/bluetooth/bt_config.conf \
                 /data/vendor/bluetooth/bt_config.conf; do
        [ -f "$btcfg" ] || continue
        grep -q '^Name = ' "$btcfg" 2>/dev/null || continue
        owner=$(stat -c '%U:%G' "$btcfg" 2>/dev/null)
        mode=$(stat -c '%a' "$btcfg" 2>/dev/null)
        cp -f "$btcfg" "$BACKUP_DIR_ROOT/bt_config_name.$(date +%s).conf" 2>/dev/null
        NEWNAME="$NEW_NAME" awk '/^Name = / { print "Name = " ENVIRON["NEWNAME"]; next } { print }' \
            "$btcfg" > "${btcfg}.tmp" 2>/dev/null
        if [ -s "${btcfg}.tmp" ] && mv "${btcfg}.tmp" "$btcfg" 2>/dev/null; then
            [ -n "$owner" ] && chown "$owner" "$btcfg" 2>/dev/null
            [ -n "$mode" ]  && chmod "$mode"  "$btcfg" 2>/dev/null
            log_ok "Rewrote Name in $btcfg"
            updated=1
        fi
        rm -f "${btcfg}.tmp" 2>/dev/null
    done
    [ "$updated" -eq 0 ] && log_warn "No writable bt_config.conf for Name"
    se_restore
    backup_rotate "bt_config_name." 10

    force_stop com.android.bluetooth
    pkill -f 'com\.(android|google\.android)\.bluetooth' 2>/dev/null
    sleep 1
    log_ok "Name: $NEW_NAME"
    return 0
}

_carrier_clear_keys() {
    identity_del GSM_OPERATOR_NUMERIC
    identity_del GSM_OPERATOR_ALPHA
    identity_del GSM_OPERATOR_ISO
    identity_del GSM_CARRIER_ID
    identity_del GSM_SIM_STATE
}

_carrier_lookup_id() {
    _lk_mcc="$1"; _lk_mnc="$2"
    [ -r "$CARRIERS_FILE" ] || return 0
    awk -F'\t' -v mcc="$_lk_mcc" -v mnc="$_lk_mnc" '
        /^[[:space:]]*#/ || NF < 4 { next }
        $2 == mcc && $3 == mnc { gsub(/[[:space:]]/, "", $5); print $5; exit }
    ' "$CARRIERS_FILE" 2>/dev/null
}

set_carrier() {
    spec="${1:-status}"
    case "$spec" in
        status|'')
            log_step "Status operator / kartu SIM"
            if [ -f "$CARRIER_CONF" ]; then
                cn="$(awk -F= '$1=="NAME"{sub(/^[^=]*=/,"");print;exit}' "$CARRIER_CONF" 2>/dev/null)"
                cm="$(awk -F= '$1=="MCC"{print $2;exit}'  "$CARRIER_CONF" 2>/dev/null)"
                cc="$(awk -F= '$1=="MNC"{print $2;exit}'  "$CARRIER_CONF" 2>/dev/null)"
                ci="$(awk -F= '$1=="ISO"{print $2;exit}'  "$CARRIER_CONF" 2>/dev/null)"
                cid="$(awk -F= '$1=="CARRIER_ID"{print $2;exit}' "$CARRIER_CONF" 2>/dev/null)"
                cp="$(awk -F= '$1=="PHANTOM"{print $2;exit}' "$CARRIER_CONF" 2>/dev/null)"
                log_info "Operator : ${cn:-(kosong)}"
                log_info "Kode     : ${cm}${cc}"
                log_info "Negara   : ${ci:-(kosong)}"
                log_info "Carrier ID: ${cid:-(kosong, -1/UNKNOWN)}"
                [ "$cp" = "1" ] && log_info "Phantom  : aktif (slot kosong lapor SIM ada)"
            else
                log_info "Belum ada operator dipilih — pakai bawaan (Telkomsel 51010)"
            fi
            log_info "identity GSM_OPERATOR_NUMERIC = $(identity_get GSM_OPERATOR_NUMERIC 2>/dev/null || true)"
            log_info "identity GSM_OPERATOR_ALPHA   = $(identity_get GSM_OPERATOR_ALPHA 2>/dev/null || true)"
            return 0 ;;
        off|none|clear|default)
            log_step "Nonaktifkan operator kustom"
            rm -f "$CARRIER_CONF" 2>/dev/null
            _carrier_clear_keys
            log_ok "Operator kustom dihapus — kembali ke bawaan"
            return 0 ;;
    esac

    mcc="$(printf '%s' "$spec" | awk -F'|' '{print $1}' | tr -d ' \t\r')"
    mnc="$(printf '%s' "$spec" | awk -F'|' '{print $2}' | tr -d ' \t\r')"
    name="$(printf '%s' "$spec" | awk -F'|' '{print $3}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    iso="$(printf '%s'  "$spec" | awk -F'|' '{print $4}' | tr -d ' \t\r' | tr '[:upper:]' '[:lower:]')"
    phantom="$(printf '%s' "$spec" | awk -F'|' '{print $5}' | tr -d ' \t\r')"
    [ "$phantom" = "1" ] || phantom=0
    cid="$(printf '%s' "$spec" | awk -F'|' '{print $6}' | tr -d ' \t\r')"

    case "$mcc" in ''|*[!0-9]*) log_err "carrier: MCC tidak valid ('$mcc') — harus 3 digit angka"; return 2 ;; esac
    case "$mnc" in ''|*[!0-9]*) log_err "carrier: MNC tidak valid ('$mnc') — harus 2-3 digit angka"; return 2 ;; esac
    if [ "${#mcc}" -ne 3 ]; then log_err "carrier: MCC harus 3 digit (dapat '$mcc')"; return 2; fi
    if [ "${#mnc}" -lt 2 ] || [ "${#mnc}" -gt 3 ]; then log_err "carrier: MNC harus 2-3 digit (dapat '$mnc')"; return 2; fi
    if [ -z "$name" ]; then log_err "carrier: nama operator kosong"; return 2; fi

    [ -z "$cid" ] && cid="$(_carrier_lookup_id "$mcc" "$mnc" | tr -d ' \t\r')"
    case "$cid" in
        ''|-1) : ;;
        -[0-9]*|[0-9]*) case "${cid#-}" in *[!0-9]*) log_warn "carrier: CARRIER_ID '$cid' bukan angka — diabaikan"; cid="" ;; esac ;;
        *) log_warn "carrier: CARRIER_ID '$cid' bukan angka — diabaikan"; cid="" ;;
    esac

    _ph_note=""
    [ "$phantom" = "1" ] && _ph_note=", phantom"
    log_step "Set operator: $name ($mcc$mnc${iso:+, $iso}$_ph_note)"

    _oldmask=$(umask)
    umask 077
    tmpc="${CARRIER_CONF}.tmp.$$"
    {
        printf 'NAME=%s\n' "$name"
        printf 'MCC=%s\n'  "$mcc"
        printf 'MNC=%s\n'  "$mnc"
        printf 'ISO=%s\n'  "$iso"
        printf 'PHANTOM=%s\n' "$phantom"
        printf 'CARRIER_ID=%s\n' "$cid"
    } > "$tmpc" 2>/dev/null || { log_err "carrier: gagal tulis carrier.conf"; rm -f "$tmpc"; umask "$_oldmask"; return 1; }
    mv "$tmpc" "$CARRIER_CONF" 2>/dev/null || { log_err "carrier: gagal simpan carrier.conf"; rm -f "$tmpc"; umask "$_oldmask"; return 1; }
    chmod 0644 "$CARRIER_CONF" 2>/dev/null
    umask "$_oldmask"

    identity_persist GSM_OPERATOR_NUMERIC "$mcc$mnc" || log_warn "carrier: gagal tulis GSM_OPERATOR_NUMERIC"
    identity_persist GSM_OPERATOR_ALPHA   "$name"    || log_warn "carrier: gagal tulis GSM_OPERATOR_ALPHA"
    if [ -n "$iso" ]; then identity_persist GSM_OPERATOR_ISO "$iso"; else identity_del GSM_OPERATOR_ISO; fi
    if [ -n "$cid" ]; then identity_persist GSM_CARRIER_ID "$cid"; else identity_del GSM_CARRIER_ID; fi
    if [ "$phantom" = "1" ]; then identity_persist GSM_SIM_STATE "LOADED"; else identity_del GSM_SIM_STATE; fi

    log_ok "Operator aktif: $name ($mcc$mnc${cid:+, id $cid}) — berlaku saat aplikasi target dibuka lagi"
    return 0
}

cmd_status() {
    log_step "Current identifier state"
    if [ -f "$IDENTITY_FILE" ]; then
        log_info "identity.prop  : $IDENTITY_FILE"
        for k in MODEL DEVICE BRAND SERIAL ANDROID_ID GOOGLE_AID WIFI_MAC BLUETOOTH_ADDR BLUETOOTH_NAME; do
            v="$(identity_get "$k" 2>/dev/null || true)"
            [ -z "$v" ] && continue
            case "$k" in
                SERIAL|ANDROID_ID|GOOGLE_AID|WIFI_MAC|BLUETOOTH_ADDR) v="$(mask_id "$v")" ;;
            esac
            log_info "  $k = $v"
        done
    else
        log_info "identity.prop  : missing (run 'sandboxid freshen')"
    fi
    if command -v settings >/dev/null 2>&1; then
        log_info "Settings.Global.advertising_id  = $(mask_id "$(settings get --user 0 global advertising_id </dev/null 2>/dev/null)")"
        log_info "Settings.Global.device_name     = $(settings get --user 0 global device_name </dev/null 2>/dev/null)"
        log_info "Settings.Global.bluetooth_name  = $(settings get --user 0 global bluetooth_name </dev/null 2>/dev/null)"
    fi
    log_info "getprop ro.product.model              = $(getprop ro.product.model 2>/dev/null)"
    log_info "getprop persist.bluetooth.adaptername = $(getprop persist.bluetooth.adaptername 2>/dev/null)"
    log_info "getprop persist.service.bdroid.bdaddr = $(mask_id "$(getprop persist.service.bdroid.bdaddr 2>/dev/null)")"
    log_info "getprop ro.serialno                   = $(mask_id "$(getprop ro.serialno 2>/dev/null)")"
    for u in $(get_users); do
        f="/data/system/users/$u/settings_ssaid.xml"
        if [ -f "$f" ]; then
            log_info "  user $u SSAID xml = present ($(stat -c '%s' "$f") bytes)"
        else
            log_info "  user $u SSAID xml = absent"
        fi
    done

    if grep -qE '^[[:space:]]*[^[:space:]#]' "$MODDIR/target.txt" 2>/dev/null; then
        log_info "AppLog cache (per target):"
        while IFS= read -r _t || [ -n "$_t" ]; do
            _t=${_t%%#*}
            _t=$(printf '%s' "$_t" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
            [ -n "$_t" ] || continue
            _probe=$(applog_probe "$_t" 2>/dev/null)
            if [ -n "$_probe" ]; then
                _n=$(printf '%s' "$_probe" | awk '{print $2}')
                _st=$(printf '%s' "$_probe" | awk '{print $3}')
                log_info "  $_t = $_n file(s), state=$_st"
            else
                log_info "  $_t = (probe unavailable)"
            fi
        done < "$MODDIR/target.txt"
    fi
}

cmd="${1:-all}"
shift 2>/dev/null || true
MODVER=$(awk -F= '$1=="version"{print $2}' "$MODDIR/module.prop" 2>/dev/null)
log_step "rotate_ids.sh cmd=$cmd (module $MODVER)"

case "$cmd" in
    all)
        wipe_ssaid                    || FAILURES=$((FAILURES + 1))
        set_gaid_value "$@"           || FAILURES=$((FAILURES + 1))
        clear_gsf_id                  || FAILURES=$((FAILURES + 1))
        randomize_wlan_mac            || FAILURES=$((FAILURES + 1))
        rotate_bluetooth_mac          || FAILURES=$((FAILURES + 1))
        sync_device_name              || FAILURES=$((FAILURES + 1))
        sync_boot_count               || :
        regen_applog                  || :
        ;;
    safe)
        set_gaid_value "$@"           || FAILURES=$((FAILURES + 1))
        rotate_bluetooth_mac          || FAILURES=$((FAILURES + 1))
        sync_device_name              || :
        sync_boot_count               || :
        regen_applog                  || :
        ;;
    ssaid)                wipe_ssaid              || FAILURES=$((FAILURES + 1)) ;;
    gaid)                 set_gaid_value "$@"     || FAILURES=$((FAILURES + 1)) ;;
    gsf|gsf-id)           clear_gsf_id            || FAILURES=$((FAILURES + 1)) ;;
    wlan-mac|mac)         randomize_wlan_mac "$@" || FAILURES=$((FAILURES + 1)) ;;
    bt-mac|bluetooth-mac) rotate_bluetooth_mac "$@" || FAILURES=$((FAILURES + 1)) ;;
    device-name|name)     sync_device_name "$@"   || FAILURES=$((FAILURES + 1)) ;;
    boot-count|bootcount) sync_boot_count         || FAILURES=$((FAILURES + 1)) ;;
    carrier|sim)          set_carrier "$@"        || FAILURES=$((FAILURES + 1)) ;;
    applog|bytedance|regen-applog) regen_applog "$@"       || FAILURES=$((FAILURES + 1)) ;;
    applog-wipe|wipe-applog)       wipe_applog_only "$@"   || FAILURES=$((FAILURES + 1)) ;;
    status)               cmd_status ;;
    -h|--help|help)
        cat <<USAGE
Usage: rotate_ids.sh <cmd> [args]
  all                        - SSAID + GAID + GSF-ID + wlan-MAC + BT-MAC + device-name + boot-count + applog (default)
  safe                       - GAID + BT-MAC + device-name + boot-count + applog (no reboot, no wifi reset)
  ssaid                      - wipe settings_ssaid.xml (needs reboot)
  gaid [uuid]                - set Google Advertising ID
  gsf                        - clear GSF ID (gservices/checkin DBs; regenerates at next check-in)
  wlan-mac [xx:xx:..]        - set wlan0 MAC
  bt-mac [xx:xx:..]          - set Bluetooth adapter MAC
  device-name [name]         - sync device_name/BT to persona (identity.prop MODEL)
  boot-count                 - write Settings.Global.boot_count from identity.prop BOOT_COUNT
  carrier <spec>|off|status  - pick SIM/operator; spec = "MCC|MNC|NAME|ISO|PHANTOM|CARRIER_ID"
  applog [pkg]               - rotate ByteDance AppLog IDs (did/iid/ssid/openudid/clientudid/cdid):
                               bump APPLOG_EPOCH + wipe stale cache + force-stop; the zygisk hook
                               serves the new values in-process on next cold start
  applog-wipe [pkg]          - wipe cache only (no rotation) — forces SDK to re-register from server
  status                     - show current values (read-only)
USAGE
        exit 0 ;;
    *) log_err "Unknown cmd: $cmd (try: rotate_ids.sh help)"; exit 2 ;;
esac

[ "$REBOOT_NEEDED" = "1" ] && log_warn "REBOOT REQUIRED for SSAID regeneration."
if [ "$FAILURES" -gt 0 ]; then
    log_warn "rotate_ids.sh: $FAILURES step(s) reported failure"
    exit 1
fi
log_ok "rotate_ids.sh $cmd completed cleanly"
exit 0
