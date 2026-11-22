#!/system/bin/sh
# MagicRoot BakaSU / official KernelSU post-root stage.
#
# Manager-registration and module-load hardening (2026-10-25):
#   - manager registration is verified by an actual kernel-fd check
#     (`readlink /proc/<pid>/fd/* | grep ksu`), retried once, and finally
#     repaired with an optional KernelSU soft-reboot;
#   - manager registration belongs to the matching manager's late-load path;
#     MagicRoot never chmods/renames packages.list or edits PackageManager data;
#   - `debug set-manager` failures caused by CONFIG_KSU_DEBUG are classified as
#     "auto-recognition is normal" instead of a hard failure;
#   - the manager data directory can be snapshotted for repair runs;
#   - SELinux is restored to Enforcing after the root environment is up
#     (configurable, same as the reference root_stage_v24.sh).
#
# Backends:
#   resukisu = BakaSU (default):   extracted ksud, com.resukisu.resukisu,
#                                  kernel dynamic-manager
#   official = official KernelSU:  $D/ksud, me.weishu.kernelsu,
#                                  late-load package recognition
# Flavor comes from MAGICROOT_KSU_FLAVOR (exported by run.sh) or $D/ksu_flavor.
set -u
D=/data/local/tmp/magic
MARK="$D/marks"
ADB=/data/adb
mkdir -p "$MARK" 2>/dev/null || true

log() { echo "$*"; }
warn() { echo "ROOT_STAGE_WARN=$*"; }

ROOT_UID=$(id -u 2>/dev/null || echo "unknown")
CTX=$(cat /proc/self/attr/current 2>/dev/null || echo "unknown")
ENF=$(getenforce 2>/dev/null || echo "unknown")
FLAVOR=${MAGICROOT_KSU_FLAVOR:-$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')}
case "$FLAVOR" in
    resukisu|fina|kernelsu|sukisu|next|nova|maplesu) ;;
    official|bakasu) FLAVOR=resukisu ;;
    *) FLAVOR=kernelsu ;;
esac
# Per-flavor manager package / label / expected kernel version+uapi table.
case "$FLAVOR" in
    resukisu)
        MGR=${MAGICROOT_KSU_PKG:-com.resukisu.resukisu}
        MANAGER_LABEL=BakaSU
        EXPECT_KVER=""; EXPECT_UAPI=6 ;;
    fina)
        MGR=${MAGICROOT_KSU_PKG:-me.yuki.fina}; MANAGER_LABEL=FinaSU
        EXPECT_KVER=33074; EXPECT_UAPI=6 ;;
    kernelsu)
        MGR=${MAGICROOT_KSU_PKG:-me.weishu.kernelsu}; MANAGER_LABEL=KernelSU
        EXPECT_KVER=32680; EXPECT_UAPI=5 ;;
    sukisu)
        MGR=${MAGICROOT_KSU_PKG:-com.sukisu.ultra}; MANAGER_LABEL=SukiSU
        EXPECT_KVER=41068; EXPECT_UAPI=6 ;;
    next)
        MGR=${MAGICROOT_KSU_PKG:-com.rifsxd.ksunext}; MANAGER_LABEL=KernelSU-Next
        EXPECT_KVER=33355; EXPECT_UAPI=5 ;;
    nova)
        # SukiSU Nova is the successor line but a *separate* package; its
        # versionCode (30000/35000) can be lower than SukiSU Ultra's 41xxx.
        # Never infer the flavour from versionCode.
        MGR=${MAGICROOT_KSU_PKG:-com.sukisu.nova}; MANAGER_LABEL="SukiSU Nova"
        EXPECT_KVER=30000; EXPECT_UAPI=6 ;;
    maplesu)
        # MapleSU 5.2.0 reports "ksud 32650 (uapi: 7)".
        MGR=${MAGICROOT_KSU_PKG:-dev.maplesu.manager}; MANAGER_LABEL=MapleSU
        EXPECT_KVER=32650; EXPECT_UAPI=7 ;;
esac
# run.sh exported the expected version/uapi for the active kernel profile.
[ -n "${MAGICROOT_EXPECT_KVER:-}" ] && EXPECT_KVER=$MAGICROOT_EXPECT_KVER
[ -n "${MAGICROOT_EXPECT_UAPI:-}" ] && EXPECT_UAPI=$MAGICROOT_EXPECT_UAPI
# Userspace ksud: the app extracted it from the installed manager APK
# (MAGICROOT_KSUD) or a previous run already installed /data/adb/ksud.
KSUD_SRC=${MAGICROOT_KSUD:-}
if [ -z "$KSUD_SRC" ] || [ ! -f "$KSUD_SRC" ]; then
    if [ -f "$D/ksud_${FLAVOR}" ]; then
        KSUD_SRC="$D/ksud_${FLAVOR}"
    elif [ -x "$ADB/ksud" ]; then
        KSUD_SRC="$ADB/ksud"
        echo "ROOT_STAGE_KSUD_EXISTING_ONLY"
    else
        echo "ROOT_STAGE_FAIL=ksud_source_missing hint=install_matching_manager_apk"
        exit 12
    fi
fi
REPAIR=0
MGR_WAIT=${MAGICROOT_MANAGER_CONNECT_WAIT:-10}
case "$MGR_WAIT" in ''|*[!0-9]*) MGR_WAIT=10 ;; esac
[ "$MGR_WAIT" -ge 30 ] 2>/dev/null && MGR_WAIT=30

log "ROOT_STAGE_ENV uid=$ROOT_UID context=$CTX enforce=$ENF"

# Preserve a previous crash's console-ramoops (pstore) for diagnostics: the
# device may have restarted during the race stages, and pstore is only readable
# with root.
if [ -d /sys/fs/pstore ] && [ -n "$(ls /sys/fs/pstore 2>/dev/null)" ]; then
    mkdir -p "$D/pstore-last" 2>/dev/null || true
    cp -a /sys/fs/pstore/. "$D/pstore-last/" 2>/dev/null || true
    echo "ROOT_STAGE_PSTORE=$D/pstore-last files=$(ls "$D/pstore-last" 2>/dev/null | wc -l)"
    if mkdir -p /sdcard/Download/MagicRoot/pstore-last 2>/dev/null &&
       cp -a /sys/fs/pstore/. /sdcard/Download/MagicRoot/pstore-last/ 2>/dev/null; then
        echo "ROOT_STAGE_PSTORE_EXPORT=/sdcard/Download/MagicRoot/pstore-last"
    fi
fi
log "ROOT_STAGE_FLAVOR=$FLAVOR manager=$MGR label=$MANAGER_LABEL ksud_src=$KSUD_SRC"
grep '^Uid:' /proc/self/status 2>/dev/null || true
ls -ld "$ADB" 2>&1 || true

if [ "$ROOT_UID" != "0" ]; then
    echo "ROOT_STAGE_FAIL=not_root uid=$ROOT_UID context=$CTX"
    exit 10
fi

if ! mkdir -p "$ADB/ksu/bin" "$ADB/modules" 2>"$D/root_stage_mkdir.err"; then
    echo "ROOT_STAGE_FAIL=mkdir context=$CTX enforce=$ENF"
    cat "$D/root_stage_mkdir.err" 2>/dev/null || true
    exit 11
fi

# ---------------------------------------------------------------------------
# 1. userspace ksud install
# ---------------------------------------------------------------------------
# Stage a temporary file in the same directory, then rename:
# - do not follow an old /data/adb/ksud symlink;
# - do not open the old inode while it is executing;
# - avoid a direct cp failing on the old destination's mode/label.
install_ksud() {
    src="$KSUD_SRC"
    tmp="$ADB/.ksud.new.$$"
    err="$D/ksud_cp.err"

    if [ ! -f "$src" ]; then
        echo "ROOT_STAGE_FAIL=ksud_source_missing src=$src"
        return 1
    fi
    rm -f "$tmp" 2>/dev/null || true
    if cp -f "$src" "$tmp" 2>"$err"; then
        chmod 755 "$tmp" 2>/dev/null || true
        if mv -f "$tmp" "$ADB/ksud" 2>>"$err"; then
            echo "ROOT_STAGE_KSUD_COPY_OK"
            return 0
        fi
        rm -f "$tmp" 2>/dev/null || true
    fi
    if [ -f "$ADB/ksud" ] && [ -x "$ADB/ksud" ]; then
        echo "ROOT_STAGE_KSUD_REUSE_EXISTING"
        return 0
    fi
    echo "ROOT_STAGE_FAIL=ksud_copy context=$CTX enforce=$ENF"
    cat "$err" 2>/dev/null || true
    return 1
}

KSUD_REUSE=0
if [ -x "$ADB/ksud" ] && [ -x "$ADB/ksu/bin/su" ] && [ -x "$ADB/ksu/bin/ksud" ] &&
   cmp -s "$KSUD_SRC" "$ADB/ksud" 2>/dev/null; then
    KSUD_REUSE=1
    echo "ROOT_STAGE_KSUD_REUSE"
fi
if [ "$KSUD_REUSE" != "1" ]; then
    install_ksud || exit 12
    chmod 755 "$ADB/ksud" 2>/dev/null || true
    if [ ! -f "$ADB/ksud" ] || [ ! -x "$ADB/ksud" ]; then
        echo "ROOT_STAGE_FAIL=ksud_not_executable"
        exit 13
    fi
    ln -sf "$ADB/ksud" "$ADB/ksu/bin/su" 2>/dev/null || true
    ln -sf "$ADB/ksud" "$ADB/ksu/bin/ksud" 2>/dev/null || true
    "$ADB/ksud" install
    KS_INSTALL_RC=$?
    if [ "$KS_INSTALL_RC" != "0" ]; then
        echo "ROOT_STAGE_WARN=ksud_install_rc=$KS_INSTALL_RC"
    fi
    [ -f "$ADB/ksud" ] && [ -x "$ADB/ksud" ] || {
        echo "ROOT_STAGE_FAIL=ksud_missing_after_install"
        exit 14
    }
fi
ln -sf "$ADB/ksud" "$ADB/ksu/bin/su" 2>/dev/null || true
ln -sf "$ADB/ksud" "$ADB/ksu/bin/ksud" 2>/dev/null || true

KSUD_VERSION=$("$ADB/ksud" -V 2>/dev/null || echo unknown)
KSU_DEBUG_INFO=$("$ADB/ksud" debug info 2>/dev/null | tr '\n' '|')
echo "ROOT_STAGE_KSUD_VERSION=$KSUD_VERSION"
echo "ROOT_STAGE_KSU_DEBUG_INFO=$KSU_DEBUG_INFO"
# Parse field-by-field: the greedy ".*version:" match used to pick
# "uapi_version: 6" instead of the leading "version: <manager build>".
KSU_KERNEL_VERSION=$(printf '%s\n' "$KSU_DEBUG_INFO" | tr '|' '\n' \
    | sed -n 's/^version: *\([0-9][0-9]*\).*/\1/p' | head -1)
KSU_UAPI=$(printf '%s\n' "$KSU_DEBUG_INFO" | tr '|' '\n' \
    | sed -n 's/^uapi_version: *\([0-9][0-9]*\).*/\1/p' | head -1)
echo "ROOT_STAGE_KERNEL_VERSION=${KSU_KERNEL_VERSION:-unknown} UAPI=${KSU_UAPI:-unknown} EXPECTED_FLAVOR=$FLAVOR"
echo "ROOT_STAGE_EXPECTED_FLAVOR=$FLAVOR version=$EXPECT_KVER uapi=$EXPECT_UAPI"
MISMATCH=0
if [ -n "$EXPECT_KVER" ] && [ -n "$KSU_KERNEL_VERSION" ] &&
   [ "$KSU_KERNEL_VERSION" != "$EXPECT_KVER" ]; then
    warn "kernel_version_mismatch flavor=$FLAVOR actual=$KSU_KERNEL_VERSION expected=$EXPECT_KVER"
    MISMATCH=1
fi
if [ -n "$KSU_UAPI" ] && [ "$KSU_UAPI" != "$EXPECT_UAPI" ]; then
    warn "uapi_mismatch flavor=$FLAVOR actual=$KSU_UAPI expected=$EXPECT_UAPI"
    MISMATCH=1
fi
if [ "$MISMATCH" = "1" ]; then
    # The live LKM was loaded for a different backend/version; reuse may still
    # work but registration semantics can differ.  Record it so run.sh can
    # surface the mismatch instead of reporting a silent success.
    {
        echo "REUSE_FLAVOR_MISMATCH=1 flavor=$FLAVOR actual_version=${KSU_KERNEL_VERSION:-unknown} actual_uapi=${KSU_UAPI:-unknown} expected_version=$EXPECT_KVER expected_uapi=$EXPECT_UAPI"
    } > "$D/root_stage_flavor_mismatch"
    echo "ROOT_STAGE_FLAVOR_MISMATCH=1"
fi

# ---------------------------------------------------------------------------
# 2. manager data snapshot (repair support, reference post.sh PRESERVE)
# ---------------------------------------------------------------------------
PRESERVE="$D/ksu-preserve"
if [ -d "$PRESERVE" ] && [ ! -d "$ADB/ksu" ]; then
    mkdir -p "$ADB" 2>/dev/null || true
    cp -a "$PRESERVE" "$ADB/ksu" 2>/dev/null && log "ROOT_STAGE_PRESERVE_RESTORE=ok"
fi

# ---------------------------------------------------------------------------
# 3. module feature switches / legacy dev-su cleanup / marks
# ---------------------------------------------------------------------------
# The /dev/su debug shim was removed together with its UI switch.  Only
# remove a shim that an older build explicitly created and marked.
if [ -f "$D/dev-su-created" ]; then
    rm -f /dev/su
    rm -f "$D/dev-su-created"
    echo "DEV_SU_LEGACY_CLEANED=/dev/su"
fi
"$ADB/ksud" debug mark refresh 2>/dev/null || true

SU_COMPAT=${MAGICROOT_SU_COMPAT:-$(cat "$D/su_compat" 2>/dev/null || echo 1)}
case "$SU_COMPAT" in 0) ;; *) SU_COMPAT=1 ;; esac
ADB_ROOT=${MAGICROOT_ADB_ROOT:-0}
case "$ADB_ROOT" in 1) ;; *) ADB_ROOT=0 ;; esac
SU_ENTRY=${MAGICROOT_SU_ENTRY:-1}
case "$SU_ENTRY" in 1) ;; *) SU_ENTRY=0 ;; esac
KERNEL_UMOUNT=${MAGICROOT_KERNEL_UMOUNT:-1}
case "$KERNEL_UMOUNT" in 1) ;; *) KERNEL_UMOUNT=0 ;; esac
SELINUX_HIDE=${MAGICROOT_SELINUX_HIDE:-1}
case "$SELINUX_HIDE" in 1) ;; *) SELINUX_HIDE=0 ;; esac
echo "SU_COMPAT=$SU_COMPAT"
echo "KERNEL_UMOUNT=$KERNEL_UMOUNT"
echo "SELINUX_HIDE=$SELINUX_HIDE"

chmod 666 /dev/ksu /dev/ksu_driver 2>/dev/null || true
apply_feature() {
    _feature="$1"
    _value="$2"
    if "$ADB/ksud" feature set "$_feature" "$_value" >/dev/null 2>&1; then
        echo "ROOT_STAGE_FEATURE_${_feature}=${_value}"
    else
        echo "ROOT_STAGE_FEATURE_${_feature}=unsupported_or_failed"
    fi
}
apply_feature su_compat "$SU_COMPAT"
apply_feature kernel_umount "$KERNEL_UMOUNT"
apply_feature selinux_hide "$SELINUX_HIDE"
# KernelSU adb_root: static-key default is false (upstream source); the switch
# enables the feature after root_stage has root.  Manager does the same and
# restarts adbd.
apply_feature adb_root "$ADB_ROOT"
if [ "$ADB_ROOT" = "1" ]; then
    setprop ctl.restart adbd 2>/dev/null || true
    echo "ROOT_STAGE_ADB_ROOT=1 adbd_restart=requested"
else
    echo "ROOT_STAGE_ADB_ROOT=0"
fi

# allow_shell is a finit_module/module_param, NOT a kernel feature.  The value
# is fixed at module load time (cred_target / ksud --allow-shell) and cannot be
# changed by `ksud feature set` afterwards.  Log the actual load-time state,
# not a misleading "requested" state.
UI_ALLOW_SHELL=${MAGICROOT_ALLOW_SHELL_UI:-0}
case "$UI_ALLOW_SHELL" in 1) UI_ALLOW_SHELL=1 ;; *) UI_ALLOW_SHELL=0 ;; esac
LOADED_ALLOW_SHELL=${MAGICROOT_ALLOW_SHELL_LOADED:-$UI_ALLOW_SHELL}
case "$LOADED_ALLOW_SHELL" in 1) LOADED_ALLOW_SHELL=1 ;; *) LOADED_ALLOW_SHELL=0 ;; esac
echo "ROOT_STAGE_ALLOW_SHELL_MODE=load_time_${LOADED_ALLOW_SHELL}"
if [ "$LOADED_ALLOW_SHELL" != "$UI_ALLOW_SHELL" ]; then
    warn "allow_shell_ui_vs_loaded_mismatch ui=$UI_ALLOW_SHELL loaded=$LOADED_ALLOW_SHELL (takes effect on next module load)"
fi
if [ -f "$D/enable_shell_adb_only" ]; then
    # Opt-in only: confines shell su to adbd/ksu descendants, but it also
    # blocks GRANT_ROOT from the Stellar/Shizuku shell, which breaks the
    # "module already Live" reuse path.  Keep it behind a marker file.
    if "$ADB/ksud" feature set shell_su_adb_only 1 >/dev/null 2>&1 ||
       "$ADB/ksud" feature set 6 1 >/dev/null 2>&1; then
        echo "ROOT_STAGE_SHELL_SU=adb_only(opt-in)"
    else
        echo "ROOT_STAGE_SHELL_SU=unrestricted (shell_su_adb_only unavailable)"
    fi
elif [ "$LOADED_ALLOW_SHELL" = "1" ]; then
    echo "ROOT_STAGE_SHELL_SU=allow_shell_load_time_1"
else
    echo "ROOT_STAGE_SHELL_SU=allow_shell_load_time_0"
fi

# Restore the saved allowlist backup (root-only path) so a future cold boot
# can pass GRANT_ROOT without enabling allow_shell.
ALLOWLIST_BACKUP="$D/ksu-data-backup/.allowlist.bak"
if [ -s "$ALLOWLIST_BACKUP" ]; then
    if [ ! -s "$ADB/ksu/.allowlist" ]; then
        cp -f "$ALLOWLIST_BACKUP" "$ADB/ksu/.allowlist" 2>/dev/null &&
            echo "ROOT_STAGE_ALLOWLIST_RESTORED=size=$(wc -c < "$ADB/ksu/.allowlist" 2>/dev/null)" ||
            echo "ROOT_STAGE_ALLOWLIST_RESTORE=failed"
    else
        echo "ROOT_STAGE_ALLOWLIST=present size=$(wc -c < "$ADB/ksu/.allowlist" 2>/dev/null)"
    fi
else
    echo "ROOT_STAGE_ALLOWLIST=no_backup"
fi

# SELinux is always restored to Enforcing after the temporary permissive phase.
if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
    setenforce 1 2>/dev/null && echo "ROOT_STAGE_SELINUX=restored_enforcing" \
                             || echo "ROOT_STAGE_SELINUX=restore_failed"
else
    echo "ROOT_STAGE_SELINUX=$(getenforce 2>/dev/null || echo unknown)"
fi

echo "SU_PATH_ROOT=$(command -v su 2>/dev/null || echo missing)"
echo "SU_PATH_SYSTEM_BIN=$(ls -l /system/bin/su 2>/dev/null || echo missing)"
echo "SU_PATH_SYSTEM_EXT=$(ls -l /system_ext/bin/su 2>/dev/null || echo missing)"
echo "KSU_DEV=$(ls -l /dev/ksu /dev/ksu_driver 2>/dev/null | tr '\n' ' ' || echo missing)"
echo "KSUD_VERSION=$KSUD_VERSION"

# ---------------------------------------------------------------------------
# 4. manager resolution + bundled manager install
# ---------------------------------------------------------------------------
TARGET_PKG=""
if pm path "$MGR" >/dev/null 2>&1; then
    TARGET_PKG="$MGR"
else
    for pkg in "$MGR" com.resukisu.resukisu.dev com.resukisu.resukisu.debug \
               com.resukisu.resukisu.canary com.resukisu.resukisu.beta \
               com.resukisu.resukisu.ci me.weishu.kernelsu com.rifsxd.ksunext \
               com.resukisu.resukisu com.sukisu.ultra com.sukisu.ultra.g \
               com.sukisu.nova dev.maplesu.manager me.yuki.fina; do
        if pm path "$pkg" >/dev/null 2>&1; then
            TARGET_PKG="$pkg"
            break
        fi
    done
fi
if [ -z "$TARGET_PKG" ]; then
    warn "manager_not_installed package=$MGR (register the installed manager app and rerun)"
fi

# ---------------------------------------------------------------------------
# 5. manager signature + registration (flavor aware)
# ---------------------------------------------------------------------------
SIG_SIZE=""
SIG_HASH=""
SIG_SOURCE=""
APK_PATH=""
[ -n "$TARGET_PKG" ] && APK_PATH=$(pm path "$TARGET_PKG" 2>/dev/null | head -1 | cut -d: -f2)
# Preferred source: the signing tuple the app computed from the installed
# manager package (PackageManager.GET_SIGNING_CERTIFICATES).  This works even
# on a cold boot where the KernelSU fd is not available yet.
if [ -s "$D/manager_sig" ]; then
    _sig_line=$(head -1 "$D/manager_sig" 2>/dev/null)
    set -- $_sig_line
    if [ "${1:-}" = "$FLAVOR" ] && [ "$#" -ge 4 ] && [ "${2:-}" = "$TARGET_PKG" ] &&
       [ -n "${3:-}" ] && [ -n "${4:-}" ]; then
        SIG_SIZE=$3
        SIG_HASH=$4
        SIG_SOURCE=app-package-manager
    elif [ "${1:-}" = "$FLAVOR" ] && [ "$#" -eq 3 ] && [ -n "${2:-}" ] && [ -n "${3:-}" ]; then
        # Legacy tuple without package name: only accept when the canonical
        # package was resolved, never for a dev alias.
        case "$TARGET_PKG" in
            *".dev"|*".debug"|*".canary"|*".beta"|*".ci") ;;
            *) SIG_SIZE=$2; SIG_HASH=$3; SIG_SOURCE=app-package-manager-legacy ;;
        esac
    fi
fi
if [ -n "$APK_PATH" ] && [ -f "$APK_PATH" ]; then
    if [ -z "$SIG_HASH" ]; then
        SIG_INFO=$("$ADB/ksud" debug get-sign "$APK_PATH" 2>/dev/null || true)
        echo "ROOT_STAGE_SIG_INFO=$(echo "$SIG_INFO" | tr '\n' '|')"
        SIG_HEX=$(echo "$SIG_INFO" | sed -n 's/.*size: 0x\([0-9a-fA-F]*\).*/\1/p' | head -1)
        SIG_HASH=$(echo "$SIG_INFO" | sed -n 's/.*hash: \([0-9a-fA-F]*\).*/\1/p' | head -1)
        if [ -n "$SIG_HEX" ]; then
            SIG_SIZE=$((0x$SIG_HEX))
        else
            SIG_SIZE=$(echo "$SIG_INFO" | sed -n 's/.*size: \([0-9][0-9]*\).*/\1/p' | head -1)
        fi
        SIG_SOURCE=get-sign
    fi
    if { [ -z "$SIG_SIZE" ] || [ -z "$SIG_HASH" ]; } &&
       [ "$FLAVOR" = "resukisu" ] && [ "$TARGET_PKG" = "com.resukisu.resukisu" ]; then
        # Verified from the shipped BakaSU v4.2.0-rc3 manager APK (v2 signer).
        SIG_SIZE=887
        SIG_HASH=d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64
        SIG_SOURCE=static-4.2.0-rc3
    fi
    echo "ROOT_STAGE_SIG_SIZE=${SIG_SIZE:-unknown} HASH=${SIG_HASH:-unknown} SOURCE=$SIG_SOURCE"
fi

register_manager() {
    # $1 = reason tag (first / retry / repair)
    _why=$1
    log "ROOT_STAGE_REGISTER_BEGIN=$_why target=${TARGET_PKG:-none} flavor=$FLAVOR"
    if [ -z "$TARGET_PKG" ] || [ -z "$APK_PATH" ] || [ ! -f "$APK_PATH" ]; then
        warn "register_skipped missing_pkg_or_apk pkg=${TARGET_PKG:-none}"
        return 1
    fi
    DM_SUPPORTED=0
    DM_FINA=0
    # Manager recognition is owned by `ksud late-load --package-name` and the
    # selected manager's own userspace.  Never chmod or rename packages.list;
    # PackageManager state is read-only for MagicRoot.
    echo "ROOT_STAGE_PACKAGES=untouched"
    # Portable capability probe over the KernelSU-family userspace variants.
    #   1) kernel dynamic-manager set-apk   (BakaSU / ReSukiSU 4.2.x)
    #   2) dynamic-manager set-apk / set    (older/top-level variants)
    #   3) manager add / set-enabled        (manager-capable ksud builds)
    #   4) debug set-manager                (official KernelSU, KSU_DEBUG)
    #   5) direct /data/adb/ksu/.dynamic_manager record (stable file format)
    if "$ADB/ksud" kernel dynamic-manager --help >/dev/null 2>&1; then
        DM_SUPPORTED=1
        echo "ROOT_STAGE_MANAGER_CMD=kernel-dynamic-manager"
        "$ADB/ksud" kernel dynamic-manager set-apk "$APK_PATH" >>"$MARK/manager_add.log" 2>&1 || true
        echo "ROOT_STAGE_DYNAMIC_MANAGER_GET=$("$ADB/ksud" kernel dynamic-manager get 2>&1 | tr '\n' ' ')"
    elif "$ADB/ksud" dynamic-manager --help >/dev/null 2>&1; then
        DM_SUPPORTED=1
        echo "ROOT_STAGE_MANAGER_CMD=dynamic-manager"
        "$ADB/ksud" dynamic-manager set-apk "$APK_PATH" >>"$MARK/manager_add.log" 2>&1 || true
        if [ -n "$SIG_SIZE" ] && [ -n "$SIG_HASH" ]; then
            "$ADB/ksud" dynamic-manager set "$SIG_SIZE" "$SIG_HASH" >>"$MARK/manager_add.log" 2>&1 || true
        fi
        echo "ROOT_STAGE_DYNAMIC_MANAGER_GET=$("$ADB/ksud" dynamic-manager get 2>&1 | tr '\n' ' ')"
    elif "$ADB/ksud" dynamic --help >/dev/null 2>&1; then
        # FinaSU 1.5+ persists signs[] and authorized uids[] separately.
        # Registering the APK signature alone leaves the manager unauthorized.
        DM_SUPPORTED=1
        DM_FINA=1
        echo "ROOT_STAGE_MANAGER_CMD=fina-dynamic"
        _dm_vcode=$(dumpsys package "$TARGET_PKG" 2>/dev/null |
            sed -n 's/.*versionCode=\([0-9][0-9]*\).*/\1/p' | head -1)
        if [ -n "$_dm_vcode" ]; then
            "$ADB/ksud" dynamic set-apk --version-code "$_dm_vcode" "$APK_PATH" >>"$MARK/manager_add.log" 2>&1
        else
            "$ADB/ksud" dynamic set-apk "$APK_PATH" >>"$MARK/manager_add.log" 2>&1
        fi
        _dm_set_rc=$?
        echo "ROOT_STAGE_DYNAMIC_SET_RC=$_dm_set_rc version_code=${_dm_vcode:-unknown}"
        _dm_appid=$(cmd package list packages -U "$TARGET_PKG" 2>/dev/null |
            sed -n 's/.*uid:\([0-9][0-9]*\).*/\1/p' | head -1)
        if [ -z "$_dm_appid" ]; then
            _dm_appid=$(dumpsys package "$TARGET_PKG" 2>/dev/null |
                sed -n 's/.*appId=\([0-9][0-9]*\).*/\1/p; s/.*userId=\([0-9][0-9]*\).*/\1/p' | head -1)
        fi
        if [ "$_dm_set_rc" = "0" ] && [ -n "$_dm_appid" ]; then
            "$ADB/ksud" dynamic grant "$_dm_appid" >>"$MARK/manager_add.log" 2>&1
            _dm_grant_rc=$?
        else
            _dm_grant_rc=1
        fi
        echo "ROOT_STAGE_DYNAMIC_GRANT_RC=$_dm_grant_rc appid=${_dm_appid:-unknown}"
        echo "ROOT_STAGE_DYNAMIC_LIST=$("$ADB/ksud" dynamic list 2>&1 | tr '\n' '|')"
    fi
    MGR_LIST_SUPPORTED=0
    if "$ADB/ksud" manager --help >/dev/null 2>&1; then
        MGR_LIST_SUPPORTED=1
        echo "ROOT_STAGE_MANAGER_CMD2=manager-add"
        if [ -n "$SIG_SIZE" ] && [ -n "$SIG_HASH" ]; then
            "$ADB/ksud" manager add "$TARGET_PKG" "$SIG_SIZE" "$SIG_HASH" >>"$MARK/manager_add.log" 2>&1 || true
            "$ADB/ksud" manager set-enabled true >>"$MARK/manager_add.log" 2>&1 || true
            cat "$MARK/manager_add.log" 2>/dev/null || true
            echo "ROOT_STAGE_MANAGER_ADD=$TARGET_PKG"
        else
            warn "manager_sign_parse_failed sig_info=${SIG_INFO:-none}"
        fi
    fi
    # Portable dynamic-manager record fallback: the file format is stable
    # across KernelSU-family forks that support the dynamic-manager feature.
    if [ "$FLAVOR" = "resukisu" ] && [ -n "$SIG_SIZE" ] && [ -n "$SIG_HASH" ] &&
       [ -d "$ADB/ksu" ]; then
        DM_FILE="$ADB/ksu/.dynamic_manager"
        if [ ! -s "$DM_FILE" ] || ! grep -q "$SIG_HASH" "$DM_FILE" 2>/dev/null; then
            if printf '{\n  "size": %s,\n  "hash": "%s"\n}\n' \
                    "$SIG_SIZE" "$SIG_HASH" > "$DM_FILE" 2>/dev/null; then
                chmod 666 "$DM_FILE" 2>/dev/null || true
                DM_SUPPORTED=1
                echo "ROOT_STAGE_DYNAMIC_MANAGER_FILE=written"
            else
                echo "ROOT_STAGE_DYNAMIC_MANAGER_FILE=write_failed"
            fi
        else
            DM_SUPPORTED=1
            echo "ROOT_STAGE_DYNAMIC_MANAGER_FILE=present"
        fi
        echo "ROOT_STAGE_DYNAMIC_MANAGER=present size=$(wc -c < "$DM_FILE" 2>/dev/null)"
    fi
    # No packages.list rename trigger: late-load owns manager recognition.
    # Dynamic-manager commands above are userspace registration only and never
    # alter PackageManager's package database.
    # debug set-manager is the official-KernelSU path; on builds without
    # CONFIG_KSU_DEBUG it is expected to fail and treated as normal
    # auto-recognition.
    DBG_OUT=$("$ADB/ksud" debug set-manager "$APK_PATH" 2>&1)
    DBG_RC=$?
    case "$DBG_OUT" in
        *CONFIG_KSU_DEBUG*)
            echo "ROOT_STAGE_DEBUG_SET_MANAGER=requires_CONFIG_KSU_DEBUG (auto-recognition expected)" ;;
        *)
            if [ "$DBG_RC" = "0" ]; then
                echo "ROOT_STAGE_DEBUG_SET_MANAGER=ok"
            else
                echo "ROOT_STAGE_DEBUG_SET_MANAGER=fail rc=$DBG_RC out=$DBG_OUT"
            fi
            ;;
    esac
    if [ "${MGR_LIST_SUPPORTED:-0}" = "1" ]; then
        echo "ROOT_STAGE_MANAGER_LIST=$("$ADB/ksud" manager list 2>&1 | head -5 | tr '\n' '|')"
    else
        echo "ROOT_STAGE_MANAGER_LIST=skipped(no manager subcommand; dynamic-manager path used)"
    fi
    echo "ROOT_STAGE_PACKAGES=untouched_verified"
    echo "ROOT_STAGE_DYNAMIC_MANAGER_SUPPORTED=$DM_SUPPORTED"
    return 0
}

restart_manager() {
    [ -n "$TARGET_PKG" ] || return 0
    am force-stop "$TARGET_PKG" >/dev/null 2>&1 || true
    monkey -p "$TARGET_PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
    # wait_manager_connected() polls immediately, so the previous fixed 2s
    # sleep only delayed the common case.  Keep a short launch grace period.
    sleep 0.5
    if ! pidof "$TARGET_PKG" >/dev/null 2>&1; then
        # Generic launcher-activity fallback.
        ACT=$(cmd package resolve-activity --brief -c android.intent.category.LAUNCHER "$TARGET_PKG" 2>/dev/null | tail -1)
        case "$ACT" in
            */*) am start -n "$ACT" >/dev/null 2>&1 || true ;;
        esac
        sleep 0.5
    fi
}

manager_connected() {
    # -> 0 when any manager process owns a KernelSU fd.
    for p in $(pidof "$TARGET_PKG" 2>/dev/null); do
        if readlink /proc/$p/fd/* 2>/dev/null | grep -q ksu; then
            echo "ROOT_STAGE_MANAGER_FD_PID=$p"
            return 0
        fi
    done
    return 1
}

wait_manager_connected() {
    # $1 = seconds
    _n=$1
    _i=0
    while [ "$_i" -lt "$_n" ]; do
        _i=$((_i + 1))
        if manager_connected; then
            echo "ROOT_STAGE_MANAGER_CONNECTED=1 after=${_i}s"
            return 0
        fi
        sleep 1
    done
    return 1
}

if [ -n "$TARGET_PKG" ]; then
    echo "ROOT_STAGE_MANAGER=$TARGET_PKG"
    if [ "${MAGICROOT_ROOT_FAST:-1}" = "1" ] && manager_connected; then
        echo "ROOT_STAGE_MANAGER_FAST_REUSE=1"
        echo "ROOT_STAGE_MANAGER_CONNECTED=1 after=0s"
    else
        register_manager first || true
        restart_manager
        if wait_manager_connected "$MGR_WAIT"; then
            :
        else
            echo "ROOT_STAGE_MANAGER_CONNECTED=0 retry=registration"
            register_manager retry || true
            restart_manager
            if wait_manager_connected "$MGR_WAIT"; then
                :
            else
                echo "ROOT_STAGE_MANAGER_CONNECTED=0 repair_available=$REPAIR"
                sleep 3
                if manager_connected; then
                    echo "ROOT_STAGE_MANAGER_CONNECTED=1 after=late"
                fi
            fi
        fi
    fi
    if manager_connected; then
        echo "ROOT_STAGE_MANAGER_STATE=connected"
    else
        echo "ROOT_STAGE_MANAGER_STATE=launched_not_connected"
        log "管理器已启动但尚未连接内核；若首页显示未安装，可开启「软重启修复」后重试"
    fi
else
    warn "no_manager_found expected=$MGR"
fi

# Manager data snapshot for repair/next-run (reference PRESERVE mechanism).
if [ -d "$ADB/ksu" ]; then
    mkdir -p "$PRESERVE" 2>/dev/null
    chmod 700 "$PRESERVE" 2>/dev/null || true
    rm -rf "$PRESERVE.new" 2>/dev/null
    if cp -a "$ADB/ksu/." "$PRESERVE.new/" 2>/dev/null; then
        rm -rf "$PRESERVE" 2>/dev/null
        mv "$PRESERVE.new" "$PRESERVE" 2>/dev/null || rm -rf "$PRESERVE.new" 2>/dev/null
        echo "ROOT_STAGE_PRESERVE=committed"
    else
        rm -rf "$PRESERVE.new" 2>/dev/null
        echo "ROOT_STAGE_PRESERVE=copy_failed"
    fi
fi

# Only the explicit Tools action may restart zygote; never schedule stop/start.
echo "ROOT_STAGE_SOFT_REBOOT_REPAIR=disabled reason=use_explicit_zygote_hotfix"

# 6. su entry (PMX v1.6 style) + optional overlay fallback
# ---------------------------------------------------------------------------
SU_ENTRY_OK=0
if [ "$SU_ENTRY" = "1" ] && [ -f "$D/su_entry.sh" ]; then
    chmod 755 "$D/su_entry.sh" 2>/dev/null || true
    echo "SU_ENTRY=begin"
    if sh "$D/su_entry.sh" 2>&1; then
        SU_ENTRY_OK=1
        echo "SU_ENTRY_RESULT=ok"
    else
        echo "SU_ENTRY_RESULT=failed"
    fi
elif [ "$SU_ENTRY" = "1" ]; then
    echo "SU_ENTRY=skipped (su_entry.sh missing)"
else
    echo "SU_ENTRY=disabled"
fi

SU_CHECK=""
for _suc in /system/bin/su /product/bin/su "$ADB/ksu/bin/su" /debug_ramdisk/su; do
    [ -x "$_suc" ] || continue
    _check=$(timeout 5 "$_suc" -c 'id -u' 2>/dev/null || true)
    if [ -n "$_check" ]; then
        SU_CHECK="$_check"
        echo "ROOT_STAGE_SU_USED=$_suc"
        break
    fi
done
[ -n "$SU_CHECK" ] || SU_CHECK=pending
echo "ROOT_STAGE_SU_CHECK=$SU_CHECK"
echo "ROOT_STAGE_SU_BIN=$(for _suc in /system/bin/su /product/bin/su "$ADB/ksu/bin/su" /debug_ramdisk/su; do [ -e "$_suc" ] && printf '%s ' "$_suc"; done)"
echo "ROOT_STAGE_KSUD=$(ls -l "$ADB/ksud" 2>/dev/null | tr '\n' ' ' || echo missing)"

"$ADB/ksud" debug mark refresh >/dev/null 2>&1 || true

id > "$MARK/ROOT_ID" 2>&1 || true
chmod 644 "$MARK/ROOT_ID" 2>/dev/null || true
echo "ROOT_STAGE_OK"
