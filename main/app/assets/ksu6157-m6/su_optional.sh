#!/system/bin/sh
# su 兼容层（移植自 MagicRoot 1.0.3 的 su_optional.sh，适配 m6 的目录布局）
#
# 为什么不能简单 `su -M` + overlay：
#   1. `su -M` 挂的是全局 namespace；App 进程是从 zygote 的**私有** mount
#      namespace fork 出来的，看不到那个挂载 ⇒ 必须 setns 进每个 pid 再挂。
#   2. HONOR/高通 的 /data 是 case-insensitive-capable f2fs，overlayfs 拒绝把它
#      当 upperdir（EINVAL: "case-insensitive capable filesystem ... not supported"）
#      ⇒ upper/work 必须用 tmpfs。
#
# 做法：对 pid 1 和 zygote 逐个 setns，挂 tmpfs upper 的 overlay 到 /system_ext/bin，
# upper 里放 su_forward。su_forward 自己 exec /system/bin/su，让 KernelSU 的
# sucompat 钩子看到**原始路径** —— 直接往 /system/bin 放真 su 副本会绕过钩子，
# 而且部分 app 域直接 EACCES。
set -u
MODE="${1:-}"
D=/data/local/tmp/route/m6
ADB=/data/adb
NATIVE="$ADB/ksu/bin/su"
KSUD="$ADB/ksud"
BASE="$ADB/m6shell/su-wrapper"
WRAPPER="$BASE/bin/su"
STATE="$BASE/state"
HELPER="$D/su_overlay_helper"
PATH=/system/bin:/system/xbin:/system_ext/bin
export PATH

root_check() {
    [ "$(id -u 2>/dev/null || echo 1)" = "0" ] || {
        echo "SU_OPTIONAL_FAIL=not_root"
        exit 1
    }
}

mount_ns() {
    pid="$1"; shift
    [ -x "$HELPER" ] || return 1
    "$HELPER" "$pid" "$@"
}

all_pids() {
    {
        echo 1
        pidof zygote64 2>/dev/null || true
        pidof zygote 2>/dev/null || true
    } | awk 'NF && !seen[$1]++ { print $1 }'
}

write_wrapper() {
    mkdir -p "$BASE/bin" "$BASE/overlay" || return 1
    if [ -x "$D/su_forward" ]; then
        cp -f "$D/su_forward" "$WRAPPER" 2>/dev/null || true
    fi
    if [ ! -s "$WRAPPER" ]; then
        printf '%s\n' '#!/system/bin/sh' \
            'exec /system/bin/su "$@"' > "$WRAPPER" || return 1
    fi
    chmod 755 "$WRAPPER" "$BASE/bin" "$BASE" 2>/dev/null || true
    chown 0:0 "$WRAPPER" "$BASE/bin" "$BASE" 2>/dev/null || true
}

label_wrapper() {
    label=$(ls -Zd /system_ext/bin 2>/dev/null | awk '{print $1}')
    case "$label" in
        u:object_r:*:s0)
            chcon "$label" "$BASE" "$BASE/bin" "$WRAPPER" 2>/dev/null || true
            ;;
        *)
            echo "SU_OPTIONAL_WARN=no_system_label"
            ;;
    esac
    return 0
}

enable_one() {
    mode="$1"; target="$2"
    ok=0
    zygote_seen=0
    zygote_ok=0
    for pid in $(all_pids); do
        [ "$pid" = "1" ] || zygote_seen=1
        case "$mode" in
            bind)
                if mount_ns "$pid" bind "$WRAPPER" "$target"; then
                    ok=1
                    [ "$pid" = "1" ] || zygote_ok=1
                    echo "SU_OPTIONAL_MOUNT=bind pid=$pid target=$target"
                    echo "$pid|bind|$target|" >> "$STATE"
                fi
                ;;
            overlay)
                odir="$BASE/overlay/$pid"
                if mount_ns "$pid" overlay-tmpfs "$odir" "$target" "$target" "$WRAPPER"; then
                    ok=1
                    [ "$pid" = "1" ] || zygote_ok=1
                    echo "SU_OPTIONAL_MOUNT=overlay pid=$pid target=$target"
                    echo "$pid|overlay|$target|$odir" >> "$STATE"
                fi
                ;;
        esac
    done
    if [ "$zygote_seen" = "1" ]; then
        [ "$zygote_ok" = "1" ]
    else
        [ "$ok" = "1" ]
    fi
}

enable() {
    root_check
    [ -x "$NATIVE" ] || {
        echo "SU_OPTIONAL_FAIL=no_native_su"
        exit 3
    }
    [ -x "$KSUD" ] || {
        echo "SU_OPTIONAL_FAIL=no_ksud"
        exit 4
    }
    [ -x "$HELPER" ] || {
        echo "SU_OPTIONAL_FAIL=no_ns_helper"
        exit 5
    }

    disable >/dev/null 2>&1 || true
    rm -rf "$BASE"
    write_wrapper || {
        echo "SU_OPTIONAL_FAIL=write_wrapper"
        exit 6
    }
    label_wrapper || true
    : > "$STATE" || true

    timeout 15 "$KSUD" feature set su_compat 1 >/dev/null 2>&1 || true
    timeout 15 "$KSUD" debug mark refresh >/dev/null 2>&1 || true

    if enable_one overlay /system_ext/bin; then
        # ★ 2.56：挂上去之后**再**标一次标签。
        #   实测 overlay 挂载点本身会带上 u:object_r:tmpfs:s0（upper 是 /data 上的
        #   目录时尤甚），shell 域穿过这个目录去 exec 会被 SELinux 拒，
        #   现象就是 `su: can't execute: Permission denied`（EACCES，不是 ENOEXEC）。
        #   把挂载点根 + su 都标成 system_file，与只读 /system_ext/bin 保持一致。
        chcon u:object_r:system_file:s0 /system_ext/bin /system_ext/bin/su 2>/dev/null || true
        chcon u:object_r:system_file:s0 "$WRAPPER" "$BASE" "$BASE/bin" 2>/dev/null || true
        echo "SU_OPTIONAL_LABEL=$(ls -Zd /system_ext/bin 2>/dev/null | awk '{print $1}')/$(ls -Zd /system_ext/bin/su 2>/dev/null | awk '{print $1}')"
        echo "SU_OPTIONAL_MODE=overlay-system-ext-bin-tmpfs"
        echo "SU_OPTIONAL_OK"
        echo "SU_OPTIONAL_NOTE=restart apps to enter the updated zygote mount namespace"
        return 0
    fi
    echo "SU_OPTIONAL_WARN=system_ext_bin_overlay_failed"

    for target in /system/xbin /vendor/bin; do
        [ -d "$target" ] && [ ! -L "$target" ] || continue
        if enable_one overlay "$target"; then
            echo "SU_OPTIONAL_MODE=overlay-$target-tmpfs"
            echo "SU_OPTIONAL_OK"
            echo "SU_OPTIONAL_NOTE=restart apps to enter the updated zygote mount namespace"
            return 0
        fi
    done

    echo "SU_OPTIONAL_FAIL=no_mountable_target"
    exit 7
}

disable() {
    root_check
    if [ -f "$STATE" ]; then
        while IFS='|' read -r pid mode target root; do
            [ -n "${pid:-}" ] && [ -n "${target:-}" ] || continue
            mount_ns "$pid" umount "$target" "${root:-}" >/dev/null 2>&1 || true
            mount_ns 1 umount "$target" "${root:-}" >/dev/null 2>&1 || true
            echo "SU_OPTIONAL_UNMOUNT=$target"
        done < "$STATE"
    else
        for target in /system/bin /system/bin/su /system_ext/bin /system/xbin; do
            if awk -v t="$target" '$2 == t && ($1 == "m6shell-su" || index($1, "/m6shell/su-wrapper/") == 1) { found=1 } END { exit !found }' /proc/mounts 2>/dev/null; then
                mount_ns 1 umount "$target" >/dev/null 2>&1 || true
                mount_ns "$$" umount "$target" >/dev/null 2>&1 || true
                echo "SU_OPTIONAL_UNMOUNT=$target"
            fi
        done
    fi
    rm -rf "$BASE"
    if [ -x "$KSUD" ]; then
        timeout 15 "$KSUD" feature set su_compat 0 >/dev/null 2>&1 || true
    fi
    echo "SU_OPTIONAL_DISABLED"
}

case "$MODE" in
    enable) enable ;;
    disable) disable ;;
    *) echo "usage: $0 enable|disable"; exit 2 ;;
esac
