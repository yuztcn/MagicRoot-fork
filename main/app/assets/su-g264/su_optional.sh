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
# upper 里放 su_forward。CGA late-load 模块**没有 sucompat**，所以 su_forward
# 是 su_lkm：它自己走 KSU_IOCTL_GRANT_ROOT，不经过 /system/bin/su。
#
# Termux 的 su 是脚本，只按固定列表探测绝对路径（/system/bin/su 等），
# /system_ext/bin 不在列表里，所以挂好了它也会报 "No su program found"。
# 因此 enable 成功后要同步改 Termux wrapper 的 `for p in` 列表，并把正在运行的
# Termux 进程一起 setns，避免它因为 namespace 太旧而看不到挂载。
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
TERMUX_SU=/data/data/com.termux/files/usr/bin/su
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
        # 正在运行的 Termux 不会继承之后挂进 zygote namespace 的 overlay，
        # 这里直接进它的 namespace 挂一次；没运行就只影响后续新进程。
        pidof com.termux 2>/dev/null || true
        pidof 'com.termux:terminal' 2>/dev/null || true
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

# Termux 的 su 是脚本，按固定绝对路径列表探测，不搜索 PATH。
# 只把 /system_ext/bin/su 挂上还不够，必须把它写进这个列表。
termux_su_patch() {
    _tgt="${1:-/system_ext/bin}"
    _ts="$TERMUX_SU"
    if [ ! -f "$_ts" ]; then
        echo "SU_OPTIONAL_TERMUX=absent"
        return 0
    fi
    _line=$(grep -m1 '^for p in ' "$_ts" 2>/dev/null || true)
    if [ -z "$_line" ]; then
        # 不是标准 termux-tools su 脚本，不乱改。
        echo "SU_OPTIONAL_TERMUX=unsupported reason=no_search_list"
        return 0
    fi
    _want="$_tgt/su"
    [ "$_tgt" = "/system_ext/bin" ] || _want="$_want /system_ext/bin/su"
    _want="$_want /data/adb/ksu/bin/su /data/local/tmp/magic/su"
    _orig=${_line#for p in }
    _new=""
    for _p in $_want $_orig; do
        case " $_new " in
            *" $_p "*) ;;
            *) _new="$_new $_p" ;;
        esac
    done
    _new=${_new# }
    if [ "$_line" = "for p in $_new" ]; then
        echo "SU_OPTIONAL_TERMUX=already target=$_tgt"
        return 0
    fi
    [ -f "$_ts.magicroot.bak" ] || cp -p "$_ts" "$_ts.magicroot.bak" 2>/dev/null || true
    if ! awk -v repl="for p in $_new" '/^for p in / { print repl; next } { print }' \
            "$_ts" > "$_ts.magicroot.tmp" 2>/dev/null; then
        rm -f "$_ts.magicroot.tmp"
        echo "SU_OPTIONAL_TERMUX=failed reason=rewrite target=$_tgt"
        return 0
    fi
    # 用 cat 写回原 inode，保留 Termux 自己的属主/权限；mv 会变成 root:root。
    if [ -s "$_ts.magicroot.tmp" ] && cat "$_ts.magicroot.tmp" > "$_ts" 2>/dev/null; then
        rm -f "$_ts.magicroot.tmp"
        echo "SU_OPTIONAL_TERMUX=patched target=$_tgt"
        echo "SU_OPTIONAL_TERMUX_LINE=$(grep -m1 '^for p in ' "$_ts" 2>/dev/null)"
    else
        rm -f "$_ts.magicroot.tmp"
        echo "SU_OPTIONAL_TERMUX=failed reason=write target=$_tgt"
    fi
    return 0
}

enable_one() {
    mode="$1"; target="$2"
    ok=0
    zygote_seen=0
    zygote_ok=0
    zygote_pids=$( { pidof zygote64 2>/dev/null || true; pidof zygote 2>/dev/null || true; } | tr '\n' ' ')
    for pid in $(all_pids); do
        # 只有真正的 zygote 才能证明“新 App 会看到挂载”；Termux 自己的
        # namespace 挂载成功不算，否则 zygote 挂失败也会被误判为成功。
        case " $zygote_pids " in *" $pid "*) zygote_seen=1 ;; esac
        case "$mode" in
            bind)
                if mount_ns "$pid" bind "$WRAPPER" "$target"; then
                    ok=1
                    case " $zygote_pids " in *" $pid "*) zygote_ok=1 ;; esac
                    echo "SU_OPTIONAL_MOUNT=bind pid=$pid target=$target"
                    echo "$pid|bind|$target|" >> "$STATE"
                fi
                ;;
            overlay)
                odir="$BASE/overlay/$pid"
                if mount_ns "$pid" overlay-tmpfs "$odir" "$target" "$target" "$WRAPPER"; then
                    ok=1
                    case " $zygote_pids " in *" $pid "*) zygote_ok=1 ;; esac
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

    if [ "${NO_SUCOMPAT:-0}" = "1" ]; then
        timeout 15 "$KSUD" feature set su_compat 0 >/dev/null 2>&1 || true
    else
        timeout 15 "$KSUD" feature set su_compat 1 >/dev/null 2>&1 || true
    fi
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
        termux_su_patch /system_ext/bin
        echo "SU_OPTIONAL_OK"
        echo "SU_OPTIONAL_NOTE=restart apps to enter the updated zygote mount namespace"
        return 0
    fi
    echo "SU_OPTIONAL_WARN=system_ext_bin_overlay_failed"

    for target in /system/xbin /vendor/bin; do
        [ -d "$target" ] && [ ! -L "$target" ] || continue
        if enable_one overlay "$target"; then
            echo "SU_OPTIONAL_MODE=overlay-$target-tmpfs"
            termux_su_patch "$target"
            echo "SU_OPTIONAL_OK"
            echo "SU_OPTIONAL_NOTE=restart apps to enter the updated zygote mount namespace"
            return 0
        fi
    done

    # 没有可挂载目标时，仍让 Termux 至少能找到 /data/adb/ksu/bin/su（su_lkm）。
    # 该路径不依赖 namespace，能否 exec 取决于 SELinux；失败信息比
    # "No su program found" 更有诊断价值。
    termux_su_patch /system_ext/bin
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
