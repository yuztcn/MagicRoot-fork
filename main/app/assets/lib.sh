#!/system/bin/sh
# 公共变量与函数（被其它脚本 source）
TR=/sys/kernel/tracing
[ -d "$TR/events" ] || TR=/sys/kernel/debug/tracing
DIR=/data/local/tmp/magic
WORK="$DIR"

say() { echo "[m9] $*"; }
kv() { printf 'M9_%s=%s\n' "$1" "$2"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---- 98260 / 6157 共享辅助函数 --------------------------------------------
current_boot_id() {
    cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown
}

parked_mark() {
    _b=$(current_boot_id)
    _m=${PARKED_MARKER:-/data/local/tmp/.magicroot-98260-parked}
    if printf '%s\n' "$_b" > "$_m" 2>/dev/null && chmod 644 "$_m" 2>/dev/null; then
        echo "98260_PARKED=1 marker=$_m boot=$_b pid=$(pidof exploit-android-key-ptr 2>/dev/null)"
        return 0
    fi
    echo "98260_PARKED_WRITE_FAILED=1 marker=$_m boot=$_b"
    return 1
}

num_or() {
    case "$1" in
        ''|*[!0-9]*) echo "$2" ;;
        *) echo "$1" ;;
    esac
}

_susfs_loaded() {
    [ -d /sys/module/susfs_guard_lkm ] && return 0
    [ -e /proc/susfs_path ] && return 0
    grep -q '^susfs_guard_lkm ' /proc/modules 2>/dev/null
}

_susfs_wait_loaded() {
    _sw_i=0
    while [ "$_sw_i" -lt 20 ]; do
        _susfs_loaded && return 0
        sleep 0.25 2>/dev/null || sleep 1
        _sw_i=$((_sw_i + 1))
    done
    _susfs_loaded
}
