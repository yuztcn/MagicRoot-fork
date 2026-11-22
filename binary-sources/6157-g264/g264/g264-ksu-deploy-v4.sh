#!/system/bin/sh
# ============================================================================
# g264-ksu-deploy-v3.sh — GT-2（AMG-AN00 / g264）装载现编的 g264 KSU 模块
#
# 与 v2 的区别：
#   - 先核对 boot_id 和 _text，手机重启过/换过开机就拒绝安装（防止装错炸机）；
#   - 自动在 /data/local/tmp 和 /sdcard/Download/QQ 找 ko，并校验 sha256；
#   - 日志写到 /data/local/tmp，不依赖 /sdcard 目录权限；
#   - 管理器包名自动探测，不再写死。
#
# 用法（aShell You + Shizuku，uid=2000）：
#   sh g264-ksu-deploy-v3.sh [ko 路径]
# 不给路径时自动找。
#
# 本次模块按：boot 1f6a5d6b-4217-4909-a75e-176cb078cfb7
#             slide 0x23c1200000   （_text=0xffffffe3c9200000）
# 编译；换开机必须重编，脚本会拦住。
# ============================================================================
set -u

D=/data/local/tmp/magic
SU=$D/98260-g264/pc98260-su
SOCK=/data/local/tmp/pc98260-root.sock

EXPECT_BOOT=${EXPECT_BOOT:-1f6a5d6b-4217-4909-a75e-176cb078cfb7}
EXPECT_TEXT=${EXPECT_TEXT:-0xffffffe3c9200000}
EXPECT_SHA=${EXPECT_SHA:-e3b590c388c87e0f0ea082b7d16ce35079d5c6836fd1f4db81cd0bf5258a6846}
KO=${1:-}
MOD=kernelsu
LOG=/data/local/tmp/g264-ksu-deploy-$(date +%m%d-%H%M%S 2>/dev/null).log

{
echo "=== g264 ksu deploy v3 start $(date 2>/dev/null) ==="
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)"
echo "expect_boot=$EXPECT_BOOT"
echo "expect_text=$EXPECT_TEXT"
echo "expect_sha=$EXPECT_SHA"

_uid=$(id -u 2>/dev/null)
echo "uid=$_uid"
if [ "$_uid" != "2000" ]; then
    echo "FAIL: 当前终端不是 shell（uid=$_uid）。请用 aShell You + Shizuku，看到 uid=2000 再跑。"
    exit 2
fi

_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if [ "$_boot" != "$EXPECT_BOOT" ]; then
    echo "FAIL: 手机重启过了。当前 boot=$_boot"
    echo "      模块是按 $EXPECT_BOOT 编的，装不上/会卡死。"
    echo "      不要 insmod；重新跑 g264-rootonly，把新的 ROOTONLY_TEXT 发群里。"
    exit 2
fi

[ -x "$SU" ] || { echo "FAIL: $SU 不可执行，先在 MagicRoot 里点「部署资产」"; exit 2; }
[ -S "$SOCK" ] || { echo "FAIL: rootd socket 不存在，先跑 g264-rootonly"; exit 2; }

_id=$("$SU" -c 'id -u' 2>/dev/null | tr -d '\r\n ')
[ "$_id" = "0" ] || { echo "FAIL: rootd 不是 uid=0（当前 $_id）"; exit 2; }

_text=$("$SU" -c 'grep -w _text /proc/kallsyms' 2>/dev/null | awk '{print $1; exit}')
echo "_text=$_text"
if [ "0x$_text" != "$EXPECT_TEXT" ]; then
    echo "FAIL: _text 不是 $EXPECT_TEXT。这台的 slide 变了，模块不能用。"
    echo "      不要 insmod；把上面 _text 发群里。"
    exit 2
fi
echo "BOOT_CHECK=ok"

# ---- 找 ko ----
if [ -z "$KO" ]; then
    for f in /data/local/tmp/ksm-g264.ko \
             /sdcard/Download/QQ/ksm-g264-0x23c1200000.ko \
             /sdcard/Download/ksm-g264-0x23c1200000.ko \
             /sdcard/Download/QQ/ksm-g264.ko; do
        [ -f "$f" ] && { KO=$f; break; }
    done
fi
if [ -z "$KO" ] || [ ! -f "$KO" ]; then
    echo "FAIL: 找不到 ksm-g264.ko。把模块下载到 /sdcard/Download/QQ/ 或 /data/local/tmp/。"
    exit 2
fi
echo "ko_source=$KO"

# /sdcard 下的文件先复制到 /data/local/tmp，insmod 从本地读
case "$KO" in
    /sdcard/*)
        echo "--- 复制到 /data/local/tmp/ksm-g264.ko ---"
        cp -f "$KO" /data/local/tmp/ksm-g264.ko || { echo "FAIL: 复制失败"; exit 2; }
        KO=/data/local/tmp/ksm-g264.ko
        ;;
esac
ls -l "$KO"
_sha=$(sha256sum "$KO" 2>/dev/null | awk '{print $1}')
echo "sha256=$_sha"
if [ -n "$_sha" ] && [ "$_sha" != "$EXPECT_SHA" ]; then
    echo "FAIL: 文件 sha256 不对（下载损坏），重下 ksm-g264-0x23c1200000.ko。"
    exit 2
fi

# ---- 管理器包名 ----
MGR=""
for c in me.weishu.kernelsu com.resukisu.resukisu com.rifsxd.ksunext \
         com.sukisu.ultra com.derrosu.kernelsu me.bmax.apatch; do
    if pm list packages 2>/dev/null | grep -qx "package:$c"; then MGR=$c; break; fi
done
echo "manager=${MGR:-none}"

# ---- 0) 停管理器，释放 ksu_driver fd ----
echo "--- 停管理器 ---"
if [ -n "$MGR" ]; then am force-stop "$MGR" 2>/dev/null; fi
sleep 3

# ---- 1) 卸载旧模块 ----
echo "--- 卸载旧模块 ---"
for m in "$MOD" ksm kst ksl ksk ksj ksi ksh ksg ksf kse ksd ksc ksb ksa; do
    _c=$("$SU" -c "grep -cE '^$m ' /proc/modules" 2>/dev/null | tr -d '\r\n ')
    case "$_c" in ''|0) continue ;; esac
    echo "  rmmod $m"
    "$SU" -c "rmmod $m" 2>&1
    sleep 3
done

# ---- 2) /data/adb 权限 ----
echo "--- 修 /data/adb 权限 ---"
"$SU" -c 'chmod 755 /data/adb /data/adb/ksu /data/adb/ksu/bin 2>/dev/null; chmod 755 /data/adb/ksud 2>/dev/null; chmod 755 /data/adb/ksu/bin/* 2>/dev/null' 2>&1

# ---- 3) 关 panic_on_oops / warn ----
"$SU" -c 'echo 0 > /proc/sys/kernel/panic_on_oops; echo 0 > /proc/sys/kernel/panic_on_warn' 2>&1

# ---- 4) insmod ----
echo "--- insmod $KO allow_shell=1 ---"
_before=$("$SU" -c 'cut -d" " -f1 /proc/uptime' 2>/dev/null | tr -d '\r\n ')
"$SU" -c "insmod $KO allow_shell=1" 2>&1
_rc=$?
sleep 2
# 注意：模块一加载，SELinux 可能回到 Enforcing，rootd 会被切断；
# 所以这里必须用 shell 直接读 /proc/modules，不能再经 su。
_mods=$(grep -w "$MOD" /proc/modules 2>/dev/null)
echo "insmod_rc=$_rc uptime_before=$_before"
if [ -n "$_mods" ]; then
    echo "LOADED=1 $_mods"
    echo "NOTE: rootd 若已断开是正常现象（SELinux 恢复强制），不影响模块。"
else
    echo "LOADED=0"
    echo "--- dmesg 失败原因 ---"
    dmesg 2>/dev/null | grep -iE 'kernelsu|overflow|Invalid ELF|Unknown symbol|no symbol version|disagrees|exec format|kprobe failed|CFI' | tail -20
    "$SU" -c "dmesg | grep -iE 'kernelsu|overflow|Invalid ELF|Unknown symbol|no symbol version|disagrees|exec format|kprobe failed|CFI' | tail -20" 2>&1
    echo "DEPLOY_OK=0"
    exit 4
fi

# ---- 5) 验证 kprobe / 参数 ----
echo "--- kprobe / 参数 ---"
ls /sys/module/$MOD/parameters 2>/dev/null
_dm=$(dmesg 2>/dev/null | grep -iE 'kprobe registered|shell is allowed|kprobe failed|MANAGER-INSTALL|KernelSU' | tail -15)
if [ -z "$_dm" ]; then
    _dm=$("$SU" -c "dmesg | grep -iE 'kprobe registered|shell is allowed|kprobe failed|MANAGER-INSTALL|KernelSU' | tail -15" 2>/dev/null)
fi
printf '%s\n' "${_dm:-（dmesg 读不到，跳过）}"

# ---- 6) 重启管理器 ----
echo "--- 重启管理器 ---"
if [ -n "$MGR" ]; then
    am force-stop "$MGR" 2>/dev/null
    sleep 2
    monkey -p "$MGR" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
    sleep 12
    echo "--- MANAGER-INSTALL ---"
    _mi=$(dmesg 2>/dev/null | grep -iE 'MANAGER-INSTALL' | tail -6)
    if [ -z "$_mi" ]; then
        _mi=$("$SU" -c "dmesg | grep -iE 'MANAGER-INSTALL' | tail -6" 2>/dev/null)
    fi
    printf '%s\n' "${_mi:-（没有 MANAGER-INSTALL 记录）}"
    _pid=$(pidof "$MGR" 2>/dev/null | awk '{print $1}')
    echo "manager_pid=$_pid"
    if [ -n "$_pid" ]; then
        "$SU" -c "ls -l /proc/$_pid/fd 2>/dev/null | grep -i ksu" 2>&1
    fi
    echo "--- logcat KsuCli ---"
    logcat -d 2>/dev/null | grep -E 'KsuCli.*install result|not a shell|blocked by seccomp' | tail -6
else
    echo "NOTE: 没找到 KSU 管理器，只装了内核模块。"
fi

echo "DEPLOY_OK=1"
echo "=== g264 ksu deploy v3 end ==="
} 2>&1 | tee "$LOG"

echo
echo "LOG=$LOG"
