#!/system/bin/sh
# 清理本项目自己的运行残留，恢复到部署资产前的临时状态。
# 注意：/data/adb 下的 KernelSU 本体不在这里卸载；只清理 MagicRoot 自己的文件。
D=/data/local/tmp/magic
EXT_STAGE=/storage/emulated/0/Android/data/com.aoki.magicroot/files/stage
UID_NOW=$(id -u 2>/dev/null || echo 1)

echo "== 清理残留进程 =="
pkill -9 -f '[t]64560' 2>/dev/null
pkill -9 -f '[c]red_target' 2>/dev/null
pkill -9 -f '[v]ictim-child' 2>/dev/null
pkill -9 -f '[k]su_grant' 2>/dev/null
pkill -9 -f '[k]o_patch' 2>/dev/null
pkill -9 -f '[k]aslr_slide' 2>/dev/null
pkill -9 -f '[r]oot_stage' 2>/dev/null
pkill -9 -f '[s]u_optional' 2>/dev/null
pkill -9 -f "$D/run.sh" 2>/dev/null
sleep 1

# ---------------------------------------------------------------------------
# CVE-2026-98260 second chain (opt-in, experimental).  Only runs when a 98260
# deployment / parked marker exists; only affects this chain and only removes
# files whose sha256 matches our manifest.  The live rootd is deliberately
# kept (killing it can reboot the phone).  It must only run from the explicit clean action.
# The same-boot PARKED guard marker is preserved (see $D/.98260-parked below).
# ---------------------------------------------------------------------------
if [ -d "$D/98260" ] || [ -d "$D/98260-6138" ] || [ -f "$D/.98260-parked" ] || [ -f /data/local/tmp/.magicroot-98260-parked ] \
        || [ -S /data/local/tmp/pc98260-root.sock ] || [ -S /data/local/tmp/pc98260-root2.sock ] \
        || pidof exploit-android-key-ptr >/dev/null 2>&1 \
        || pidof cve98260_plant >/dev/null 2>&1 \
        || ps -A 2>/dev/null | grep -q '[e]xploit-android'; then
    echo "== 清理 98260 链 =="
    # P0: if a PARKED marker matches the CURRENT boot, the kernel may still hold a
    # dangling timer node. Killing the deliberately-parked process would let init
    # reap it -> timerqueue UAF -> panic (PANIC_ON_OOPS=1).  Refuse to touch the
    # process/socket; only a phone restart clears this state.
    _98260_park_same=0
    _98260_cur_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)
    for _98260_pf in /data/local/tmp/.magicroot-98260-parked "$D/.98260-parked"; do
        if [ -f "$_98260_pf" ]; then
            _98260_pb=$(cat "$_98260_pf" 2>/dev/null || true)
            if [ -n "${_98260_pb:-}" ] && [ "$_98260_pb" = "${_98260_cur_boot:-}" ]; then
                _98260_park_same=1
            fi
        fi
    done
    if [ "$_98260_park_same" = "1" ]; then
        echo "CLEAN_98260_REFUSED=parked_state_restart_required"
        echo "HINT_98260=do NOT kill or reap the parked exploit/rootd process; restart the phone, then clean."
    else
    # Upstream-style cleanup: end the plant only after a normal su works.
    # If it was already cleaned by the automatic handoff, report success too.
    _98260_rootd_cleaned=0
    _98260_rootd_proc=0
    pidof exploit-android-key-ptr >/dev/null 2>&1 && _98260_rootd_proc=1
    ps -A 2>/dev/null | grep -q '[e]xploit-android' && _98260_rootd_proc=1
    if [ "$_98260_rootd_proc" = "1" ]; then
        _98260_su=""
        if command -v su >/dev/null 2>&1; then _98260_su=su
        elif [ -x /data/adb/ksu/bin/su ]; then _98260_su=/data/adb/ksu/bin/su
        fi
        _98260_uid=""
        [ -n "$_98260_su" ] && _98260_uid=$("$_98260_su" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
        if [ "$_98260_uid" = "0" ]; then
            # Do not SIGKILL the exploit parent: last_kmsg shows init reaping a
            # timer-UAF zombie when the parent dies (rb_next/posix_cpu_timers_exit).
            # Stop the service by unlinking its socket and keep the process parked.
            #
            # u:r:ksu:s0 / u:r:shell:s0 cannot unlink a live rootd socket on this
            # SELinux policy.  The rootd child itself runs with the exploit's
            # system_server-ish context and can unlink it; use pc98260-su first.
            _98260_rootd_su="$D/pc98260-su"
            if [ -x "$_98260_rootd_su" ] && [ -S /data/local/tmp/pc98260-root.sock ]; then
                echo "CLEAN_98260_ROOTD_SU=pc98260-su"
                timeout 5 "$_98260_rootd_su" -c "rm -f /data/local/tmp/pc98260-root.sock /data/local/tmp/pc98260-root2.sock" 2>/dev/null || true
            fi
            "$_98260_su" -c "rm -f /data/local/tmp/pc98260-root.sock /data/local/tmp/pc98260-root2.sock" 2>/dev/null || true
            if [ ! -S /data/local/tmp/pc98260-root.sock ] && [ ! -S /data/local/tmp/pc98260-root2.sock ]; then
                echo "CLEAN_98260_ROOTD_SOFT_CLEANED=1 reason=zombie_reap_panic"
            else
                echo "CLEAN_98260_ROOTD_SOCKET_KEPT=1 reason=remove_denied"
            fi
        else
            echo "CLEAN_98260_KEPT=rootd_active reason=no_working_su uid=${_98260_uid:-unknown}"
        fi
    else
        if [ -S /data/local/tmp/pc98260-root.sock ] || [ -S /data/local/tmp/pc98260-root2.sock ]; then
            rm -f /data/local/tmp/pc98260-root.sock /data/local/tmp/pc98260-root2.sock 2>/dev/null || true
            if [ -S /data/local/tmp/pc98260-root.sock ] || [ -S /data/local/tmp/pc98260-root2.sock ]; then
                _98260_su=""
                if command -v su >/dev/null 2>&1; then _98260_su=su
                elif [ -x /data/adb/ksu/bin/su ]; then _98260_su=/data/adb/ksu/bin/su
                fi
                _98260_ruid=""
                [ -n "$_98260_su" ] && _98260_ruid=$("$_98260_su" -c 'id -u' 2>/dev/null | tr -d ' \r\n')
                [ "$_98260_ruid" = "0" ] && "$_98260_su" -c "rm -f /data/local/tmp/pc98260-root.sock /data/local/tmp/pc98260-root2.sock" 2>/dev/null || true
            fi
            if [ ! -S /data/local/tmp/pc98260-root.sock ] && [ ! -S /data/local/tmp/pc98260-root2.sock ]; then
                _98260_rootd_cleaned=1
                echo "CLEAN_98260_STALE_SOCKETS_REMOVED=1"
            else
                echo "CLEAN_98260_STALE_SOCKETS_KEPT=1 reason=remove_denied"
            fi
        else
            echo "CLEAN_98260_ROOTD_ALREADY_CLEANED=1"
            _98260_rootd_cleaned=1
        fi
    fi
    _98260_sums="$D/98260/SHA256SUMS.txt $D/98260-6138/SHA256SUMS.txt"
    for _98260_n in exploit-android-perf exploit-android-perf-chain exploit-android-key-ptr pc98260-su; do
        _98260_f="/data/local/tmp/$_98260_n"
        _98260_want=""
        for _98260_sum in $_98260_sums; do
            [ -f "$_98260_sum" ] || continue
            _98260_want=$(awk -v n="$_98260_n" '$2 == n {print $1}' "$_98260_sum" 2>/dev/null | head -1)
            [ -n "${_98260_want:-}" ] && break
        done
        if [ -f "$_98260_f" ] && [ -n "$_98260_want" ] && command -v sha256sum >/dev/null 2>&1; then
            _98260_got=$(sha256sum "$_98260_f" 2>/dev/null | awk '{print $1}')
            if [ "$_98260_got" = "$_98260_want" ]; then
                rm -f "$_98260_f"
                echo "CLEAN_98260_REMOVED=$_98260_f"
            else
                echo "CLEAN_98260_KEPT=$_98260_f reason=hash_mismatch"
            fi
        elif [ -f "$_98260_f" ]; then
            echo "CLEAN_98260_KEPT=$_98260_f reason=no_manifest_or_sha256sum"
        fi
    done
    # Preserve the same-boot PARKED guard even though $D is removed below.
    if [ -f "$D/.98260-parked" ]; then
        _98260_pm=$(cat "$D/.98260-parked" 2>/dev/null || true)
        if [ -n "${_98260_pm:-}" ]; then
            printf '%s\n' "$_98260_pm" > /data/local/tmp/.magicroot-98260-parked 2>/dev/null || true
        fi
    fi
    if [ "${MAGICROOT_KEEP_ROOTD:-0}" = "1" ] || [ -f "$D/.keep-rootd-user" ] \
            || [ -f "$D/.h1c-rootd-only" ]; then
        echo "CLEAN_H1C_SOCKET_KEPT=user_keep_or_rootd_only"
    else
        for _h1c_sock in /data/local/tmp/cve98260-h1c-*.sock; do
            [ -S "$_h1c_sock" ] || continue
            rm -f "$_h1c_sock" 2>/dev/null || true
            if [ -S "$_h1c_sock" ]; then
                echo "CLEAN_H1C_SOCKET_KEPT=$_h1c_sock reason=remove_denied"
            else
                echo "CLEAN_H1C_SOCKET_REMOVED=$_h1c_sock"
            fi
        done
    fi
    rm -rf "$D/98260" "$D/98260-6138" "$D/98260-h1c"
    echo "CLEAN_98260=ok rootd_cleaned=$_98260_rootd_cleaned rootd_soft_cleaned=1"
    echo "CLEAN_98260_KEPT=/data/local/tmp/.magicroot-98260-parked (same-boot retry guard; restart the phone to clear)"
    fi
fi

echo "== 删除本项目工作目录与外部 stage 缓存 =="
# Legacy cleanup: dev su was removed.  Remove /dev/su only if an older
# build created it (marker) or it is an identical ksud copy (wild fallback).
if [ -f "$D/dev-su-created" ]; then
    rm -f /dev/su
    echo "DEV_SU_REMOVED=/dev/su"
elif [ -f /dev/su ] && [ -f /data/adb/ksud ] && cmp -s /dev/su /data/adb/ksud; then
    rm -f /dev/su
    echo "DEV_SU_REMOVED=/dev/su"
fi
rm -rf "$D"
rm -rf "$EXT_STAGE"

sync
echo "CLEAN_OK"
echo "CLEAN_SCOPE=magicroot-work-and-stage"
echo "CLEAN_KEPT=/data/adb KernelSU;/sdcard/Download/MagicRoot failure logs"
