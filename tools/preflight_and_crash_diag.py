#!/usr/bin/env python3
"""Pre-chain safety: wait for the device to settle after boot (low load, enough
free memory) before running the risky SELinux-permissive race; record a crash
marker per stage; copy pstore from root_stage for future crash analysis."""
from __future__ import annotations

from pathlib import Path

WS = Path(__file__).resolve().parent.parent


def patch(path: Path, pairs):
    p = Path(path)
    t = p.read_text(encoding="utf-8", errors="replace")
    for old, new in pairs:
        if old not in t:
            raise SystemExit(f"anchor missing in {p.name}: {old[:70]}")
        t = t.replace(old, new, 1)
    p.write_text(t, encoding="utf-8", newline="\n")
    print("patched", p.relative_to(WS))


# ------------------------------------------------------------------ run.sh ---
R = WS / "main/app/assets/run.sh"
patch(R, [
    # 1. staleness marker for the previous incomplete run
    ('''# 清理上一次中止留下的 helper / victim
pkill -9 -f '[c]red_target' 2>/dev/null''',
     '''# 上一次运行是否在竞态阶段中断（同一路径跨 boot 保留，用于诊断重启）
if [ -f "$MARK/PERMISSIVE_STARTED" ]; then
    echo "PREVIOUS_RUN_INCOMPLETE $(cat "$MARK/PERMISSIVE_STARTED" 2>/dev/null)"
    rm -f "$MARK/PERMISSIVE_STARTED" 2>/dev/null
fi

# 清理上一次中止留下的 helper / victim
pkill -9 -f '[c]red_target' 2>/dev/null'''),
    # 2. preflight function before KASLR
    ('''mark KASLR_PRE
echo "== 1. KASLR =="''',
     '''# ---------------------------------------------------------------------------
# Preflight: the CVE-2026-64560 permissive race sprays/races kernel heap memory.
# Running it while Android is still booting (high load, little free memory) has a
# much higher panic/reboot rate, so wait until the device has settled.
#   MAGICROOT_BOOT_SETTLE_SEC  (default 60)
#   MAGICROOT_PREFLIGHT_MAX_LOAD (default 12)
#   MAGICROOT_PREFLIGHT_MIN_MEM_KB (default 800 MB)
#   MAGICROOT_PREFLIGHT_MAX_WAIT (default 180 s)
#   $D/skip-preflight or MAGICROOT_SKIP_PREFLIGHT=1 bypasses the wait.
#   MAGICROOT_PREFLIGHT_ONLY=1 stops after the check (diagnostics).
# ---------------------------------------------------------------------------
PREFLIGHT_SETTLE=${MAGICROOT_BOOT_SETTLE_SEC:-60}
PREFLIGHT_MAX_LOAD=${MAGICROOT_PREFLIGHT_MAX_LOAD:-12}
PREFLIGHT_MIN_MEM_KB=${MAGICROOT_PREFLIGHT_MIN_MEM_KB:-819200}
PREFLIGHT_MAX_WAIT=${MAGICROOT_PREFLIGHT_MAX_WAIT:-180}
case "$PREFLIGHT_SETTLE" in ''|*[!0-9]*) PREFLIGHT_SETTLE=60 ;; esac
case "$PREFLIGHT_MAX_LOAD" in ''|*[!0-9]*) PREFLIGHT_MAX_LOAD=12 ;; esac
case "$PREFLIGHT_MIN_MEM_KB" in ''|*[!0-9]*) PREFLIGHT_MIN_MEM_KB=819200 ;; esac
case "$PREFLIGHT_MAX_WAIT" in ''|*[!0-9]*) PREFLIGHT_MAX_WAIT=180 ;; esac
preflight() {
    if [ -f "$D/skip-preflight" ] || [ "${MAGICROOT_SKIP_PREFLIGHT:-0}" = "1" ]; then
        echo "PREFLIGHT_SKIP=1"
        return 0
    fi
    _i=0
    while :; do
        _up=$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)
        _load=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null | cut -d. -f1)
        [ -n "$_load" ] || _load=0
        _mem=$(awk '/^MemAvailable:/ {print int($2)}' /proc/meminfo 2>/dev/null)
        [ -n "$_mem" ] || _mem=0
        _bootc=$(getprop sys.boot_completed 2>/dev/null | tr -d '\\r\\n')
        if [ "$_up" -ge "$PREFLIGHT_SETTLE" ] && [ "$_bootc" = "1" ] &&
           [ "$_load" -le "$PREFLIGHT_MAX_LOAD" ] && [ "$_mem" -ge "$PREFLIGHT_MIN_MEM_KB" ]; then
            echo "PREFLIGHT_OK uptime=${_up}s load=${_load} mem_avail_kb=${_mem} settle=${PREFLIGHT_SETTLE} max_load=${PREFLIGHT_MAX_LOAD}"
            return 0
        fi
        if [ "$_i" -ge "$PREFLIGHT_MAX_WAIT" ]; then
            echo "FAIL=preflight_timeout uptime=${_up}s load=${_load} mem_avail_kb=${_mem} boot_completed=${_bootc}"
            echo "HINT=the device is still busy after boot; wait 1-2 minutes and retry (the permissive race is restart-prone on a busy boot)"
            echo "HINT_SKIP=touch $D/skip-preflight (or MAGICROOT_SKIP_PREFLIGHT=1) to bypass this safety wait"
            return 1
        fi
        if [ $((_i % 10)) -eq 0 ]; then
            echo "PREFLIGHT_WAIT uptime=${_up}s load=${_load} mem_avail_kb=${_mem} wait=${_i}/${PREFLIGHT_MAX_WAIT}s"
        fi
        sleep 1
        _i=$((_i + 1))
    done
}
preflight || exit 2
if [ "${MAGICROOT_PREFLIGHT_ONLY:-0}" = "1" ]; then
    echo "PREFLIGHT_ONLY_OK"
    exit 0
fi

mark KASLR_PRE
echo "== 1. KASLR =="'''),
    # 3. crash marker before permissive stage
    ('''echo "== 3. SELinux permissive =="''',
     '''echo "== 3. SELinux permissive =="
echo "boot_id=$BOOT_ID time=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null) uptime=$(cut -d. -f1 /proc/uptime 2>/dev/null)" > "$MARK/PERMISSIVE_STARTED"'''),
])

# remove the marker after the permissive stage landed
t = R.read_text(encoding="utf-8")
# find the successful landing echo region: after "attempt=" success branch
old = 'echo "  LANDED attempt=$attempt off=$off val=$val"'
if old in t:
    t = t.replace(old, old + '\n    rm -f "$MARK/PERMISSIVE_STARTED" 2>/dev/null', 1)
else:
    print("WARN permissive landed anchor missing")
R.write_text(t, encoding="utf-8", newline="\n")

# ------------------------------------------------------------- root_stage ---
S = WS / "main/app/assets/root_stage.sh"
patch(S, [
    ('''log "ROOT_STAGE_ENV uid=$ROOT_UID context=$CTX enforce=$ENF"''',
     '''log "ROOT_STAGE_ENV uid=$ROOT_UID context=$CTX enforce=$ENF"

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
fi'''),
])
print("done")
