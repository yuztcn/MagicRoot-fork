from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")

start = 'if [ "$KASLR_CACHE_HIT" != "1" ]; then'
end = 'grep -q \'^KASLR_ERROR=\' "$D/kaslr.txt" && { echo "FAIL=kaslr_validation"; exit 2; }'
i = t.find(start)
j = t.find(end)
if i < 0 or j < 0:
    raise SystemExit("KASLR block anchors missing")
j += len(end)
old = t[i:j]

new = '''KASLR_MIN_VOTES=${PROFILE_KASLR_MIN_VOTES:-3}
KASLR_MIN_ANCHORS=${PROFILE_KASLR_MIN_ANCHORS:-2}
KASLR_MIN_BYTES=${PROFILE_KASLR_MIN_BYTES:-1048576}
KASLR_GRAB_TRIES=${MAGICROOT_KASLR_GRAB_TRIES:-3}
case "$KASLR_GRAB_TRIES" in ''|*[!0-9]*) KASLR_GRAB_TRIES=3 ;; esac
[ "$KASLR_GRAB_TRIES" -ge 1 ] 2>/dev/null && [ "$KASLR_GRAB_TRIES" -le 5 ] 2>/dev/null ||
    KASLR_GRAB_TRIES=3
KASLR_GRAB_MAX_LOOPS=${MAGICROOT_KASLR_GRAB_MAX_LOOPS:-300}
case "$KASLR_GRAB_MAX_LOOPS" in ''|*[!0-9]*) KASLR_GRAB_MAX_LOOPS=300 ;; esac
[ "$KASLR_GRAB_MAX_LOOPS" -ge 40 ] 2>/dev/null &&
    [ "$KASLR_GRAB_MAX_LOOPS" -le 600 ] 2>/dev/null ||
    KASLR_GRAB_MAX_LOOPS=300

# Read + validate KASLR fields.  This only accepts a capture that meets the
# profile's anchors/votes/bytes gates; otherwise the caller re-captures.
kaslr_fields_ok() {
    SLIDE=$(sed -n 's/^KASLR_SLIDE=//p' "$D/kaslr.txt" 2>/dev/null)
    SELINUX_ARG=$(sed -n 's/^SELINUX_ARG=//p' "$D/kaslr.txt" 2>/dev/null)
    PREPARE=$(sed -n 's/^PREPARE=//p' "$D/kaslr.txt" 2>/dev/null)
    VOTES=$(sed -n 's/^KASLR_VOTES=//p' "$D/kaslr.txt" 2>/dev/null)
    ANCHORS=$(sed -n 's/^KASLR_ANCHORS=//p' "$D/kaslr.txt" 2>/dev/null)
    KASLR_BYTES=$(sed -n 's/^KASLR_BYTES=//p' "$D/kaslr.txt" 2>/dev/null)
    case "$KASLR_BYTES" in ''|*[!0-9]*) KASLR_BYTES=0 ;; esac
    [ -n "$SLIDE" ] || return 1
    case "$PREPARE" in 0xffff*) ;; *) return 1 ;; esac
    case "$SELINUX_ARG" in 0xffff*) ;; *) return 1 ;; esac
    [ -n "$VOTES" ] && [ "$VOTES" -ge "$KASLR_MIN_VOTES" ] 2>/dev/null || return 1
    [ -n "$ANCHORS" ] && [ "$ANCHORS" -ge "$KASLR_MIN_ANCHORS" ] 2>/dev/null || return 1
    [ "$KASLR_BYTES" -ge "$KASLR_MIN_BYTES" ] 2>/dev/null || return 1
    ! grep -q '^KASLR_ERROR=' "$D/kaslr.txt" 2>/dev/null || return 1
    return 0
}

# A cache entry from an earlier run can be under-sampled (the old code wrote
# it before validating).  Reject it and force a fresh capture.
if [ "$KASLR_CACHE_HIT" = "1" ] && ! kaslr_fields_ok; then
    echo "KASLR_CACHE_REJECT boot_id=$BOOT_ID anchors=${ANCHORS:-none} votes=${VOTES:-none} bytes=${KASLR_BYTES:-0}"
    KASLR_CACHE_HIT=0
fi
if [ "$KASLR_CACHE_HIT" != "1" ]; then
    KASLR_GRAB_TRY=0
    while [ "$KASLR_GRAB_TRY" -lt "$KASLR_GRAB_TRIES" ]; do
        KASLR_GRAB_TRY=$((KASLR_GRAB_TRY + 1))
        _loops=$((GRAB_LOOPS * KASLR_GRAB_TRY))
        [ "$_loops" -gt "$KASLR_GRAB_MAX_LOOPS" ] && _loops=$KASLR_GRAB_MAX_LOOPS
        if [ "$KASLR_GRAB_TRY" -eq "$KASLR_GRAB_TRIES" ] && [ "$KASLR_GRAB_TRY" -gt 1 ]; then
            echo "KASLR_GRAB_TRY=$KASLR_GRAB_TRY legacy=1 loops=$_loops"
            mark GRAB_PRE
            sh "$D/grab_legacy.sh" 8 >/dev/null 2>&1
            mark GRAB_DONE
        else
            echo "KASLR_GRAB_TRY=$KASLR_GRAB_TRY loops=$_loops"
            mark GRAB_PRE
            sh "$D/grab.sh" "$_loops" >/dev/null 2>&1
            mark GRAB_DONE
        fi
        "$KASLR_BIN" "$D" > "$D/kaslr.txt"
        if kaslr_fields_ok; then
            break
        fi
        if [ "$KASLR_GRAB_TRY" -lt "$KASLR_GRAB_TRIES" ]; then
            echo "KASLR_REGRAB attempt=$KASLR_GRAB_TRY anchors=${ANCHORS:-none} votes=${VOTES:-none} bytes=${KASLR_BYTES:-0} reason=below_profile_gate"
            sleep 1
        fi
    done
fi
cat "$D/kaslr.txt"
if ! kaslr_fields_ok; then
    if [ -z "$SLIDE" ]; then
        echo "FAIL=kaslr"
    elif [ "${PREPARE#0xffff}" = "$PREPARE" ]; then
        echo "FAIL=bad_prepare"
    elif [ "${SELINUX_ARG#0xffff}" = "$SELINUX_ARG" ]; then
        echo "FAIL=bad_selinux_arg"
    elif [ -z "$VOTES" ] || [ "$VOTES" -lt "$KASLR_MIN_VOTES" ] 2>/dev/null; then
        echo "FAIL=kaslr_votes votes=${VOTES:-none} min=$KASLR_MIN_VOTES"
    elif [ -z "$ANCHORS" ] || [ "$ANCHORS" -lt "$KASLR_MIN_ANCHORS" ] 2>/dev/null; then
        echo "FAIL=kaslr_anchors anchors=${ANCHORS:-none} min=$KASLR_MIN_ANCHORS"
    elif [ "$KASLR_BYTES" -lt "$KASLR_MIN_BYTES" ] 2>/dev/null; then
        echo "FAIL=kaslr_bytes bytes=$KASLR_BYTES min=$KASLR_MIN_BYTES"
    else
        echo "FAIL=kaslr_validation"
    fi
    rm -f "$KASLR_CACHE" 2>/dev/null || true
    exit 2
fi
# Only cache a capture that passed the gates.
if [ -n "$BOOT_ID" ] && [ "$KASLR_CACHE_HIT" != "1" ]; then
    { echo "$BOOT_ID"; cat "$D/kaslr.txt"; } > "$KASLR_CACHE" 2>/dev/null || true
fi
SELINUX_ARG=$(sed -n 's/^SELINUX_ARG=//p' "$D/kaslr.txt")
PREPARE=$(sed -n 's/^PREPARE=//p' "$D/kaslr.txt")
VOTES=$(sed -n 's/^KASLR_VOTES=//p' "$D/kaslr.txt")
ANCHORS=$(sed -n 's/^KASLR_ANCHORS=//p' "$D/kaslr.txt")
KASLR_BYTES=$(sed -n 's/^KASLR_BYTES=//p' "$D/kaslr.txt")
case "$KASLR_BYTES" in ''|*[!0-9]*) KASLR_BYTES=0 ;; esac'''

t = t[:i] + new + t[j:]
p.write_text(t, encoding="utf-8", newline="\n")
print(f"replaced KASLR block ({len(old)} -> {len(new)} bytes)")
