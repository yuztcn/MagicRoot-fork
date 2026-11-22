from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")

old = '''AB_EXPORT=0
[ -f "$D/ab-export" ] && AB_EXPORT=1
VICTIMS_PERMISSIVE=${MAGICROOT_VICTIMS_PERMISSIVE:-32}
VICTIMS_FSUID=${MAGICROOT_VICTIMS_FSUID:-32}
VICTIMS_CRED=${MAGICROOT_VICTIMS_CRED:-24}
case "$VICTIMS_PERMISSIVE" in 16|24|32) ;; *) VICTIMS_PERMISSIVE=32 ;; esac
case "$VICTIMS_FSUID" in 16|24|32) ;; *) VICTIMS_FSUID=32 ;; esac
case "$VICTIMS_CRED" in 8|12|16|24) ;; *) VICTIMS_CRED=24 ;; esac'''

new = '''AB_EXPORT=0
[ -f "$D/ab-export" ] && AB_EXPORT=1

# Tuning presets (opt-in via marker files; defaults are the MagicRoot values).
#   $D/tuning-reference : HyperBreak Enhanced's tuned 6.18 values
#                         (24 victims / 200-300 attempts / 12000 nfrag / 10000 cred drain)
#   $D/tuning-op16      : OnePlus16 v2.7.0 explicit core.sh values
#                         (16 victims / 180 perm attempts / 90+90 writer / 6000 nfrag)
# Environment overrides MAGICROOT_* always win over the preset.
TUNING=current
[ -f "$D/tuning-reference" ] && TUNING=reference
[ -f "$D/tuning-op16" ] && TUNING=op16
[ -n "${MAGICROOT_TUNING:-}" ] && TUNING=$MAGICROOT_TUNING
case "$TUNING" in
    reference)
        DEF_VICTIMS_PERMISSIVE=24; DEF_VICTIMS_FSUID=24; DEF_VICTIMS_CRED=24
        DEF_ATTEMPTS_PERMISSIVE=200; DEF_ATTEMPTS_FSUID=200
        DEF_ATTEMPTS_CRED1=200; DEF_ATTEMPTS_CRED2=300
        DEF_FRAG_PERMISSIVE=12000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        DEF_FRAG_CRED=12000; DEF_DRAIN_CRED1=10000; DEF_MIN_CRED1=3500
        DEF_DRAIN_CRED2=10000; DEF_MIN_CRED2=3500
        ;;
    op16)
        DEF_VICTIMS_PERMISSIVE=16; DEF_VICTIMS_FSUID=16; DEF_VICTIMS_CRED=16
        DEF_ATTEMPTS_PERMISSIVE=180; DEF_ATTEMPTS_FSUID=180
        DEF_ATTEMPTS_CRED1=90; DEF_ATTEMPTS_CRED2=90
        DEF_FRAG_PERMISSIVE=6000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        DEF_FRAG_CRED=6000; DEF_DRAIN_CRED1=12000; DEF_MIN_CRED1=4500
        DEF_DRAIN_CRED2=12000; DEF_MIN_CRED2=4500
        ;;
    *)
        TUNING=current
        DEF_VICTIMS_PERMISSIVE=32; DEF_VICTIMS_FSUID=32; DEF_VICTIMS_CRED=24
        DEF_ATTEMPTS_PERMISSIVE=500; DEF_ATTEMPTS_FSUID=500
        DEF_ATTEMPTS_CRED1=400; DEF_ATTEMPTS_CRED2=500
        DEF_FRAG_PERMISSIVE=12000; DEF_DRAIN_PERMISSIVE=12000; DEF_MIN_PERMISSIVE=4500
        DEF_FRAG_CRED=12000; DEF_DRAIN_CRED1=15000; DEF_MIN_CRED1=3500
        DEF_DRAIN_CRED2=15000; DEF_MIN_CRED2=3500
        ;;
esac

VICTIMS_PERMISSIVE=${MAGICROOT_VICTIMS_PERMISSIVE:-$DEF_VICTIMS_PERMISSIVE}
VICTIMS_FSUID=${MAGICROOT_VICTIMS_FSUID:-$DEF_VICTIMS_FSUID}
VICTIMS_CRED=${MAGICROOT_VICTIMS_CRED:-$DEF_VICTIMS_CRED}
case "$VICTIMS_PERMISSIVE" in 16|24|32) ;; *) VICTIMS_PERMISSIVE=$DEF_VICTIMS_PERMISSIVE ;; esac
case "$VICTIMS_FSUID" in 16|24|32) ;; *) VICTIMS_FSUID=$DEF_VICTIMS_FSUID ;; esac
case "$VICTIMS_CRED" in 8|12|16|24) ;; *) VICTIMS_CRED=$DEF_VICTIMS_CRED ;; esac'''

if old not in t:
    raise SystemExit("victim block anchor missing")
t = t.replace(old, new, 1)

old2 = '''ATTEMPTS_PERMISSIVE=500
ATTEMPTS_FSUID=500
ATTEMPTS_CRED1=400
ATTEMPTS_CRED2=500
FRAG_PERMISSIVE=12000
DRAIN_PERMISSIVE=12000
MIN_PERMISSIVE=4500
FRAG_CRED=12000
DRAIN_CRED1=15000
MIN_CRED1=3500
DRAIN_CRED2=15000
MIN_CRED2=3500
# timers per victim (legacy 400).
GRAB_LOOPS=40'''

new2 = '''ATTEMPTS_PERMISSIVE=${MAGICROOT_ATTEMPTS_PERMISSIVE:-$DEF_ATTEMPTS_PERMISSIVE}
ATTEMPTS_FSUID=${MAGICROOT_ATTEMPTS_FSUID:-$DEF_ATTEMPTS_FSUID}
ATTEMPTS_CRED1=${MAGICROOT_ATTEMPTS_CRED1:-$DEF_ATTEMPTS_CRED1}
ATTEMPTS_CRED2=${MAGICROOT_ATTEMPTS_CRED2:-$DEF_ATTEMPTS_CRED2}
FRAG_PERMISSIVE=${MAGICROOT_FRAG_PERMISSIVE:-$DEF_FRAG_PERMISSIVE}
DRAIN_PERMISSIVE=${MAGICROOT_DRAIN_PERMISSIVE:-$DEF_DRAIN_PERMISSIVE}
MIN_PERMISSIVE=${MAGICROOT_MIN_PERMISSIVE:-$DEF_MIN_PERMISSIVE}
FRAG_CRED=${MAGICROOT_FRAG_CRED:-$DEF_FRAG_CRED}
DRAIN_CRED1=${MAGICROOT_DRAIN_CRED1:-$DEF_DRAIN_CRED1}
MIN_CRED1=${MAGICROOT_MIN_CRED1:-$DEF_MIN_CRED1}
DRAIN_CRED2=${MAGICROOT_DRAIN_CRED2:-$DEF_DRAIN_CRED2}
MIN_CRED2=${MAGICROOT_MIN_CRED2:-$DEF_MIN_CRED2}
# timers per victim (legacy 400); capture loop count for grab.sh.
GRAB_LOOPS=${MAGICROOT_GRAB_LOOPS:-40}
for _v in ATTEMPTS_PERMISSIVE ATTEMPTS_FSUID ATTEMPTS_CRED1 ATTEMPTS_CRED2; do
    eval "_n=\\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=120" ;; esac
    [ "$_n" -ge 1 ] 2>/dev/null && [ "$_n" -le 20000 ] 2>/dev/null || eval "$_v=120"
done
for _v in FRAG_PERMISSIVE FRAG_CRED; do
    eval "_n=\\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=6000" ;; esac
    [ "$_n" -ge 100 ] 2>/dev/null && [ "$_n" -le 60000 ] 2>/dev/null || eval "$_v=6000"
done
for _v in DRAIN_PERMISSIVE DRAIN_CRED1 DRAIN_CRED2; do
    eval "_n=\\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=12000" ;; esac
    [ "$_n" -ge 1000 ] 2>/dev/null && [ "$_n" -le 60000 ] 2>/dev/null || eval "$_v=12000"
done
for _v in MIN_PERMISSIVE MIN_CRED1 MIN_CRED2; do
    eval "_n=\\$$_v"
    case "$_n" in ''|*[!0-9]*) eval "$_v=3500" ;; esac
    [ "$_n" -ge 100 ] 2>/dev/null && [ "$_n" -le 60000 ] 2>/dev/null || eval "$_v=3500"
done
case "$GRAB_LOOPS" in ''|*[!0-9]*) GRAB_LOOPS=40 ;; esac
[ "$GRAB_LOOPS" -ge 1 ] 2>/dev/null && [ "$GRAB_LOOPS" -le 400 ] 2>/dev/null || GRAB_LOOPS=40'''

if old2 not in t:
    raise SystemExit("attempt block anchor missing")
t = t.replace(old2, new2, 1)

old3 = '''echo "VICTIMS_PERMISSIVE=$VICTIMS_PERMISSIVE"'''
new3 = '''echo "TUNING=$TUNING VICTIMS_PERMISSIVE=$VICTIMS_PERMISSIVE"'''
if old3 not in t:
    raise SystemExit("echo anchor missing")
t = t.replace(old3, new3, 1)

p.write_text(t, encoding="utf-8", newline="\n")
print("tuning presets/env overrides added")
