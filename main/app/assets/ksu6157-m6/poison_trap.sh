#!/system/bin/sh
# poison_trap.sh - catch the poisoned 8-byte word and hunt it in exactly the
# files the crashing linker had mapped.
#
# Why: every fresh zygote dies at startup with
#   signal 11 SIGSEGV fault addr = <poison> + 0x200   pc = linker64
#   soinfo::get_primary_namespace()+0
# and 16/16 crashes use the SAME word, so the poison reaches the linker from a
# source that persists between process starts. The value is a kernel pointer
# (this boot: read straight out of the tombstone's x0), and a KASLR-different
# value on every boot - which is why it must be harvested from the tombstone of
# the SAME boot instead of being hardcoded.
#
# Scanning only the files listed in that tombstone's memory map keeps the search
# to a few hundred MB (seconds) instead of all of /system/lib64. Reading a file
# goes through the page cache, so a corrupted page cache page shows up directly.
#
# Started detached by ksu_loader.sh; results land in $RD/poison_trap.log.
RD=/data/local/tmp/ksu
LOG=$RD/poison_trap.log
STAMP=$RD/.poison_trap_stamp
: > $LOG
echo "trap start uptime=$(cut -d. -f1 /proc/uptime)" >> $LOG

touch $STAMP
TS=""
i=0
while [ $i -lt 200 ]; do
  for t in $(find /data/tombstones -maxdepth 1 -name 'tombstone_[0-9][0-9]' -newer $STAMP 2>/dev/null); do
    case "$t" in
      *.pb) continue ;;
    esac
    grep -aq SIGSEGV "$t" 2>/dev/null || continue
    # ONLY the zygote crash counts. Lesson learned the hard way: a bug in this
    # very tool (an out-of-bounds read in `file_hunt --shape`) produced its own
    # SIGSEGV tombstone first, poison_trap harvested x0 from THAT, got 0x100000
    # and matched every file in the tree.
    grep -aqE 'Cmdline: .*(app_process|zygote)' "$t" 2>/dev/null || continue
    TS=$t
    break
  done
  [ -n "$TS" ] && break
  sleep 2
  i=$((i+1))   # ★ 2026-10-16（修 P1-11）：上限 900→200（1800s→400s）
#   原因：App 只观察 480s，而原来这里跑 1800s ⇒ 它产出的结论永远无人接。
done

if [ -z "$TS" ]; then
  echo "no fresh SIGSEGV tombstone after $i polls" >> $LOG
  exit 0
fi

echo "tombstone=$TS at uptime=$(cut -d. -f1 /proc/uptime)" >> $LOG
grep -a -m1 'fault addr' "$TS" >> $LOG 2>&1
grep -a -m1 Cmdline "$TS" >> $LOG 2>&1

VAL=$(grep -ao 'x0  [0-9a-f]\{16\}' "$TS" | head -1 | sed 's/.*x0  //')
case "$VAL" in
  ffffff*) ;;
  *)
    # x0 was not the poison - fall back to any kernel pointer in the register dump
    VAL=$(grep -ao 'ffffff[0-9a-f]\{10\}' "$TS" | head -1)
    ;;
esac
echo "harvested value=$VAL" >> $LOG
case "$VAL" in
  ffffff*) ;;
  *) echo "harvested value is not a kernel pointer - aborting hunt" >> $LOG; exit 0 ;;
esac

LIST=$RD/.trap_files
awk '$1 ~ /-/ && $2 ~ /^r/ && $5 ~ /^\// {print $5}' "$TS" | sort -u > $LIST
echo "mapped files: $(wc -l < $LIST)" >> $LOG

# 1) exact top-40-bit search in every file that process had mapped.
#    file_hunt exits 1 when a file contains the word, so collect the hits.
HITS=""
while read -r f; do
  [ -f "$f" ] || continue
  if $RD/file_hunt "0x$VAL" --top40 "$f" >> $LOG 2>&1; then
    :
  else
    HITS="$HITS $f"
  fi
done < $LIST
echo "files containing the poison:${HITS:- none}" >> $LOG

# 1b) THE VMA HUNT - which mapping actually holds the poison, and does even a
#     trivial new process get it? The value is KASLR-dependent, so it CANNOT come
#     from a file (file contents are fixed across boots) - the kernel must hand it
#     to each new process at run time. So scan:
#       * a process WE spawn now (toybox sleep) - if it has the poison, the
#         delivery is universal and not specific to the Android framework,
#       * a live app_process64 (zygote) if one exists,
#       * system_server (it is one of the poison's victims),
#     over EVERY readable mapping, including read-only and kernel-made ones like
#     [vvar]/[vdso], which the stride hunt never looked at.
scan_proc() {
  label="$1"; pid="$2"; [ -n "$pid" ] || return 0
  echo "  [$label pid=$pid] non-file mappings:" >> $LOG
  $RD/poison_hunt --value "0x$VAL" --single --all-maps --no-file-maps --pid "$pid" >> $LOG 2>&1
  echo "  [$label pid=$pid] all mappings:" >> $LOG
  $RD/poison_hunt --value "0x$VAL" --single --all-maps --pid "$pid" >> $LOG 2>&1
}

# our own fresh process, so the scan cannot fail for lack of a target
sleep 90 &
SLEEP_PID=$!
echo "--- VMA hunt at uptime=$(cut -d. -f1 /proc/uptime) (spawned sleep pid=$SLEEP_PID)" >> $LOG
scan_proc "sleep" "$SLEEP_PID"

for d in /proc/[0-9]*; do
  c=$(cat "$d/comm" 2>/dev/null)
  case "$c" in
    app_process64) scan_proc "zygote" "${d#/proc/}"; break ;;
  esac
done
for d in /proc/[0-9]*; do
  c=$(cat "$d/comm" 2>/dev/null)
  case "$c" in
    system_server) scan_proc "system_server" "${d#/proc/}"; break ;;
  esac
done
# 1c) SCRUB THE POISONED PAGE. Device-verified 2026-09-19: a brand-new trivial
#     process (toybox sleep) has the poison word at offset +8 of EVERY page of
#     its [anon:.bss], [anon:cfi shadow] and [anon:scudo:primary] regions - i.e.
#     one physical page is handed out again and again, so the same word shows up
#     in every new process (which is why it is KASLR-dependent and in no file).
#     That page is mapped WRITABLE in our own process, so writing zeros to those
#     slots zeroes the physical page itself and every later handout is clean.
#     Guarded by $RD/SCRUB_POISON so it can be A/B'd.
#     ★ 用法：adb shell touch /data/local/tmp/ksu/SCRUB_POISON  （开启归零清理） Only words matching the
#     harvested value's top 40 bits are touched, so kernel text pointers in the
#     same page (e.g. a forged file_operations table) are left alone.
if [ -f "$RD/SCRUB_POISON" ] && [ -n "$SLEEP_PID" ]; then
  echo "--- SCRUB: zeroing the poison word in pid=$SLEEP_PID" >> $LOG
  $RD/poison_hunt --value "0x$VAL" --single --all-maps --scrub --pid "$SLEEP_PID" >> $LOG 2>&1
  echo "--- SCRUB verify: rescan (expect zero new hits)" >> $LOG
  $RD/poison_hunt --value "0x$VAL" --single --all-maps --no-file-maps --pid "$SLEEP_PID" >> $LOG 2>&1
  touch $RD/.scrub_stamp
  sleep 60
  LEFT=0
  for t in $(find /data/tombstones -maxdepth 1 -name 'tombstone_[0-9][0-9]' -newer $RD/.scrub_stamp 2>/dev/null); do
    grep -aqE 'Cmdline: .*(app_process|zygote|system_server)' "$t" 2>/dev/null && LEFT=$((LEFT+1))
  done
  echo "--- SCRUB verify: $LEFT new zygote/system_server crash(es) in the 60 s after the scrub" >> $LOG
fi

kill $SLEEP_PID 2>/dev/null
for h in $HITS; do
  echo "--- $h" >> $LOG
  ls -l "$h" >> $LOG 2>&1
  # which filesystem is it on (decides whether it can be repaired in place)
  d=$(dirname "$h")
  grep -F " $d " /proc/mounts >> $LOG 2>&1 || echo "(no exact mount match for $d)" >> $LOG
done

# 2) If the poison lives in a file's page cache, drop that page: the on-disk copy
#    is intact, so the next fault re-reads clean data. Two routes, because the
#    module's sysfs dir does not exist at runtime (KernelSU kobject_del's it):
#      - `purge <path>` borrows the reboot syscall (KSU reboot kprobe + 'PURG')
#      - the module's purge_path parameter, if a build ever exposes it
PURGE_BIN=$RD/purge
PURGE_PARAM=/sys/module/kernelsu/parameters/purge_path
if [ -n "$HITS" ]; then
  if [ -x "$PURGE_BIN" ]; then
    $PURGE_BIN $HITS >> $LOG 2>&1
  elif [ -w "$PURGE_PARAM" ]; then
    for h in $HITS; do
      echo "purge(param) -> $h" >> $LOG
      echo "$h" > "$PURGE_PARAM" 2>>$LOG || echo "purge write FAILED for $h" >> $LOG
    done
  else
    echo "no purge route available (no $PURGE_BIN, no $PURGE_PARAM)" >> $LOG
  fi

  # verification: no NEW zygote SIGSEGV tombstone in the next 60 s means the
  # poison is no longer reaching new processes.
  touch $RD/.purge_stamp
  sleep 60
  LEFT=0
  for t in $(find /data/tombstones -maxdepth 1 -name 'tombstone_[0-9][0-9]' -newer $RD/.purge_stamp 2>/dev/null); do
    grep -aqE 'Cmdline: .*(app_process|zygote)' "$t" 2>/dev/null && LEFT=$((LEFT+1))
  done
  echo "verify: $LEFT new zygote crash(es) in the 60 s after the purge" >> $LOG
fi

# 3) also record the crashed process's memfd/ashmem/anon mappings
echo "--- special mappings of the crashed process ---" >> $LOG
awk '$1 ~ /-/ && ($NF ~ /memfd/ || $NF ~ /ashmem/ || $NF ~ /deleted/ || NF < 5) {print}' "$TS" \
  | sort -u | head -60 >> $LOG

echo "trap done uptime=$(cut -d. -f1 /proc/uptime)" >> $LOG
