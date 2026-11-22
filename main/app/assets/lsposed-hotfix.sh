#!/system/bin/sh
# v12: never bundle or restore Zygisk Next sepolicy; require the module's own rule.
# v11: poll lspd's delayed nice-name transition and retain launch diagnostics.
# v10: LSPosed-only hot reboot repair, adapted from the proven m_rcq flow.
#
# Other KSU/Zygisk modules load normally after ksud post-fs-data/services.
# LSPosed is special: its lspd daemon must be started with the real zygote
# BOOTCLASSPATH and in the init mount namespace, then zygote64 is killed so a
# fresh system_server can receive the bridge.  Starting lspd from the module
# service environment is not enough on this temporary-root setup.
PATH=/system/bin:/vendor/bin:/data/adb/ksu/bin:$PATH
export PATH

mkdir -p /data/local/tmp/magic 2>/dev/null || true
LOG=/data/local/tmp/magic/lsposed-hotfix-tool.log
MODDIR=/data/adb/modules/zygisk_lsposed
LOGDIR=/data/adb/lspd/log
ZYGISKDIR=/data/adb/modules/zygisksu
ZN_STATE_DIR=/data/adb/zygisksu
KSUD=${KSUD:-}
PFD_STATE=/data/local/tmp/.magicroot-lsposed-pfd

zn_daemon_pid() {
  ps -A -o PID,STAT,NAME 2>/dev/null |
    awk 'NR > 1 && $2 !~ /^Z/ && tolower($3) ~ /^(zygiskd|zn-daemon)(32|64)?$/ {print $1}' |
    while read -r _pid; do
      [ -r "/proc/$_pid/cmdline" ] || continue
      _cmd=$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null)
      case "$_cmd" in *service-stage*) continue ;; esac
      case "$_cmd" in
        *daemon*) printf '%s\n' "$_pid"; break ;;
      esac
    done
}

lspd_pid() {
  ps -A -o PID,NAME 2>/dev/null | awk '$2 == "lspd" {print $1; exit}'
}

wait_for_lspd() {
  _limit=${1:-20}
  _elapsed=0
  while [ "$_elapsed" -lt "$_limit" ]; do
    _pid=$(lspd_pid)
    if [ -n "$_pid" ]; then
      printf '%s\n' "$_pid"
      return 0
    fi
    sleep 1
    _elapsed=$((_elapsed + 1))
  done
  return 1
}

{
  echo "=== BEGIN $(date) boot_id=$(cat /proc/sys/kernel/random/boot_id)"
  if [ -z "$KSUD" ] || [ ! -x "$KSUD" ]; then
    _fl=$(cat /data/local/tmp/magic/ksu_flavor 2>/dev/null | tr -d '\r\n')
    case "$_fl" in
      kernelsu) _sel=/data/local/tmp/magic/ksud_kernelsu ;;
      resukisu) _sel=/data/local/tmp/magic/ksud_bakasu ;;
      next)     _sel=/data/local/tmp/magic/ksud_next ;;
      sukisu)   _sel=/data/local/tmp/magic/ksud_sukisu ;;
      fina)     _sel=/data/local/tmp/magic/ksud_fina ;;
      *)        _sel="" ;;
    esac
    if [ -n "$_sel" ] && [ -x "$_sel" ]; then
      KSUD="$_sel"
    else
      for c in /data/adb/ksud /data/local/tmp/magic/ksud_*; do
        [ -x "$c" ] || continue
        KSUD="$c"
        break
      done
    fi
  fi
  echo "KSUD=${KSUD:-none}"
  echo "LSPOSED_MODULE_VERSION=$(grep -E '^version=' "$MODDIR/module.prop" 2>/dev/null | head -1)"
  # The LSPosed manager APK is intentionally not installed here.
  echo "LSPOSED_MANAGER_INSTALL=skip reason=not_required"

  if [ -z "$KSUD" ]; then
    echo "ERROR=no_ksud"
    echo "DONE"
    exit 2
  fi

  # Zygisk is a pluggable provider: KernelSU's built-in FolkZygisk engine,
  # Zygisk Next (zygisksu), YukiZygisk and others all speak the same API to
  # LSPosed.  Only Zygisk Next is auto-repaired below, because its
  # verify1/sepolicy/self-disable behaviour is the one we have audited.  Any
  # other provider is used as-is and its module/daemon is never touched.
  ZYGISK_STATUS=$(timeout 10 "$KSUD" zygisk status 2>/dev/null)
  ZN_ACTIVE=1
  if [ -n "$ZYGISK_STATUS" ] &&
     printf '%s' "$ZYGISK_STATUS" | grep -q 'external_providers'; then
    if printf '%s' "$ZYGISK_STATUS" | grep -q '"zygisksu"'; then
      ZN_ACTIVE=1
    else
      ZN_ACTIVE=0
    fi
  fi
  case "$ZYGISK_STATUS" in
    *'"engine_available": true'*) ZYGISK_ENGINE=builtin ;;
    *) ZYGISK_ENGINE=none ;;
  esac
  echo "ZYGISK_PROVIDER=engine=$ZYGISK_ENGINE zygisknext_active=$ZN_ACTIVE"

  # Zygisk Next 1.5.3 aborts before injection when its state directory is
  # absent: open(/data/adb/zygisksu/.magic, O_CREAT) then fails with ENOENT.
  # Restore only the missing parent directory; never clear the module's state.
  ZN_STATE_READY=0
  if [ "$ZN_ACTIVE" = "1" ] && [ -d "$ZYGISKDIR" ]; then
    if [ ! -d "$ZN_STATE_DIR" ]; then
      mkdir -p "$ZN_STATE_DIR" 2>/dev/null
      echo "ZYGISK_STATE_MKDIR=$ZN_STATE_DIR rc=$?"
    fi
    if [ -d "$ZN_STATE_DIR" ] && [ -w "$ZN_STATE_DIR" ]; then
      ZN_STATE_READY=1
      echo "ZYGISK_STATE=ready path=$ZN_STATE_DIR"
    else
      echo "ZYGISK_STATE=error path=$ZN_STATE_DIR reason=missing_or_unwritable"
    fi
  fi

  # Zygisk Next verifies every module file at startup (verify1).  MagicRoot
  # must not supply or restore sepolicy.rule: that would add live SELinux rules
  # on the module's behalf.  Use only the rule already shipped by the installed
  # module.  If it is absent, leave the module untouched and fail closed below.
  ZN_RULE="$ZYGISKDIR/sepolicy.rule"
  if [ "$ZN_ACTIVE" = "1" ] && [ -d "$ZYGISKDIR" ]; then
    if [ -f "$ZN_RULE" ]; then
      echo "ZYGISK_SEPOLICY=present source=module"
    else
      echo "ZYGISK_SEPOLICY=missing path=$ZN_RULE reason=module_rule_required"
    fi
    if [ -f "$ZN_RULE" ]; then
      if [ -f "$ZYGISKDIR/disable" ] ||
         ! grep -q '^id=zygisksu' "$ZYGISKDIR/module.prop" 2>/dev/null; then
        [ -f "$ZYGISKDIR/module.prop.orig" ] &&
          cp -f "$ZYGISKDIR/module.prop.orig" "$ZYGISKDIR/module.prop" 2>/dev/null
        rm -f "$ZYGISKDIR/disable" 2>/dev/null
        echo "ZYGISK_MODULE_RECOVERED=reenabled"
      fi
      if [ -f "$ZN_STATE_DIR/.abort_msg" ]; then
        cp -f "$ZN_STATE_DIR/.abort_msg" "$ZN_STATE_DIR/.abort_msg.old" 2>/dev/null
        rm -f "$ZN_STATE_DIR/.abort_msg" "$ZN_STATE_DIR/.magic" \
              "$ZN_STATE_DIR/.injecting" 2>/dev/null
        echo "ZYGISK_STATE_RESET=abort_cleared"
      fi
    fi
  fi

  # post-fs-data mounts modules and injects sepolicy; neither is undone by a
  # zygote restart.  Repeating it re-adds lsposed_file/magisk_file and produces
  # duplicate-type errors.  Run it once per boot, but run services every time so
  # Zygisk Next/LSPosed still restart and inject normally.
  CURRENT_BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n')
  PFD_BOOT=$(cat "$PFD_STATE" 2>/dev/null | tr -d '\r\n')
  if [ -n "$CURRENT_BOOT" ] && [ "$PFD_BOOT" = "$CURRENT_BOOT" ]; then
    echo "POST_FS_DATA_RC=0 skipped=already_done_this_boot"
  else
    timeout 45 "$KSUD" post-fs-data
    PFD_RC=$?
    echo "POST_FS_DATA_RC=$PFD_RC"
    if [ "$PFD_RC" = "0" ] && [ -n "$CURRENT_BOOT" ]; then
      if printf '%s\n' "$CURRENT_BOOT" > "$PFD_STATE.tmp.$$"; then
        mv -f "$PFD_STATE.tmp.$$" "$PFD_STATE" 2>/dev/null || true
      fi
      rm -f "$PFD_STATE.tmp.$$" 2>/dev/null || true
    fi
  fi
  # Zygisk Next's service.sh drops a cleanup script into /data/adb/service.d;
  # the directory is absent on a fresh /data/adb and the copy fails loudly.
  mkdir -p /data/adb/service.d 2>/dev/null || true
  timeout 45 "$KSUD" services
  echo "SERVICES_RC=$?"
  sleep 2

  # Stop any stale lspd, including one started by service.sh without the
  # zygote runtime environment.
  echo "KILL_OLD_LSPD=begin"
  for PID in $(ps -A -o PID,NAME 2>/dev/null | grep -E '(^| )lspd($| )' | awk '{print $1}'); do
    kill -9 "$PID" 2>/dev/null
    echo "KILLED_LSPD=$PID"
  done
  sleep 1

  ZPID=$(ps -A -o PID,NAME 2>/dev/null | grep 'zygote64' | awk '{print $1}' | head -1)
  if [ -z "$ZPID" ]; then
    echo "ERROR=no_zygote64"
    echo "DONE"
    exit 3
  fi
  BOOTCP=$(cat "/proc/$ZPID/environ" 2>/dev/null | tr '\0' '\n' | grep '^BOOTCLASSPATH=' | head -1)
  DEX2OAT=$(cat "/proc/$ZPID/environ" 2>/dev/null | tr '\0' '\n' | grep '^DEX2OATBOOTCLASSPATH=' | head -1)
  if [ -z "$BOOTCP" ]; then
    echo "ERROR=no_bootclasspath zygote=$ZPID"
    echo "DONE"
    exit 4
  fi
  echo "ZYGOTE64=$ZPID BOOTCLASSPATH_CHARS=${#BOOTCP}"

  # Zygisk Next is optional.  Do not start a duplicate daemon when the normal
  # ksud services path already initialized magic and left a daemon running.
  ZN_PID=$(zn_daemon_pid)
  if [ "$ZN_ACTIVE" != "1" ]; then
    echo "ZYGISKD_RESTART=skip reason=provider_not_zygisksu"
  elif [ ! -d "$ZYGISKDIR" ] || [ ! -x "$ZYGISKDIR/bin/zygiskd" ]; then
    echo "ZYGISKD_RESTART=skip reason=no_zygisksu_module"
  elif [ "$ZN_STATE_READY" != "1" ]; then
    echo "ZYGISKD_RESTART=skip reason=state_dir_unavailable"
  elif [ ! -f "$ZYGISKDIR/sepolicy.rule" ]; then
    # Starting zygiskd without its verified sepolicy.rule makes verify1 fail
    # and the module disable itself.  Fail closed instead.
    echo "ZYGISKD_RESTART=skip reason=sepolicy_rule_missing"
  elif [ -n "$ZN_PID" ] && [ -f "$ZN_STATE_DIR/.magic" ]; then
    echo "ZYGISKD_RESTART=skip reason=already_running pid=$ZN_PID magic=present"
  elif [ -f "$ZN_STATE_DIR/.magic" ] && [ -f "$ZN_STATE_DIR/modules_info" ] &&
       [ ! -f "$ZN_STATE_DIR/.abort_msg" ]; then
    # The daemon attaches to init and exits by design; a consumed magic plus
    # modules_info is a finished injection, not a missing daemon.
    echo "ZYGISKD_RESTART=skip reason=already_injected magic=present pid=none"
  else
    ( cd "$ZYGISKDIR" && ./bin/zygiskd daemon ) >> "$LOG" 2>&1 &
    sleep 2
    ( cd "$ZYGISKDIR" && ./bin/zygiskd service-stage ) >> "$LOG" 2>&1 &
    sleep 1
    ZN_PID=$(zn_daemon_pid)
    echo "ZYGISKD_RESTART=done pid=${ZN_PID:-none}"
  fi
  if [ -d "$ZYGISKDIR" ]; then
    if [ -f "$ZN_STATE_DIR/.magic" ]; then ZN_MAGIC=present; else ZN_MAGIC=missing; fi
    echo "ZYGISK_NEXT_STATE=magic=$ZN_MAGIC pid=${ZN_PID:-none}"
  fi

  rm -f /data/adb/lspd/monitor /data/adb/lspd/lock 2>/dev/null

  OLD_SS=$(ps -A -o PID,NAME 2>/dev/null | grep 'system_server' | awk '{print $1}' | head -1)
  echo "OLD_SYSTEM_SERVER=${OLD_SS:-none}"

  # Start lspd exactly like the proven reference: init mount namespace,
  # zygote BOOTCLASSPATH, app_process, no image dex2oat.  Keep a separate
  # launch log: a fixed sleep used to misreport a slow start as a missing lspd.
  java_options="-Djava.class.path=$MODDIR/daemon.apk -Xnoimage-dex2oat"
  : > "$LOG.launch"
  setsid nsenter -t 1 -m -- /system/bin/sh -c "
      cd $MODDIR || exit 1
      export $BOOTCP
      ${DEX2OAT:+export $DEX2OAT}
      export PATH=$PATH
      exec /system/bin/app_process $java_options /system/bin --nice-name=lspd org.lsposed.lspd.Main
  " </dev/null >>"$LOG.launch" 2>&1 &
  LSPD_LAUNCHER=$!
  echo "LSPD_START_LOG=$LOG.launch launcher=$LSPD_LAUNCHER"

  # app_process applies --nice-name only after ART and the Java main entry have
  # started.  Poll for up to 20 seconds instead of failing at the old 3-second
  # mark.  The launcher PID is retained for correlating a failed launch with
  # its captured stderr; do not kill it here if it is still initializing.
  LSPD_PID=$(wait_for_lspd 20)
  if [ -z "$LSPD_PID" ]; then
    echo "ERROR=lspd_start_failed launcher=$LSPD_LAUNCHER"
    if [ -s "$LOG.launch" ]; then
      echo "LSPD_START_LOG_BEGIN"
      tail -40 "$LOG.launch"
      echo "LSPD_START_LOG_END"
    fi
    echo "DONE"
    exit 5
  fi
  echo "LSPD_STARTED=$LSPD_PID"
  sleep 3
  LSPD_PID=$(lspd_pid)
  if [ -z "$LSPD_PID" ]; then
    echo "ERROR=lspd_crashed launcher=$LSPD_LAUNCHER"
    if [ -s "$LOG.launch" ]; then
      echo "LSPD_START_LOG_BEGIN"
      tail -40 "$LOG.launch"
      echo "LSPD_START_LOG_END"
    fi
    echo "DONE"
    exit 6
  fi
  echo "LSPD_ALIVE=$LSPD_PID"

  # ---- armed-victim guard -------------------------------------------------
  # A previous 98260 run that left unproven armed zombies (slab reclaimed by a
  # foreign allocation) turns the zygote restart into a kernel panic: init's
  # teardown kills the parked exploit parent and reaps those zombies through
  # the corrupted posix_cpu_timers tree.  The exploit parent maintains
  # /data/local/tmp/.magicroot-unproven ("<boot_id> <count>") while such
  # zombies exist and removes it once they are reaped (victim_watch_forever).
  # Wait for the marker to clear instead of detonating the bomb; refuse the
  # zygote kill only if it never clears.
  UNPROVEN=/data/local/tmp/.magicroot-unproven
  if [ -f "$UNPROVEN" ]; then
    _mk=$(cat "$UNPROVEN" 2>/dev/null)
    _mk_boot=$(printf '%s' "$_mk" | awk '{print $1}')
    _mk_cnt=$(printf '%s' "$_mk" | awk '{print $2}')
    _cur_boot=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
    if { [ -z "$_mk_boot" ] || [ -z "${_mk_cnt:-}" ] || ! [ "${_mk_cnt:-0}" -ge 0 ] 2>/dev/null; } &&
       { pidof exploit-android-key-ptr >/dev/null 2>&1 || pidof cve98260_plant >/dev/null 2>&1; }; then
      # A freshly created marker used to survive a panic as NUL bytes because
      # its data was never fsynced.  With a live plant this is still unsafe:
      # fail closed instead of deleting the only persistent guard.
      echo "VICTIM_GUARD=warn reason=invalid_marker_with_live_plant"
      echo "HINT=invalid unproven marker with a live plant; continuing because the user requested the repair"
    fi
    if [ -n "$_mk_boot" ] && [ "$_mk_boot" = "$_cur_boot" ] && [ "${_mk_cnt:-0}" -gt 0 ] 2>/dev/null; then
      echo "VICTIM_GUARD=waiting unproven=$_mk_cnt (parked plant is repairing)"
      _cleared=0
      for _w in $(seq 1 30); do
        [ -f "$UNPROVEN" ] || { _cleared=1; break; }
        _mk2=$(cat "$UNPROVEN" 2>/dev/null | awk '{print $2}')
        [ "${_mk2:-0}" = "0" ] && { _cleared=1; break; }
        sleep 1
      done
      if [ "$_cleared" != "1" ]; then
        echo "VICTIM_GUARD=warn unproven=$_mk_cnt"
        echo "HINT=unresolved timer-UAF zombies may exist; a zygote restart can panic the kernel (user override)"
      fi
      echo "VICTIM_GUARD=cleared (victims reaped)"
    else
      echo "VICTIM_GUARD=stale_marker_removed boot=$_mk_boot cur=$_cur_boot"
      rm -f "$UNPROVEN" 2>/dev/null || true
    fi
  fi

  # A fresh zygote/system_server is required for the bridge; ctl.restart
  # zygote can leave stale state and kill the just-started daemon.
  ZPID=$(ps -A -o PID,NAME 2>/dev/null | grep 'zygote64' | awk '{print $1}' | head -1)
  echo "KILL_ZYGOTE64=$ZPID"
  kill -9 "$ZPID"
  for i in $(seq 1 15); do
    sleep 1
    if [ -n "$OLD_SS" ] && ! kill -0 "$OLD_SS" 2>/dev/null; then
      echo "OLD_SS_DEAD=${i}s"
      break
    fi
  done

  NEW_SS=""
  for i in $(seq 1 30); do
    sleep 1
    _ss=$(ps -A -o PID,NAME 2>/dev/null | grep 'system_server' | awk '{print $1}' | head -1)
    if [ -n "$_ss" ] && [ "$_ss" != "$OLD_SS" ]; then
      NEW_SS="$_ss"
      echo "NEW_SYSTEM_SERVER=$NEW_SS (${i}s)"
      break
    fi
  done
  if [ -z "$NEW_SS" ]; then
    echo "ERROR=new_system_server_timeout"
    echo "DONE"
    exit 7
  fi

  # Wait for the actual LSPosed bridge, not merely for the process to exist.
  BRIDGE_OK=""
  for i in $(seq 1 60); do
    sleep 1
    LATEST=$(ls -t "$LOGDIR"/verbose_*.log 2>/dev/null | head -1)
    if [ -n "$LATEST" ]; then
      BRIDGE_OK=$(grep 'binder received' "$LATEST" 2>/dev/null | grep "$NEW_SS" | tail -1)
      if [ -n "$BRIDGE_OK" ]; then
        echo "BRIDGE_OK=${i}s $BRIDGE_OK"
        break
      fi
    fi
    if [ $((i % 10)) -eq 0 ]; then
      echo "WAIT_BRIDGE=${i}s lspd=$(ps -A -o PID,NAME 2>/dev/null | grep -E '(^| )lspd($| )' | awk '{print $1}' | head -1)"
    fi
  done

  # Reference fallback: restart system_server if the first zygote fork did not
  # deliver the LSPosed binder.
  if [ -z "$BRIDGE_OK" ]; then
    echo "BRIDGE_FALLBACK=kill_system_server $NEW_SS"
    kill -9 "$NEW_SS" 2>/dev/null
    SS2=""
    for i in $(seq 1 20); do
      sleep 1
      _ss=$(ps -A -o PID,NAME 2>/dev/null | grep 'system_server' | awk '{print $1}' | head -1)
      if [ -n "$_ss" ] && [ "$_ss" != "$NEW_SS" ]; then
        SS2="$_ss"
        echo "NEW_SYSTEM_SERVER_2=$SS2 (${i}s)"
        break
      fi
    done
    if [ -n "$SS2" ]; then
      for i in $(seq 1 30); do
        sleep 1
        LATEST=$(ls -t "$LOGDIR"/verbose_*.log 2>/dev/null | head -1)
        if [ -n "$LATEST" ]; then
          BRIDGE_OK=$(grep 'binder received' "$LATEST" 2>/dev/null | grep "$SS2" | tail -1)
          if [ -n "$BRIDGE_OK" ]; then
            echo "BRIDGE_OK_FALLBACK=${i}s $BRIDGE_OK"
            NEW_SS="$SS2"
            break
          fi
        fi
      done
    fi
  fi

  sleep 3
  chmod 644 /data/adb/lspd/monitor 2>/dev/null
  LSPD_PID=$(ps -A -o PID,NAME 2>/dev/null | grep -E '(^| )lspd($| )' | awk '{print $1}' | head -1)
  MONITOR=$(cat /data/adb/lspd/monitor 2>/dev/null)
  echo "FINAL_LSPD=${LSPD_PID:-none}"
  echo "FINAL_SYSTEM_SERVER=${NEW_SS:-none}"
  echo "LSPD_MONITOR=${MONITOR:-empty}"
  [ -n "$MONITOR" ] && echo "LSPD_SERVICE=$(service check "$MONITOR" 2>/dev/null | head -1)"
  if [ -x "$MODDIR/lspctl" ]; then
    echo "LSPOSED_STATUS_BEGIN"
    "$MODDIR/lspctl" status 2>&1 || true
    echo "LSPOSED_STATUS_END"
  fi

  ZN_OK=1
  if [ "$ZN_ACTIVE" = "1" ] && [ -d "$ZYGISKDIR" ]; then
    ZN_PID=$(zn_daemon_pid)
    if [ -f "$ZN_STATE_DIR/.magic" ]; then ZN_MAGIC=present; else ZN_MAGIC=missing; fi
    ZN_OK=0
    if [ -n "$ZN_PID" ] && [ -f "$ZN_STATE_DIR/.magic" ]; then
      ZN_OK=1
    elif [ -f "$ZN_STATE_DIR/.magic" ] && [ -f "$ZN_STATE_DIR/modules_info" ] &&
         [ ! -f "$ZN_STATE_DIR/.abort_msg" ]; then
      # Zygisk Next 1.5.x attaches to init and exits by design; a consumed
      # magic plus modules_info is a finished injection, not a dead daemon.
      ZN_OK=1
    fi
    echo "FINAL_ZYGISK_NEXT=ok=$ZN_OK pid=${ZN_PID:-none} magic=$ZN_MAGIC"
  elif [ "$ZN_ACTIVE" != "1" ]; then
    echo "FINAL_ZYGISK_NEXT=skipped reason=provider_not_zygisksu"
  fi

  if [ -n "$BRIDGE_OK" ] && [ -n "$LSPD_PID" ] && [ "$ZN_OK" = "1" ]; then
    echo "SOFT_REBOOT_REPAIR=ok reason=lspd_env_and_fresh_system_server"
  else
    echo "SOFT_REBOOT_REPAIR=partial reason=bridge_lspd_or_zygisk_next_missing"
  fi
  echo "=== END $(date)"
  echo "DONE"
} >> "$LOG" 2>&1

exit 0
