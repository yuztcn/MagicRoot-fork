#!/system/bin/sh
# Stop only the parked 98260 rootd listener child and remove its sockets.
# The PPID=1 exploit parent is deliberately preserved until reboot: killing
# or reaping it can trip posix_cpu_timers_exit and panic the kernel.
set -u
D=/data/local/tmp/magic
S1=/data/local/tmp/pc98260-root.sock
S2=/data/local/tmp/pc98260-root2.sock
LOG=$D/rootd-stop.log
mkdir -p "$D" 2>/dev/null || true
: > "$LOG" 2>/dev/null || true

log() {
    printf '%s\n' "$*"
    printf '%s\n' "$*" >> "$LOG" 2>/dev/null || true
}

rm -f "$D/.keep-rootd" "$D/.keep-rootd-user" "$D/.h1c-rootd-only" 2>/dev/null || true
log "ROOTD_STOP_BEGIN"

killed=0
parent_kept=0
found=0

for sock in "$S1" "$S2" /data/local/tmp/cve98260-h1c-*.sock; do
    [ -S "$sock" ] || continue
    inode=$(awk -v p="$sock" '$8 == p { print $7; exit }' /proc/net/unix 2>/dev/null)
    [ -n "$inode" ] || continue
    found=1
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        [ "$pid" = "$$" ] && continue
        for fd in "$p"/fd/*; do
            link=$(readlink "$fd" 2>/dev/null) || continue
            case "$link" in
                *"socket:[$inode]"*)
                    ppid=$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)
                    comm=$(cat "$p/comm" 2>/dev/null)
                    if [ "$ppid" = "1" ]; then
                        log "ROOTD_PARENT_KEPT=$pid PPID=1 COMM=$comm"
                        parent_kept=1
                    else
                        log "ROOTD_STOP_PID=$pid PPID=${ppid:-?} COMM=$comm"
                        kill -9 "$pid" 2>/dev/null
                        rc=$?
                        log "ROOTD_STOP_KILL_RC=$rc"
                        [ "$rc" = "0" ] && killed=1
                    fi
                    ;;
            esac
        done
    done
done

# The socket may already have been unlinked.  In that case find the PPID=1
# exploit parent and kill only its exploit/rootd child.
if [ "$found" = "0" ]; then
    for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        comm=$(cat "$p/comm" 2>/dev/null)
        case "$comm" in
            exploit-android-key-ptr|cve98260_plant) ;;
            *) continue ;;
        esac
        ppid=$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)
        [ "$ppid" = "1" ] || continue
        log "ROOTD_PARENT_KEPT=$pid PPID=1 COMM=$comm"
        parent_kept=1
        for c in /proc/[0-9]*; do
            cpid=${c#/proc/}
            [ "$cpid" = "$$" ] && continue
            ccomm=$(cat "$c/comm" 2>/dev/null)
            case "$ccomm" in
                *exploit*|*rootd*|cve98260_plant) ;;
                *) continue ;;
            esac
            cppid=$(awk '/^PPid:/{print $2}' "$c/status" 2>/dev/null)
            if [ "$cppid" = "$pid" ]; then
                log "ROOTD_STOP_PID=$cpid PPID=$cppid PARENT=$pid COMM=$ccomm"
                kill -9 "$cpid" 2>/dev/null
                rc=$?
                log "ROOTD_STOP_KILL_RC=$rc"
                [ "$rc" = "0" ] && killed=1
            fi
        done
    done
fi

rm -f "$S1" "$S2" /data/local/tmp/cve98260-h1c-*.sock 2>/dev/null || true
_h1c_left=0
for _h1c_sock in /data/local/tmp/cve98260-h1c-*.sock; do
    [ -S "$_h1c_sock" ] && _h1c_left=1
done
if [ -S "$S1" ] || [ -S "$S2" ] || [ "$_h1c_left" = "1" ]; then
    log "ROOTD_SOCK_REMOVE=fail"
else
    log "ROOTD_SOCK_REMOVE=ok"
fi
log "ROOTD_STOP_DONE killed=$killed parent_kept=$parent_kept"
exit 0
