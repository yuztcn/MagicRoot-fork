#!/system/bin/sh
# Readiness must prove a usable daemon, rather than match an old log line.
timeout 5 /data/local/tmp/ic98260/pc98260_su -c id 2>/dev/null |
    grep -q 'uid=0(root) gid=0(root)' && echo READY
