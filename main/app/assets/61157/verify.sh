#!/system/bin/sh
echo ID:
id
echo UIDLINE:
grep -E "Uid:|Gid:" /proc/self/status
echo CAPS:
grep -E "CapEff|CapPrm|CapBnd|CapAmb" /proc/self/status
echo SELINUX:
getenforce
echo CMD:
cat /proc/self/cmdline
echo UNKILLABLE:
ls -ld /data/adb 2>&1
echo ROOTFS:
ls /data/local/tmp/pc98260-root.sock
