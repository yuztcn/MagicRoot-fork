# STP / Parallel Space fix toolkit (1.0.6)

Verified flow (MLY-AN00, 6.12.58, no KSU/su):

1. push verified binaries:
   adb push exploit-direct3-61258 /data/local/tmp/magic/98260/exploit-direct3
   adb push pc98260-su-61258 /data/local/tmp/magic/98260/pc98260-su
   adb push stpclear /data/local/tmp/stpclear
2. run rootd-only:
   cd /data/local/tmp/magic/98260
   (PC98260_MAX_ATTEMPTS=12 PC98260_NO_FALLBACK=1 PC98260_BUDGET_S=180 \
    PC98260_WAIT_CAP_S=8 PC98260_CHURN_ROUNDS=8 PC98260_CHURN_PER_CPU=32 \
    setsid ./exploit-direct3 > repro.log 2>&1 < /dev/null &)
   wait for /data/local/tmp/pc98260-root.sock
3. clear STP:
   /data/local/tmp/magic/98260/pc98260-su -c "!/data/local/tmp/stpclear"
   expected: StpClearStatus=0
4. open Parallel Space and create; no Root dialog.

The 1.0.6 APK also ships assets/98260/stpclear and run.sh invokes it after a successful 98260 chain. The KSU path was not the verified path; rootd-only was verified. Never modify /system or /vendor.
