# LSPosed 7938 / soft-reboot analysis

Reference zip analyzed:

```text
LSPosed-v2.2.1-7938-release(1).zip
module version v2.2.1 (7938)
```

It contains the same architecture as the installed 7937 build:

```text
daemon          lspd          lspctl       service.sh
manager.apk     framework.dex zygisk/*.so  libpreload*.so
emulated-soft-reboot.sh
```

`emulated-soft-reboot.sh` is only:

```sh
MODDIR=${0%/*}
"$MODDIR/lspctl" stop --emulated-soft-reboot
```

## Observed failure on the test device

Before the fix, the installed module was 7937 and the hotfix only ran:

```text
ksud post-fs-data
ksud services
setprop ctl.restart zygote
```

After the zygote restart:

```text
lspctl status
LSPosed 2.2.1 (7937)
API: 102
System server: not connected
```

The old LSPosed daemon survived the zygote restart with a stale system_server
bridge.  Restarting zygote alone does not make that daemon reconnect.

## Fix

`lsposed-hotfix.sh` now performs:

1. Invoke `emulated-soft-reboot.sh` / `lspctl stop --emulated-soft-reboot` before
   restarting zygote, so the stale daemon is stopped.
2. Run `ksud post-fs-data` and `ksud services`.
3. Restart zygote.
4. Run `ksud services` again after the new system_server appears.
5. If `lspd` is still absent, run the module `service.sh` once more.
6. Log `lspctl status` for verification.

The repair path intentionally does **not** install the LSPosed manager APK.

The selected manager's `ksud` is preferred over a stale `/data/adb/ksud`.

## Version note

7938 is the minimum recommended module for this soft-reboot path.  A module
update placed under `/data/adb/modules_update` requires a normal reboot to
activate; a cold reboot invalidates temporary root, so the update must be
followed by re-rooting.  The app can only use the emulated hook when the
installed module already contains it.

The app itself does not bundle the 6 MB LSPosed module.

## Reference module analysis

Reference: `热重启修复Zygisk和Lsp.zip` (`m_rcq` 1.4.8, KSU temporary-root only).

Its `bin/fix_lspd.sh` does not rely on the LSPosed `service.sh` environment:

1. Kill the stale `lspd`.
2. Read `BOOTCLASSPATH` / `DEX2OATBOOTCLASSPATH` from the running
   `zygote64` process.
3. Restart `zygiskd` only if `/data/adb/modules/zygisksu` exists.
4. Clear `/data/adb/lspd/monitor` and `lock`.
5. Start `lspd` through
   `setsid nsenter -t 1 -m app_process ... --nice-name=lspd`.
6. Kill `zygote64`, wait for the new `system_server`.
7. Wait for `binder received` for the new system_server PID in
   `/data/adb/lspd/log/verbose_*.log`.
8. If the bridge is still missing, kill `system_server` once so zygote forks a
   replacement.
9. Verify `monitor` and `service check`.

This explains why the module lifecycle + `ctl.restart zygote` path could load
other Zygisk/KSU modules but never LSPosed: the module `service.sh` starts
`lspd` without the zygote runtime environment, and `lspd` then cannot form the
system_server bridge.

Our `lsposed-hotfix.sh` v10 adopts this flow.  It intentionally keeps the
LSPosed manager uninstalled.  `zygiskd` restart remains optional and is skipped
on this device because it uses YukiZygisk rather than a `zygisksu` module.

## 2026-11-02 hotfix verification

`runSoftRebootRepair` now creates `/data/local/tmp/magic` before opening the
log redirect.  The previous failure was:

```text
can't create /data/local/tmp/magic/lsposed-hotfix-tool.log: No such file or directory
```

After auto-clean removed WORK, the shell never executed the repair script.

Verified log after the fix:

```text
KSUD=/data/adb/ksud
LSPOSED_MODULE_VERSION=version=v2.2.1 (7938)
POST_FS_DATA_RC=0
SERVICES_RC=0
KILL_OLD_LSPD=...
LSPD_STARTED=23337
NEW_SYSTEM_SERVER=23767
BRIDGE_OK=4s binder received
LSPosed 2.2.1 (7938)
System server: connected
Modules: 3 installed, 2 enabled user states
SOFT_REBOOT_REPAIR=ok reason=lspd_env_and_fresh_system_server
```

The repair is now effective; it does not call `ksud soft-reboot`.

## 2026-11-08 lspd slow-start false failure

Root-side evidence from LSPosed 7939 showed that the script reached the manual
launch stage but stopped before the zygote restart:

```text
OLD_SYSTEM_SERVER=3238
ERROR=lspd_start_failed
DONE
```

The old code slept for exactly three seconds and then searched `ps` for the
name `lspd`.  During that window the process can still be named `app_process`;
`--nice-name=lspd` is applied only after ART/Java startup.  The old launch also
redirected all diagnostics to `/dev/null`, making a slow start indistinguishable
from a real crash.

`lsposed-hotfix.sh` v11 now:

1. records the launcher PID and captures stdout/stderr in
   `/data/local/tmp/magic/lsposed-hotfix-tool.log.launch`;
2. polls the exact `lspd` process name for up to 20 seconds;
3. retains the existing post-start liveness check and prints the last 40 launch
   log lines if startup or liveness fails.

A regression test executes the real shell helpers with `ps` reporting
`app_process` for four seconds before `lspd`; this fails the old three-second
contract and passes the polling implementation.  Android `/system/bin/sh`
syntax and the final helper against the live daemon were also verified.

The instrumented repair run restarted zygote/system_server and ended the
current terminal session.  Afterwards the device had a new lspd/zygote/
system_server set (24354/24446/24785) and `lspctl status` reported:

```text
LSPosed 2.2.1 (7939)
System server: connected
Modules: 4 installed, 3 enabled user states
```

The final v11 script was not used to trigger a second zygote restart, avoiding
another terminal interruption.  No `ksud soft-reboot` was called and the
PPID=1 exploit parent was not killed.

## 2026-11-08 remove MagicRoot-supplied SELinux rules

The earlier Zygisk Next repair bundled the official 1.5.3 `sepolicy.rule` and
restored it when the installed module copy was missing.  Its
`allow system_server system_server process execmem` rule is a real live-policy
change and was visible to policy scanners.

v12 removes that asset and all App/hotfix restoration plumbing.  MagicRoot now
uses only the installed module's own existing `sepolicy.rule`.  If it is absent,
the hotfix logs `ZYGISK_SEPOLICY=missing reason=module_rule_required`, skips
zygiskd startup and leaves the incomplete module disabled.  Existing KSU,
LSPosed or Zygisk module policies are not removed or rewritten by this change;
already-injected live policy still requires a normal reboot to clear.

The v11 device results above are historical and are not claimed as a new v12
zygote-reboot test.
