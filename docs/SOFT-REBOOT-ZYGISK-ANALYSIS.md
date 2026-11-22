# Soft reboot repair / Zygisk module loading analysis

## Symptom

Tools → 软重启修复 could restart the UI but Zygisk/LSPosed did not become
active.  The old hotfix reported a bridge timeout or left `lspd` dead after
`ctl.restart zygote`.

## Evidence

The successful 2026-10-31 run on MLY-AN00 6.12.58 (`e5d0d260-30e5-45ee-a211-c229e00772ac`)
used only:

```sh
ksud post-fs-data
ksud services
setprop ctl.restart zygote
```

Evidence:

```text
release-lsposed-complete-2026-10-31/LSPOSED-COMPLETE.md
release-lsposed-complete-2026-10-31/modules-zygote.sh
release-lsposed-complete-2026-10-31/evidence/manager-active.txt
release-lsposed-complete-2026-10-31/evidence/modules.log
release-lsposed-complete-2026-10-31/evidence/verbose-tail.log
```

After that path, the report records:

```text
lspd         running
zn-daemon    running
zn-nsdaemon-zygote
zn-zygisk-companion64 zygisk_lsposed
manager      已激活 / API 102
```

The old app hotfix (`lsposed-hotfix.sh` v8) instead did:

```text
kill lspd
start zygiskd daemon
start zygiskd service-stage
start lspd manually with nsenter
setprop ctl.restart zygote
```

## Root cause

Zygisk Next and LSPosed are KSU modules whose startup is owned by their
`post-fs-data.sh` / `service.sh` hooks.  The old hotfix bypassed that lifecycle
and started `zygiskd` and `lspd` by hand against the **old** zygote before the
restart.  Those processes were then orphaned or stale when `ctl.restart zygote`
created a new zygote/system_server, so the fresh Zygisk instance never formed
the LSPosed bridge.  Running `ksud` stages in the wrapper did not help because
the immediately following manual zygiskd/lspd launch raced and replaced the
module-managed state.

The successful report explicitly says not to call `ksud soft-reboot`; the
working path is module lifecycle + `ctl.restart zygote`, without manual daemon
launch.

## Fix

`main/app/assets/lsposed-hotfix.sh` is now the module-lifecycle path:

```text
optional LSPosed manager install
ksud post-fs-data
ksud services
setprop ctl.restart zygote
wait for new system_server
verify lspd + zygisk process
```

No `kill lspd`, no manual `zygiskd daemon/service-stage`, no manual `lspd`.
`soft-reboot-root.sh` is only a root wrapper for the hotfix; `ksud` selection
lives in the hotfix.

Expected markers:

```text
KSUD=/data/local/tmp/magic/ksud_...
POST_FS_DATA_RC=0
SERVICES_RC=0
NEW_SYSTEM_SERVER=...
LSPOSED_LSPD=...
ZYGISK_PROCESS=...
SOFT_REBOOT_REPAIR=ok reason=module_lifecycle_and_zygote_restart
DONE
```

If `SOFT_REBOOT_REPAIR=partial`, collect:

```sh
cat /data/local/tmp/magic/lsposed-hotfix-tool.log
dmesg | tail -300
```

and reboot before retrying.
