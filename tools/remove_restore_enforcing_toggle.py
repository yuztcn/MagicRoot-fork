from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")


def patch(path: Path, old: str, new: str, label: str):
    t = path.read_text(encoding="utf-8")
    if old not in t:
        raise SystemExit(f"anchor missing: {label}")
    path.write_text(t.replace(old, new, 1), encoding="utf-8", newline="\n")
    print("patched", label)


# UiState: remove restoreEnforcing state/prefs/setter.
p = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/UiState.kt"
patch(p, '''    private val enforcingPrefs = context.getSharedPreferences("magicroot_restore_enforcing", Context.MODE_PRIVATE)
    var restoreEnforcing by mutableStateOf(enforcingPrefs.getBoolean("enabled", true))
        private set
''', '', "UiState restoreEnforcing state")
patch(p, '''    fun updateRestoreEnforcing(value: Boolean) {
        restoreEnforcing = value
        enforcingPrefs.edit().putBoolean("enabled", value).apply()
    }

''', '', "UiState restoreEnforcing setter")

# MiuixHost: remove the restore SELinux toggle row.
p = WS / "main/compose-app/app/src/main/kotlin/com/aoki/magicroot/MiuixHost.kt"
patch(p, '''            CompactToggle(
                title = "恢复 SELinux",
                subtitle = "提权后恢复 Enforcing",
                checked = state.restoreEnforcing,
                enabled = !state.busy && !state.running,
                onCheckedChange = { state.updateRestoreEnforcing(it) },
            )
''', '', "MiuixHost restore SELinux toggle")

# MainActivity: drop the option and always let root_stage restore Enforcing.
p = WS / "main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java"
patch(p, '''        final boolean repair = ui.getSoftRebootRepair();
        final boolean restoreEnforcing = ui.getRestoreEnforcing();''',
'''        final boolean repair = ui.getSoftRebootRepair();''',
      "MainActivity restore field")
patch(p, '''        log("软重启修复: " + (repair ? "开启（管理器未连接时 15s 后重启 framework）" : "关闭"));
        log("恢复 SELinux 强制: " + (restoreEnforcing ? "开启" : "关闭（保持 permissive）"));''',
'''        log("软重启修复: " + (repair ? "开启（管理器未连接时 15s 后重启 framework）" : "关闭"));
        log("SELinux: 提权结束后默认恢复 Enforcing");''',
      "MainActivity restore log")
patch(p, '''        new Thread(() -> runChain(suCompat, suOverlay, allowShell, selinuxHide, kernelUmount,
                ksuFlavor, repair, restoreEnforcing, skipFsuid, vPerm, vFsuid, vCred)).start();''',
'''        new Thread(() -> runChain(suCompat, suOverlay, allowShell, selinuxHide, kernelUmount,
                ksuFlavor, repair, skipFsuid, vPerm, vFsuid, vCred)).start();''',
      "MainActivity runChain call")
patch(p, '''                           String ksuFlavor, boolean repair,
                           boolean restoreEnforcing, boolean skipFsuid,
                           int vPerm, int vFsuid, int vCred) {''',
'''                           String ksuFlavor, boolean repair,
                           boolean skipFsuid,
                           int vPerm, int vFsuid, int vCred) {''',
      "MainActivity runChain signature")
patch(p, '''            if (!restoreEnforcing)
                shell("touch " + WORK + "/no_restore_enforcing");
            else
                shell("rm -f " + WORK + "/no_restore_enforcing");
''', '', "MainActivity restore marker")
patch(p, '''                    + " MAGICROOT_REPAIR=" + (repair ? "1" : "0")
                    + " MAGICROOT_RESTORE_ENFORCING=" + (restoreEnforcing ? "1" : "0") + " ";''',
'''                    + " MAGICROOT_REPAIR=" + (repair ? "1" : "0") + " ";''',
      "MainActivity restore env")

# root_stage: unconditional Enforcing restore; remove env/marker override.
p = WS / "main/app/assets/root_stage.sh"
patch(p, '''RESTORE_ENF=${MAGICROOT_RESTORE_ENFORCING:-1}
[ -f "$D/no_restore_enforcing" ] && RESTORE_ENF=0
case "$RESTORE_ENF" in 0) ;; *) RESTORE_ENF=1 ;; esac
''', '', "root_stage RESTORE_ENF parse")
patch(p, '''log "ROOT_STAGE_FLAVOR=$FLAVOR manager=$MGR label=$MANAGER_LABEL ksud_src=$KSUD_SRC repair=$REPAIR restore_enforcing=$RESTORE_ENF"''',
'''log "ROOT_STAGE_FLAVOR=$FLAVOR manager=$MGR label=$MANAGER_LABEL ksud_src=$KSUD_SRC repair=$REPAIR"''',
      "root_stage RESTORE_ENF log")
patch(p, '''# SELinux restore (reference root_stage_v24.sh does `setenforce 1` here).
if [ "$RESTORE_ENF" = "1" ] && [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
    setenforce 1 2>/dev/null && echo "ROOT_STAGE_SELINUX=restored_enforcing" \\
                             || echo "ROOT_STAGE_SELINUX=restore_failed"
else
    echo "ROOT_STAGE_SELINUX=$(getenforce 2>/dev/null || echo unknown)"
fi''',
'''# SELinux is always restored to Enforcing after the temporary permissive phase.
if [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
    setenforce 1 2>/dev/null && echo "ROOT_STAGE_SELINUX=restored_enforcing" \\
                             || echo "ROOT_STAGE_SELINUX=restore_failed"
else
    echo "ROOT_STAGE_SELINUX=$(getenforce 2>/dev/null || echo unknown)"
fi''',
      "root_stage unconditional enforcing")

print("restore-SELinux toggle removal complete")
