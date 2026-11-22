package com.aoki.magicroot

import android.content.Context
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File

val MATERIAL_PALETTES = setOf(
    "monochrome", "neutral", "tonal", "vibrant", "expressive",
    "fidelity", "content", "rainbow", "fruit",
)

/**
 * Compose-owned UI state. The existing Shizuku controller stays in Java;
 * this object only carries observable state and persisted options.
 */
class UiState(context: Context) {
    private val victimPrefs = context.getSharedPreferences("magicroot_victims", Context.MODE_PRIVATE)
    private val skipPrefs = context.getSharedPreferences("magicroot_skip_fsuid_radio_v2", Context.MODE_PRIVATE)
    private val compatPrefs = context.getSharedPreferences("magicroot_su_compat", Context.MODE_PRIVATE)
    private val chainPrefs = context.getSharedPreferences("magicroot_chain", Context.MODE_PRIVATE)
    private val chain98260DefaultMigrated = chainPrefs.getBoolean("default_98260_migrated", false)
    private val runtime60Prefs = context.getSharedPreferences("magicroot_98260_runtime", Context.MODE_PRIVATE)
    private val preflightSkipPrefs = context.getSharedPreferences("magicroot_preflight_skip", Context.MODE_PRIVATE)
    private val uiPrefs = context.getSharedPreferences("magicroot_ui", Context.MODE_PRIVATE)
    private val setupPrefs = context.getSharedPreferences("magicroot_setup", Context.MODE_PRIVATE)

    var mainTab by mutableIntStateOf(uiPrefs.getInt("tab", 0).coerceIn(0, 2))
        private set
    /** system / light / dark */
    var themeMode by mutableStateOf(
        (uiPrefs.getString("theme_mode", "system") ?: "system")
            .takeIf { it in setOf("system", "light", "dark") } ?: "system"
    )
        private set
    /** Material 3 Monet dynamic color (system wallpaper palette). */
    var dynamicColor by mutableStateOf(uiPrefs.getBoolean("dynamic_color", false))
        private set
    /** Express / jade / violet / sunset / rose / graphite / custom. */
    var accentColor by mutableStateOf(
        (uiPrefs.getString("accent_color", "express") ?: "express")
            .takeIf { it in setOf("express", "jade", "violet", "sunset", "rose", "graphite", "custom") }
            ?: "express"
    )
        private set
    /** ARGB int used when accentColor == custom. */
    var customAccent by mutableStateOf(uiPrefs.getInt("custom_accent", 0xFF3D7EFF.toInt()))
        private set
    /** M3 2021 has all nine variants; M3 2025 exposes four. */
    var colorSpec by mutableStateOf(
        (uiPrefs.getString("color_spec", "2021") ?: "2021")
            .takeIf { it in setOf("2021", "2025") } ?: "2021"
    )
        private set
    var paletteStyle by mutableStateOf(
        (uiPrefs.getString("palette_style", "tonal") ?: "tonal")
            .takeIf { it in MATERIAL_PALETTES } ?: "tonal"
    )
        private set
    var glassBottomBar by mutableStateOf(uiPrefs.getBoolean("glass_bottom_bar", true))
        private set
    var managerSource by mutableStateOf("installed")
        private set
    var managerPkgOverride by mutableStateOf(uiPrefs.getString("manager_pkg", "") ?: "")
        private set
    var resolvedManagerPkg by mutableStateOf("")
        private set
    var installedManagers by mutableStateOf<List<ManagerInfo>>(emptyList())
        private set
    var installedApps by mutableStateOf<List<AppEntry>>(emptyList())
        private set
    var deviceStatus by mutableStateOf(DeviceStatus())
    var rootDiagnostic by mutableStateOf<RootDiagnostic?>(null)
        private set
    var diagnosticBusy by mutableStateOf(false)
        private set
    var diagnosticSummary by mutableStateOf("")
        private set
    var versionTapCount by mutableIntStateOf(0)
        private set
    var eggUnlocked by mutableStateOf(uiPrefs.getBoolean("egg_unlocked", false))
        private set
    private var versionTapFirstAt = 0L

    var showFullLog by mutableStateOf(false)
    /**
     * Home flow step (0=授权 … 5=提权).  Hoisted out of HomePage's remember{}
     * so opening the fullscreen log (which removes HomePage from composition)
     * or switching tabs does not silently jump the user back to step 0 and
     * hide the live run progress.
     */
    var homeStep by mutableIntStateOf(0)
    /** Inline run-log panel expansion on the home page; survives the same
     *  composition changes as [homeStep]. */
    var homeShowLog by mutableStateOf(false)
    var busy by mutableStateOf(false)
    var running by mutableStateOf(false)
    var logText by mutableStateOf("")
    var status by mutableStateOf("等待部署")
    /** True after the current assets were deployed successfully in this session. */
    var assetsDeployed by mutableStateOf(false)
    /** True after at least one successful setup; enables the one-click root shortcut. */
    var oneClickAvailable by mutableStateOf(setupPrefs.getBoolean("ready", false))
        private set
    /** null=not run, true=last run success, false=last run failed. */
    var runResult by mutableStateOf<Boolean?>(null)
        private set
    /** null = normal run; true/false = read-only 98260 preflight result. */
    var preflightPassed by mutableStateOf<Boolean?>(null)
        private set
    /** Passive Shizuku state; updated only by binder/permission events. */
    var channelStatus by mutableStateOf("未连接")
        private set
    var managerAuth by mutableStateOf("未授权")
        private set
    var feedbackTitle by mutableStateOf("")
    var feedbackDetail by mutableStateOf("")
    // 0=info, 1=success, 2=error
    var feedbackTone by mutableIntStateOf(0)

    var showRunProgress by mutableStateOf(false)
    var runProgress by mutableIntStateOf(0)
    var runStage by mutableStateOf("")
    var runElapsedSec by mutableIntStateOf(0)
    var runStartedAt by mutableLongStateOf(0L)
    var kernelVersion by mutableStateOf(readKernelVersion())

    // Success page (shown after a successful run).  It replaces the home
    // content until the user taps 返回主页, and keeps the final elapsed time
    // plus the exported log path for the 导出日志 action.
    var showSuccess by mutableStateOf(false)
    /** Success-page log export feedback ("正在导出…", "日志已导出：…", …). */
    var exportResult by mutableStateOf("")
    var exportOk by mutableStateOf(false)

    fun setExportResult(text: String, ok: Boolean) {
        exportResult = text
        exportOk = ok
    }
    /** About page is opened from the top header card. */
    var showAbout by mutableStateOf(false)
    /** Standalone donation QR dialog. */
    var showDonation by mutableStateOf(false)
    /** Latest SuSFS LKM online-update status shown in About/Settings. */
    var susfsUpdateBusy by mutableStateOf(false)
    var susfsUpdateStatus by mutableStateOf("")
    /** Cached/imported SuSFS guard matching the current KMI, if discovered. */
    var susfsLocalModuleName by mutableStateOf("")
        private set
    var susfsLocalModuleKmi by mutableStateOf("")
        private set
    var susfsLocalModuleSource by mutableStateOf("")
        private set

    fun updateSusfsLocalModule(name: String, kmi: String, source: String) {
        susfsLocalModuleName = name
        susfsLocalModuleKmi = kmi
        susfsLocalModuleSource = source
    }

    fun clearSusfsLocalModule() {
        susfsLocalModuleName = ""
        susfsLocalModuleKmi = ""
        susfsLocalModuleSource = ""
    }
    var lastRunElapsedSec by mutableIntStateOf(0)
        private set
    var successLogPath by mutableStateOf("")
        private set

    fun openSuccess(elapsedSec: Int, logPath: String) {
        lastRunElapsedSec = elapsedSec.coerceAtLeast(0)
        successLogPath = logPath
        showSuccess = true
    }

    fun closeSuccess() {
        showSuccess = false
    }

    var victimPerm by mutableIntStateOf(validVictim(victimPrefs.getInt("permissive", 32), 32))
        private set
    var victimFsuid by mutableIntStateOf(validVictim(victimPrefs.getInt("fsuid", 32), 32))
        private set
    var victimCred by mutableIntStateOf(validCredVictim(victimPrefs.getInt("cred_24", 24), 24))
        private set

    var suCompat by mutableStateOf(defaultOnCompatPref(compatPrefs))
        private set
    // PMX v1.6-style su entry: kernel su_compat hooks + Termux wrapper patch.
    // Optional switch; default ON to preserve the new default path.
    private val suEntryPrefs = context.getSharedPreferences("magicroot_su_entry", Context.MODE_PRIVATE)
    var suEntry by mutableStateOf(suEntryPrefs.getBoolean("enabled", false))
        private set
    // Optional SUSFS guard LKM, independent from the KSU flavor; default OFF.
    private val susfsPrefs = context.getSharedPreferences("magicroot_susfs", Context.MODE_PRIVATE)
    var susfsEnabled by mutableStateOf(susfsPrefs.getBoolean("enabled", false))
        private set
    /** Only official KernelSU has no supported SuSFS guard LKM path here. */
    val susfsSupported: Boolean
        get() = ksuFlavor != "kernelsu"
    // Temporary diagnostic override: allow a guard without the openat2/BTI
    // hardening marker.  Default false; may panic on old guards.
    var susfsAllowUnhardened by mutableStateOf(susfsPrefs.getBoolean("allow_unhardened", false))
        private set
    // Protection mode: finish root/KSU first, then load the SuSFS guard.  This
    // keeps the guard LKM out of the UAF/cred-reclaim window.
    var susfsProtectMode by mutableStateOf(susfsPrefs.getBoolean("protect_mode", true))
        private set
    private val allowShellPrefs = context.getSharedPreferences("magicroot_allow_shell", Context.MODE_PRIVATE)
    private val allowShellDefaultMigrated = allowShellPrefs.getBoolean("default_on_migrated", false)
    var allowShell by mutableStateOf(
        if (allowShellDefaultMigrated) allowShellPrefs.getBoolean("enabled", true) else true
    )
        private set
    // KernelSU adb_root feature: kernel static key defaults to false, so the
    // app default stays off and the switch is an explicit opt-in.
    private val adbRootPrefs = context.getSharedPreferences("magicroot_adb_root", Context.MODE_PRIVATE)
    var adbRoot by mutableStateOf(adbRootPrefs.getBoolean("enabled", false))
        private set
    // Boot-image adaptive profile (HOneClick-style): generated locally from
    // the exact 6.18.21 kernel image; never synced from a third party.
    private val adaptivePrefs = context.getSharedPreferences("magicroot_adaptive_profile", Context.MODE_PRIVATE)
    var adaptiveProfileKernel by mutableStateOf(adaptivePrefs.getString("kernel", "") ?: "")
        private set
    var adaptiveProfileId by mutableStateOf(adaptivePrefs.getString("id", "") ?: "")
        private set
    var adaptiveProfileStatus by mutableStateOf(adaptivePrefs.getString("status", "未导入 boot.img") ?: "未导入 boot.img")
        private set
    // Default-on: after a successful run, remove the staged work directory and
    // rootd socket when the KernelSU root path is available.  Users can keep
    // the staging area for debugging or for the rootd-only fallback.
    private val autoCleanPrefs = context.getSharedPreferences("magicroot_auto_clean", Context.MODE_PRIVATE)
    var autoCleanTemp by mutableStateOf(autoCleanPrefs.getBoolean("enabled", true))
        private set
    // STP workflow: keep the rootd listener/socket after a successful 98260
    // run so full-cap stpclear can still reach libstp/hisecd.  Default off;
    // the Tools action can stop rootd and clean sockets when done.
    private val keepRootdPrefs = context.getSharedPreferences("magicroot_keep_rootd", Context.MODE_PRIVATE)
    var keepRootdForStp by mutableStateOf(keepRootdPrefs.getBoolean("enabled", false))
        private set
    // First run-option/parameter modification is confirmed explicitly.  This
    // prevents a stray tap from changing the exploit chain, while allowing the
    // user to opt out of the hint permanently.
    private val optionsWarnPrefs = context.getSharedPreferences("magicroot_options_warning", Context.MODE_PRIVATE)
    var optionsChangeAcknowledged by mutableStateOf(optionsWarnPrefs.getBoolean("acknowledged", false))
        private set
    var optionsChangeDontShow by mutableStateOf(optionsWarnPrefs.getBoolean("dont_show", false))
        private set
    var showOptionsWarning by mutableStateOf(false)
        private set
    private var pendingOptionsAction: (() -> Unit)? = null

    init {
        // One-time migration: older builds persisted false as the default.
        // The user asked for allow_shell to be ON by default; override that
        // stale preference once, then respect later user changes.
        if (!allowShellDefaultMigrated) {
            allowShellPrefs.edit()
                .putBoolean("enabled", true)
                .putBoolean("default_on_migrated", true)
                .apply()
        }
        if (!chain98260DefaultMigrated) {
            chainPrefs.edit()
                .putString("chain", "98260")
                .putBoolean("ack_98260", true)
                .putBoolean("default_98260_migrated", true)
                .apply()
        }
    }
    // Project defaults: both KernelSU features are ON.  The switches below
    // intentionally override the module defaults when the user changes them.
    private val kernelUmountPrefs = context.getSharedPreferences("magicroot_kernel_umount", Context.MODE_PRIVATE)
    var kernelUmount by mutableStateOf(kernelUmountPrefs.getBoolean("enabled", true))
        private set
    private val selinuxHidePrefs = context.getSharedPreferences("magicroot_selinux_hide", Context.MODE_PRIVATE)
    var selinuxHide by mutableStateOf(selinuxHidePrefs.getBoolean("enabled", true))
        private set
    private val backendPrefs = context.getSharedPreferences("magicroot_ksu_backend", Context.MODE_PRIVATE)
    /** Active KernelSU-family backend (5 supported managers, KernelSU default). */
    var ksuFlavor by mutableStateOf(loadKsuFlavor(backendPrefs))
        private set
    val ksuManagerLabel: String get() = ksuLabelOf(ksuFlavor)
    val ksuManagerPkg: String
        get() = when {
            managerPkgOverride.isNotBlank() -> managerPkgOverride
            resolvedManagerPkg.isNotBlank() -> resolvedManagerPkg
            else -> ksuPkgOf(ksuFlavor)
        }

    fun updateResolvedManagerPkg(pkg: String) {
        resolvedManagerPkg = pkg
    }

    fun selectTab(index: Int) {
        mainTab = index.coerceIn(0, 2)
        uiPrefs.edit().putInt("tab", mainTab).apply()
    }

    fun updateThemeMode(mode: String) {
        themeMode = mode.takeIf { it in setOf("system", "light", "dark") } ?: "system"
        uiPrefs.edit().putString("theme_mode", themeMode).apply()
    }

    fun updateDynamicColor(enabled: Boolean) {
        dynamicColor = enabled
        if (!enabled && colorSpec == "2025" &&
            paletteStyle !in setOf("neutral", "tonal", "vibrant", "expressive")
        ) {
            paletteStyle = "tonal"
        }
        uiPrefs.edit()
            .putBoolean("dynamic_color", dynamicColor)
            .putString("palette_style", paletteStyle)
            .apply()
    }

    fun updateAccentColor(accent: String) {
        if (dynamicColor) return
        accentColor = accent.takeIf {
            it in setOf("express", "jade", "violet", "sunset", "rose", "graphite", "custom")
        } ?: "express"
        uiPrefs.edit().putString("accent_color", accentColor).apply()
    }

    fun updateCustomAccent(argb: Int) {
        if (dynamicColor) return
        customAccent = argb
        accentColor = "custom"
        uiPrefs.edit()
            .putInt("custom_accent", argb)
            .putString("accent_color", accentColor)
            .apply()
    }

    fun updatePaletteStyle(style: String) {
        if (dynamicColor) return
        paletteStyle = style.takeIf { it in MATERIAL_PALETTES } ?: "tonal"
        uiPrefs.edit().putString("palette_style", paletteStyle).apply()
    }

    fun updateColorSpec(spec: String) {
        colorSpec = spec.takeIf { it in setOf("2021", "2025") } ?: "2021"
        // Monet owns the palette; changing the spec must not rewrite the
        // user's saved accent/variant while dynamic color is active.
        if (!dynamicColor && colorSpec == "2025" &&
            paletteStyle !in setOf("neutral", "tonal", "vibrant", "expressive")
        ) {
            paletteStyle = "tonal"
        }
        uiPrefs.edit()
            .putString("color_spec", colorSpec)
            .putString("palette_style", paletteStyle)
            .apply()
    }

    fun updateGlassBottomBar(enabled: Boolean) {
        glassBottomBar = enabled
        uiPrefs.edit().putBoolean("glass_bottom_bar", enabled).apply()
    }

    /** Explicit reset to the documented default theme. */
    fun resetAppearance() {
        themeMode = "system"
        dynamicColor = false
        accentColor = "express"
        customAccent = 0xFF3D7EFF.toInt()
        colorSpec = "2021"
        paletteStyle = "tonal"
        glassBottomBar = true
        uiPrefs.edit()
            .putString("theme_mode", themeMode)
            .putBoolean("dynamic_color", false)
            .putString("accent_color", accentColor)
            .putInt("custom_accent", customAccent)
            .putString("color_spec", colorSpec)
            .putString("palette_style", paletteStyle)
            .putBoolean("glass_bottom_bar", true)
            .apply()
    }

    fun updateInstalledManagers(list: List<ManagerInfo>) {
        installedManagers = list
    }

    fun updateInstalledApps(list: List<AppEntry>) {
        installedApps = list
    }

    fun markSetupReady() {
        oneClickAvailable = true
        setupPrefs.edit().putBoolean("ready", true).apply()
    }

    fun markAssetsDeployed(value: Boolean) {
        assetsDeployed = value
    }

    fun chooseManagerSource(value: String) {
        // Only locally installed managers are selectable.  The bundled assets
        // remain a fallback, but are not a separate manager category.
        managerSource = "installed"
        uiPrefs.edit().putString("manager_source", managerSource).apply()
    }

    fun selectPresetManager(flavor: String) {
        // Kept for the refresh/fallback path: record a flavor but keep the
        // manager source on the installed catalog.
        managerSource = "installed"
        managerPkgOverride = ""
        assetsDeployed = false
        uiPrefs.edit().putString("manager_source", managerSource).remove("manager_pkg").apply()
        setKsuBackend(flavor)
    }

    fun selectInstalledManager(info: ManagerInfo) {
        managerSource = "installed"
        managerPkgOverride = info.pkg
        assetsDeployed = false
        uiPrefs.edit().putString("manager_source", managerSource)
            .putString("manager_pkg", info.pkg).apply()
        if (info.flavor.isNotBlank()) setKsuBackend(info.flavor)
    }

    /** Normalize a persisted explicit package after app upgrades.  Without
     *  this, an old override could keep a stale flavor (e.g. dev package with
     *  KernelSU selected) and late-load the wrong manager name. */
    fun normalizeExplicitManagerSelection() {
        val pkg = managerPkgOverride
        if (pkg.isBlank()) return
        val flavor = flavorForPackage(pkg)
        if (flavor.isNotBlank() && flavor != ksuFlavor) {
            setKsuBackend(flavor)
        }
    }

    fun selectOtherManager(pkg: String) {
        managerSource = "installed"
        managerPkgOverride = pkg
        assetsDeployed = false
        uiPrefs.edit().putString("manager_source", managerSource)
            .putString("manager_pkg", pkg).apply()
        val flavor = flavorForPackage(pkg)
        if (flavor.isNotBlank()) setKsuBackend(flavor)
    }

    /** Explicit package selection determines the backend; special builds are
     *  never inferred until the user picks that exact package. */
    private fun flavorForPackage(pkg: String): String = when {
        pkg == "me.weishu.kernelsu" || pkg.startsWith("me.weishu.kernelsu.") -> "kernelsu"
        pkg == "com.rifsxd.ksunext" || pkg.startsWith("com.rifsxd.ksunext.") -> "next"
        pkg == "com.sukisu.ultra" || pkg.startsWith("com.sukisu.ultra.") -> "sukisu"
        pkg == "com.sukisu.nova" || pkg.startsWith("com.sukisu.nova.") -> "nova"
        pkg == "dev.maplesu.manager" || pkg.startsWith("dev.maplesu.manager.") -> "maplesu"
        pkg == "me.yuki.fina" || pkg.startsWith("me.yuki.fina.") -> "fina"
        pkg == "com.resukisu.resukisu" || pkg.startsWith("com.resukisu.resukisu.") -> "resukisu"
        else -> ""
    }

    fun updateDeviceStatus(value: DeviceStatus) {
        deviceStatus = value
    }

    fun updateDiagnosticBusy(value: Boolean) {
        diagnosticBusy = value
    }

    fun updateRootDiagnostic(value: RootDiagnostic?, summary: String = "") {
        rootDiagnostic = value
        diagnosticSummary = summary
    }

    fun registerVersionTap(): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (versionTapFirstAt == 0L || now - versionTapFirstAt > 3000L) {
            versionTapFirstAt = now
            versionTapCount = 0
        }
        versionTapCount += 1
        if (versionTapCount >= 7) {
            versionTapCount = 0
            versionTapFirstAt = 0L
            if (!eggUnlocked) {
                eggUnlocked = true
                uiPrefs.edit().putBoolean("egg_unlocked", true).apply()
            }
            return true
        }
        return false
    }
    /** Legacy accessor kept for the remaining resukisu-only code paths. */
    val bakasuBackend: Boolean get() = ksuFlavor == "resukisu"
    val ksuNextLabel: String
        get() {
            val i = KSU_FLAVOR_ORDER.indexOf(ksuFlavor)
            return ksuLabelOf(KSU_FLAVOR_ORDER[(i + 1) % KSU_FLAVOR_ORDER.size])
        }
    fun setKsuBackend(flavor: String) {
        val next = normalizeKsuFlavor(flavor)
        if (next != ksuFlavor) resolvedManagerPkg = ""
        ksuFlavor = next
        assetsDeployed = false
        backendPrefs.edit().putString("flavor", next).remove("bakasu").apply()
        if (!susfsSupported && susfsEnabled) updateSusfs(false)
    }
    fun cycleKsuBackend() {
        val i = KSU_FLAVOR_ORDER.indexOf(ksuFlavor).coerceAtLeast(0)
        setKsuBackend(KSU_FLAVOR_ORDER[(i + 1) % KSU_FLAVOR_ORDER.size])
    }
    var skipFsuid by mutableStateOf(skipPrefs.getBoolean("enabled", false))
        private set
    /** PREFLIGHT restriction removed; default ON (no boot/load wait). */
    var skipPreflight by mutableStateOf(preflightSkipPrefs.getBoolean("enabled", true))
        private set

    init {
        if (susfsEnabled && !susfsSupported) updateSusfs(false)
        if (skipFsuid) {
            suCompat = false
            compatPrefs.edit().putBoolean("enabled", false).apply()
        }
    }

    // ------------------------------------------------------------------
    // Chain selection.  Default is the CVE-2026-64560 pipeline; the
    // CVE-2026-98260 chain is experimental, opt-in and requires an explicit
    // acknowledgement (warning dialog) before it can be selected.
    // ------------------------------------------------------------------
    var chain by mutableStateOf(if (chain98260DefaultMigrated) chainPrefs.getString("chain", "98260") ?: "98260" else "98260")
        private set
    var chain98260Ack by mutableStateOf(if (chain98260DefaultMigrated) chainPrefs.getBoolean("ack_98260", true) else true)
        private set
    // Read-only preflight is a debug mode: never persist it.  Every launch
    // defaults to the full H1C/98260 chain; the user can still enable it for
    // the current session.
    var chain98260Preflight by mutableStateOf(false)
        private set
    var chain98260Ksu by mutableStateOf(chainPrefs.getBoolean("ksu_98260", true))
        private set
    private val credModePrefs = context.getSharedPreferences("magicroot_cred_mode", Context.MODE_PRIVATE)
    /** 98260 write/delivery branch; the two package builds choose different defaults. */
    var credMode by mutableStateOf(
        credModePrefs.getString("mode", null)
            ?.takeIf { it == "real" || it == "fake" }
            ?: BuildConfig.CRED_MODE_DEFAULT
    )
        private set

    fun updateCredMode(value: String) {
        credMode = if (value == "fake") "fake" else "real"
        credModePrefs.edit().putString("mode", credMode).apply()
    }
    /** 6.18.21/H1C is the only engine; the legacy BRM toggle was removed. */
    val engine98260: String = "h1c"
    /** Full-page chain flow; hides the bottom navigation while active. */
    var flowMode by mutableStateOf(false)
        private set
    /** Runtime parameter panel is collapsed by default; unlock after the warning dialog. */
    var paramsExpanded by mutableStateOf(false)
        private set
    var showParamsWarning by mutableStateOf(false)
        private set
    /** 98260 parameters stay grey until this separate confirmation is enabled. */
    var editRunParams by mutableStateOf(false)
        private set
    var chain98260Attempts by mutableIntStateOf(runtime60Prefs.getInt("attempts", 12))
        private set
    var chain98260ChurnRounds by mutableIntStateOf(runtime60Prefs.getInt("churn_rounds", 8))
        private set
    var chain98260ChurnPerCpu by mutableIntStateOf(runtime60Prefs.getInt("churn_per_cpu", 256))
        private set
    var chain98260WaitCap by mutableIntStateOf(runtime60Prefs.getInt("wait_cap2", 25))
        private set
    var customKoEnabled by mutableStateOf(runtime60Prefs.getBoolean("custom_ko_enabled", false))
        private set
    var customKoPath by mutableStateOf(runtime60Prefs.getString("custom_ko_path", "") ?: "")
        private set
    val chain98260: Boolean get() = chain == "98260"

    fun openFlow() {
        flowMode = true
        paramsExpanded = false
    }

    fun closeFlow() {
        flowMode = false
    }

    fun updateChain(value: String) {
        chain = if (value == "98260") "98260" else "64560"
        if (chain == "64560") chain98260Preflight = false
        assetsDeployed = false
        chainPrefs.edit()
            .putString("chain", chain)
            .putBoolean("preflight_98260", chain98260Preflight)
            .apply()
        appendLog("链路已切换: " + chainLabelOf(chain))
    }

    /** Change the active chain. */
    fun requestChainChange(value: String) {
        updateChain(value)
    }

    fun update98260Preflight(value: Boolean) {
        chain98260Preflight = value
    }

    /** 98260 debug knob: auto late-load KernelSU after root must be opt-out. */
    fun requestExpandParams() {
        showParamsWarning = true
    }

    fun cancelExpandParams() {
        showParamsWarning = false
    }

    fun confirmExpandParams() {
        showParamsWarning = false
        paramsExpanded = true
    }

    fun expandParams() {
        paramsExpanded = true
    }

    fun collapseParams() {
        paramsExpanded = false
    }

    fun updateEditRunParams(value: Boolean) {
        editRunParams = value
    }

    fun update98260Ksu(value: Boolean) {
        chain98260Ksu = value
        chainPrefs.edit().putBoolean("ksu_98260", value).apply()
    }

    fun cycle98260Attempts() {
        chain98260Attempts = when (chain98260Attempts) { 1 -> 2; 2 -> 4; 4 -> 8; else -> 1 }
        runtime60Prefs.edit().putInt("attempts", chain98260Attempts).apply()
    }

    fun cycle98260ChurnRounds() {
        chain98260ChurnRounds = when (chain98260ChurnRounds) { 1 -> 2; 2 -> 4; 4 -> 8; else -> 1 }
        runtime60Prefs.edit().putInt("churn_rounds", chain98260ChurnRounds).apply()
    }

    fun cycle98260ChurnPerCpu() {
        chain98260ChurnPerCpu = when (chain98260ChurnPerCpu) {
            8 -> 16; 16 -> 32; 32 -> 64; 64 -> 128; 128 -> 256; else -> 8
        }
        runtime60Prefs.edit().putInt("churn_per_cpu", chain98260ChurnPerCpu).apply()
    }

    fun cycle98260WaitCap() {
        chain98260WaitCap = when (chain98260WaitCap) { 15 -> 25; 25 -> 40; else -> 15 }
        runtime60Prefs.edit().putInt("wait_cap2", chain98260WaitCap).apply()
    }

    fun updateCustomKoEnabled(value: Boolean) {
        customKoEnabled = value
        runtime60Prefs.edit().putBoolean("custom_ko_enabled", value).apply()
    }

    fun updateCustomKoPath(value: String) {
        customKoPath = value.trim().replace(" ", "")
        runtime60Prefs.edit().putString("custom_ko_path", customKoPath).apply()
    }

    fun updateVictimPerm(value: Int) {
        if (value != 16 && value != 24 && value != 32) return
        victimPerm = value
        victimPrefs.edit().putInt("permissive", value).apply()
    }

    fun updateVictimFsuid(value: Int) {
        if (value != 16 && value != 24 && value != 32) return
        victimFsuid = value
        victimPrefs.edit().putInt("fsuid", value).apply()
    }

    fun updateVictimCred(value: Int) {
        if (value != 8 && value != 12 && value != 16 && value != 24 && value != 32) return
        victimCred = value
        victimPrefs.edit().putInt("cred_24", value).apply()
    }

    fun cyclePerm() {
        updateVictimPerm(when (victimPerm) {
            16 -> 24
            24 -> 32
            else -> 16
        })
    }

    fun cycleFsuid() {
        updateVictimFsuid(when (victimFsuid) {
            16 -> 24
            24 -> 32
            else -> 16
        })
    }

    fun cycleCred() {
        updateVictimCred(when (victimCred) {
            8 -> 12
            12 -> 16
            16 -> 24
            24 -> 32
            else -> 8
        })
    }


    fun updateSkipFsuid(value: Boolean) {
        skipFsuid = value
        skipPrefs.edit().putBoolean("enabled", value).apply()
        if (value) {
            // Mutually exclusive with the KernelSU su path: fsuid=2000
            // makes sucompat fail to open /data/adb/ksud.
            suCompat = false
            compatPrefs.edit().putBoolean("enabled", false).apply()
        }
    }

    fun updateSkipPreflight(value: Boolean) {
        skipPreflight = value
        preflightSkipPrefs.edit().putBoolean("enabled", value).apply()
        appendLog(if (value) "PREFLIGHT 跳过开关：开启（不推荐）"
                  else "PREFLIGHT 跳过开关：关闭")
    }

    fun updateSuCompat(value: Boolean) {
        // Selecting a su path automatically leaves debug skip mode.
        if (value && skipFsuid) {
            skipFsuid = false
            skipPrefs.edit().putBoolean("enabled", false).apply()
        }
        suCompat = value
        compatPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateAdbRoot(value: Boolean) {
        adbRoot = value
        adbRootPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateAutoCleanTemp(value: Boolean) {
        autoCleanTemp = value
        autoCleanPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateKeepRootdForStp(value: Boolean) {
        keepRootdForStp = value
        keepRootdPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateAdaptiveProfile(kernel: String, id: String, status: String) {
        adaptiveProfileKernel = kernel
        adaptiveProfileId = id
        adaptiveProfileStatus = status
        adaptivePrefs.edit()
            .putString("kernel", kernel)
            .putString("id", id)
            .putString("status", status)
            .apply()
    }

    fun updateAllowShell(value: Boolean) {
        allowShell = value
        allowShellPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateKernelUmount(value: Boolean) {
        kernelUmount = value
        kernelUmountPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateSelinuxHide(value: Boolean) {
        selinuxHide = value
        selinuxHidePrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateBakasuBackend(value: Boolean) {
        // Legacy compatibility: resukisu vs kernelsu only.
        val next = if (value) "resukisu" else "kernelsu"
        ksuFlavor = next
        backendPrefs.edit().putString("flavor", next).remove("bakasu").apply()
    }

    fun requestOptionsChange(action: () -> Unit) {
        if (optionsChangeDontShow || optionsChangeAcknowledged) {
            action()
            return
        }
        pendingOptionsAction = action
        showOptionsWarning = true
    }

    fun confirmOptionsChange(dontShowAgain: Boolean) {
        if (dontShowAgain) {
            optionsChangeDontShow = true
            optionsWarnPrefs.edit().putBoolean("dont_show", true).apply()
        }
        optionsChangeAcknowledged = true
        optionsWarnPrefs.edit().putBoolean("acknowledged", true).apply()
        showOptionsWarning = false
        val action = pendingOptionsAction
        pendingOptionsAction = null
        action?.invoke()
        appendLog("运行参数修改已确认；后续不再弹出首次提示")
    }

    fun cancelOptionsChange() {
        showOptionsWarning = false
        pendingOptionsAction = null
    }

    fun resetRunDefaults() {
        // Restore the shipped runtime parameter defaults.  The KernelSU
        // backend is intentionally not changed (it is a deployment choice).
        victimPerm = 32
        victimFsuid = 32
        victimCred = 24
        victimPrefs.edit()
            .putInt("permissive", 32)
            .putInt("fsuid", 32)
            .putInt("cred_24", 24)
            .apply()
        skipFsuid = false
        skipPrefs.edit().putBoolean("enabled", false).apply()
        skipPreflight = false
        preflightSkipPrefs.edit().putBoolean("enabled", false).apply()
        suCompat = true
        compatPrefs.edit().putBoolean("enabled", true).apply()
        suEntry = false
        suEntryPrefs.edit().putBoolean("enabled", false).apply()
        keepRootdForStp = false
        keepRootdPrefs.edit().putBoolean("enabled", false).apply()
        susfsEnabled = false
        susfsAllowUnhardened = false
        susfsPrefs.edit().putBoolean("enabled", false).putBoolean("allow_unhardened", false).apply()
        allowShell = true
        allowShellPrefs.edit().putBoolean("enabled", true).apply()
        adbRoot = false
        adbRootPrefs.edit().putBoolean("enabled", false).apply()
        kernelUmount = true
        kernelUmountPrefs.edit().putBoolean("enabled", true).apply()
        selinuxHide = true
        selinuxHidePrefs.edit().putBoolean("enabled", true).apply()
        chain98260Attempts = 12
        chain98260ChurnRounds = 8
        chain98260ChurnPerCpu = 256
        chain98260WaitCap = 25
        runtime60Prefs.edit()
            .putInt("attempts", 12)
            .putInt("churn_rounds", 8)
            .putInt("churn_per_cpu", 256)
            .putInt("wait_cap2", 25)
            .putBoolean("custom_ko_enabled", false)
            .apply()
        customKoEnabled = false
        editRunParams = false
        appendLog("已恢复默认参数：SELinux=32/fsuid=32/cred=24，参数面板保持展开")
    }

    /** Restore only the su-related switches after an STP experiment. */
    fun restoreSuDefaults() {
        skipFsuid = false
        skipPrefs.edit().putBoolean("enabled", false).apply()
        suCompat = true
        compatPrefs.edit().putBoolean("enabled", true).apply()
        suEntry = true
        suEntryPrefs.edit().putBoolean("enabled", true).apply()
        keepRootdForStp = false
        keepRootdPrefs.edit().putBoolean("enabled", false).apply()
        appendLog("已恢复 su_compat=开、su entry=开、keep rootd=关；当前 boot 的模块仍需重启后重新加载")
    }

    fun updateSuEntry(value: Boolean) {
        suEntry = value
        suEntryPrefs.edit().putBoolean("enabled", value).apply()
    }

    fun updateSusfs(value: Boolean) {
        val next = value && susfsSupported
        susfsEnabled = next
        // commit() instead of apply(): the SUSFS switch must survive an
        // immediate process kill / next app start.
        susfsPrefs.edit().putBoolean("enabled", next).commit()
    }

    fun updateSusfsAllowUnhardened(value: Boolean) {
        susfsAllowUnhardened = value
        susfsPrefs.edit().putBoolean("allow_unhardened", value).commit()
    }

    fun updateSusfsProtectMode(value: Boolean) {
        susfsProtectMode = value
        susfsPrefs.edit().putBoolean("protect_mode", value).commit()
    }


    fun appendLog(line: String?) {
        val text = line ?: "(null)"
        val next = if (logText.isEmpty()) text else "$logText\n$text"
        logText = if (next.length > 20_000) next.substring(next.length - 20_000) else next
    }

    fun replaceLog(text: String) {
        logText = text
    }

    fun showFeedback(title: String, detail: String, tone: Int) {
        feedbackTitle = title
        feedbackDetail = detail
        feedbackTone = tone
    }

    fun clearFeedback() {
        feedbackTitle = ""
        feedbackDetail = ""
        feedbackTone = 0
    }

    fun startRunProgress() {
        showFullLog = false
        showRunProgress = true
        runProgress = 2
        runStage = "准备链路"
        runElapsedSec = 0
        runResult = null
        preflightPassed = null
        runStartedAt = SystemClock.elapsedRealtime()
    }

    fun updateRunProgress(percent: Int, stage: String) {
        if (percent > runProgress) {
            runProgress = percent.coerceAtMost(100)
            runStage = stage
        }
    }

    fun finishRunProgress(success: Boolean) {
        if (runStartedAt > 0) {
            runElapsedSec = ((SystemClock.elapsedRealtime() - runStartedAt) / 1000L).toInt()
        }
        runProgress = if (success) 100 else runProgress
        runStage = if (success) "完成" else "已停止"
        runResult = success
        preflightPassed = null
    }

    /** Preflight is read-only: never report it as a successful root run. */
    fun finishPreflight(success: Boolean) {
        if (runStartedAt > 0) {
            runElapsedSec = ((SystemClock.elapsedRealtime() - runStartedAt) / 1000L).toInt()
        }
        runProgress = if (success) 100 else runProgress
        runStage = if (success) "预检通过" else "预检未通过"
        runResult = null
        preflightPassed = success
    }

    fun updateChannelAuth(channel: String, auth: String) {
        channelStatus = channel
        managerAuth = auth
    }

    private fun validVictim(value: Int, fallback: Int): Int =
        if (value == 16 || value == 24 || value == 32) value else fallback

    private fun validCredVictim(value: Int, fallback: Int): Int =
        if (value == 8 || value == 12 || value == 16 || value == 24 || value == 32) value else fallback
}


private fun defaultOnCompatPref(prefs: android.content.SharedPreferences): Boolean {
    // su_compat default restored to ON. Migrate old default-off state once;
    // users can still explicitly turn it off.
    if (!prefs.getBoolean("default_on_20261028_2", false)) {
        prefs.edit()
            .putBoolean("enabled", true)
            .putBoolean("default_on_20261028_2", true)
            .apply()
    }
    return prefs.getBoolean("enabled", true)
}

private fun readKernelVersion(): String {
    val fromProc = runCatching {
        Regex("Linux version (\\S+)")
            .find(File("/proc/version").readText())
            ?.groupValues
            ?.getOrNull(1)
    }.getOrNull()
    return fromProc
        ?: System.getProperty("os.version")?.trim()?.ifEmpty { null }
        ?: "unknown"
}

// Supported KernelSU-family managers (keep in sync with kernel_profiles.sh and
// MainActivity.java's FLAVOR_* tables).
val KSU_FLAVOR_ORDER = listOf("kernelsu", "resukisu", "next", "sukisu", "fina", "nova", "maplesu")

fun normalizeKsuFlavor(value: String?): String {
    return when (value) {
        "resukisu", "fina", "kernelsu", "sukisu", "next", "nova", "maplesu" -> value
        "official", "bakasu" -> "resukisu"
        else -> "kernelsu"
    }
}

/**
 * The 2026-10-25 redesign makes KernelSU the default backend and moves
 * BakaSU to the second slot.  Migrate once so an update does not keep the
 * old default (BakaSU) stored in preferences.
 */
private fun loadKsuFlavor(prefs: android.content.SharedPreferences): String {
    if (!prefs.getBoolean("order_v2_20261025", false)) {
        prefs.edit()
            .putString("flavor", "kernelsu")
            .putBoolean("order_v2_20261025", true)
            .remove("bakasu")
            .apply()
        return "kernelsu"
    }
    return normalizeKsuFlavor(prefs.getString("flavor", "kernelsu"))
}

fun ksuLabelOf(flavor: String): String = when (flavor) {
    "fina" -> "FinaSU"
    "kernelsu" -> "KernelSU"
    "sukisu" -> "SukiSU"
    "next" -> "KernelSU-Next"
    "nova" -> "SukiSU Nova"
    "maplesu" -> "MapleSU"
    else -> "BakaSU"
}

fun ksuPkgOf(flavor: String): String = when (flavor) {
    "fina" -> "me.yuki.fina"
    "kernelsu" -> "me.weishu.kernelsu"
    "sukisu" -> "com.sukisu.ultra"
    "next" -> "com.rifsxd.ksunext"
    "nova" -> "com.sukisu.nova"
    "maplesu" -> "dev.maplesu.manager"
    else -> "com.resukisu.resukisu"
}

fun chainLabelOf(chain: String): String =
    if (chain == "98260") "98260（默认 · 6.12.58/58b 已验证 / 6.6.118 profile）" else "64560（备用）"

data class ManagerInfo(
    val flavor: String,
    val label: String,
    val pkg: String,
    val installed: Boolean,
    val version: String,
    val versionCode: String,
    val source: String,
)

data class AppEntry(val label: String, val pkg: String)

data class DeviceStatus(
    val channel: String = "检测中",
    val rootReady: Boolean = false,
    val selinux: String = "unknown",
    val managerName: String = "未选择",
    val managerPkg: String = "",
    val managerVersion: String = "",
    val managerVersionCode: String = "",
    val managerInstalled: Boolean = false,
    val moduleLive: Boolean = false,
    val suEntry: String = "未检测",
    val model: String = android.os.Build.MODEL ?: "unknown",
    val kernel: String = "",
)

data class RootDiagnostic(
    val uid: String = "",
    val cap: String = "",
    val selinux: String = "",
    val storage: String = "",
    val module: String = "",
    val manager: String = "",
    val su: String = "",
    val details: List<String> = emptyList(),
    val ok: Boolean = false,
)












