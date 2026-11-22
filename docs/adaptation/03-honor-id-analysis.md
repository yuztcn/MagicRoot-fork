# Honor ID (`com.hihonor.id`) — Root Detection, DRM/Widevine, and AI‑Sidebar Relationships

**Scope / mode:** static + read‑only dynamic triage. No device or system partition was modified; no reboot/root/install/clear was performed. ADB was used only for `pm path`, `dumpsys`, `logcat`‑derived artifacts and file pulls. All generated artifacts live under `work/reverse/honor-id/`.

| Item | Value |
|---|---|
| APK | `work/reverse/honor-id/com.hihonor.id-base.apk` |
| Size / SHA‑256 | 95,347,274 bytes / `DBD12680DA74ADBF8EF1244827B87735967168333D524F59A344032C1B97073F` |
| package / version | `com.hihonor.id` / `10.1.82.350` (versionCode `100182350`) |
| SDK | minSdk 24, targetSdk 36, compileSdk 35, platformBuild 15 |
| DEX | 21 `classes*.dex` (classes..classes21), 10.0 MB largest |
| Native | only `lib/arm64-v8a` (20 SOs); no armeabi‑v7 in base APK |
| Signature | system app: `flags=[ SYSTEM HAS_CODE ALLOW_CLEAR_USER_DATA UPDATED_SYSTEM_APP ]`, uid 10126; declared permissions are `signature|privileged` (verified via `dumpsys package`) |
| Built‑in plugins | `assets/plugins/*.jar` (6 plugins; two contain native root/DRM‑related code) |
| Device | serial `ABJR026830004079`, Honor MagicOS, Android 15, SELinux observed `permissive=1` |
| Runtime evidence | `work/m6-recreate-log.txt` (logcat, 2026‑10‑28 14:32:xx) |

Tools used: Python 3.14 (+ `pyelftools`, `capstone`), `aapt2`/`dexdump` from build‑tools 35.0.0, `llvm-nm`/`llvm-objdump` from NDK r28c. Decompilation is a custom `dexdump -d` filter (`dexdump_filter.py`) so every Java offset below is a **DEX file offset** as printed by dexdump (not a runtime address).

---

## 1. Package, components, processes, SDK versions, native libraries

### 1.1 Processes (manifest + `dumpsys activity processes` + log)

| Process | Role / representative components |
|---|---|
| `com.hihonor.id` (main; no process suffix) | Application, game SDK, ad‑attribution, RePlugin host, MMS/risk plugins; PID 17068 in the captured log (GCORE_UGMM, AdAttr, GetRiskControlDataUtils, `ric` risk collector). *The log does not print the process suffix for 17068; `:core` is the alternative interpretation* |
| `:core` | `com.hihonor.cloudservice.CoreGuardService`, `com.honor.id.urc.ipc.server.UrcServiceNonExported`, `com.hihonor.hosmananger.aidl.service.MMSHosManagerService`, `com.hihonor.cloudservice.services.HnOaIdService`, providers `HnIDProvider`, `PlatformProvider`, `CoreUuidProvider`, `DataSourceProvider`, `CoreRepositoryProvider`, `HnIdPreferencesProvider`, `OaidSwitchesProvider`, `MMSHosCommonProvider` |
| `:persistent` | `com.hihonor.cloudservice.PersistentGuardService`, `com.hihonor.id.router.RouterContentProvider`, `com.hihonor.id.replugin.sp.MultiProcPrefProvider`, `com.hihonor.mms.MMSStaticPitReceiver`, RePlugin `*Persist` providers |
| `:p0` / `:p1` / `:p2` | RePlugin plugin processes. `:p1` hosts `com.hihonor.kitassistant.service.KitAssistantService` and its 4 job services |
| `:pay` | IAP (`PurchaseService`, `CheckEnvService`, `ProcessService`) — TrustDecision `TDRisk` is initialized here (see §4.4) |
| `:wallet` | `com.hihonor.wallet.business.loan.service.MallPushService` |
| `:game` | `com.hihonor.gamecenter.gamesdk.core.service.GameService` / `GameFitService` |
| `:router` / `:remote` | Router provider / `com.hihonor.hnid.manager.accountmgr.HnAccMgrService` |
| `:loader0` / `:loader1` | RePlugin loader processes |
| `:kitAssistant` | Process declared by the bundled **plugin** manifest (`kitassistant.jar`), not by the base manifest |

`AndroidManifest` process attribute counts: `:p0` 86, `:p1` 84, `:p2` 79, `:pay` 76, `:core` 41, `:wallet` 21, `:loader0/1` 11 each, `:persistent` 8, `:game` 8, `:router` 2, `:remote` 1.

### 1.2 Account/ID components and surfaces

- Account/ID SDK code lives under `com.hihonor.hnid*`, `com.hihonor.hnid20*`, `com.hihonor.cloudservice.hnid.*` (e.g. `GetDeviceInfoRequest`, `NativeAuthorizationActivity`, `HnIDNaming`).
- Identity is exposed mainly through **ContentProviders in `:core`**: `com.hihonor.hnid.fingerprint.provider.HnIDProvider`, `com.hihonor.hnid20.provider.PlatformProvider` (read/write gated by `com.hihonor.id.permission.ADVICECARD_READ/WRITE`), `com.hihonor.hnid.common.account.CoreUuidProvider`, `com.hihonor.hnid.common.innercall.sp.HnIdPreferencesProvider`.
- `PlatformProvider`/`AdviceCardProvider` declare **signatureOrSystem** read/write permissions (`ADVICECARD_READ/WRITE`, `protectionLevel=0x3`); `HnIdCloneProvider` uses `BACKUP_READ/WRITE_PROVIDER` (0x3). However the manifest marks several identity endpoints **exported with no permission**: `HnIDProvider` (exported=true, no permission), `CloudAccountService`/`HnCloudAccountService`/`PPSChannelInfoService` (exported=true, no permission). `HnIDProvider.query` handles `deviceUniqueId` and `honor_id_account_status` columns; its `call()` only accepts `unbind_fingerprint`. These are the most plausible identity surfaces for a system assistant app (see §4).
- **Kit Assistant service** (see §4): `com.hihonor.kitassistant.service.KitAssistantService` in `:p1`, protected by `com.hihonor.id.permission.BIND_KIT_ASSISTANT_SERVICE`.

### 1.3 SDK / plugin versions found

| Component | Version | Evidence |
|---|---|---|
| Honor ID app | 10.1.82.350 (100182350) | aapt2 badging |
| HMSCore (base/device/log/update) | 6.3.0.303 | `HMSCore-*.properties` |
| AGConnect core | 1.5.0.300 | `agconnect-core.properties` |
| `Kit_Data_Collector` plugin (risk data collector, contains `libhonordetect.so`) | **9.0.9.305** | log tag `[I/Kit_Data_Collector[9.0.9.305]...]`; `plugins-builtin.json` ver `90900305` |
| `Mms_Plugin_Lib` (runtime MMS plugin that hosts `GetRiskControlDataUtils`) | **10.0.70.100** | log `[I/Mms_Plugin_Lib[10.0.70.100]/GeneralDeliver ...]` |
| `hos_manager_plugin` (`com.hihonor.mms.hosmanager`, contains `libhisec.so`, `libods.so`) | 110000302 | `plugins-builtin.json` |
| `kitassistant` plugin (`com.hihonor.mms.permissionservice`, permission/scope cache service) | 7.0.4.301 | plugin manifest + `plugins-builtin.json` |
| Ad attribution SDK | 1.0.20.300 | log tag `AdAttr-AppNotifier: [v1.0.20.300]` |
| FIDO SDK (GM RZ, package obfuscated `com.gmrz.*`) | embedded | `FidoAppSDK`, `com.gmrz.fido.asmapi.*` |
| TrustDecision TrustDevice / TDRisk | embedded (version string not recoverable) | `com.trustdecision.mobrisk.*`, `libtrustdevice.so`, `libtdcoreplugin.so` |

### 1.4 Native libraries (arm64‑v8a)

| SO | Size | Role (evidence) |
|---|---|---|
| `libhisec.so` | 51,224 | "AegisSecComp" security component; JNI natives `idj/iej/irpj/irtj` registered into `com.hihonor.secure.android.common.detect.S`; anti‑debug, emulator, signature‑hash and root checks |
| `libhonordetect.so` | 31,448 (APK) / 31,608 (plugin) | `NativeLib.isRT/isSMT/isDG` (root / emulator / debugger), package `com.hihonor.cloudservice.usm.skit.detect` |
| `libtrustdevice.so` | 638,648 | TrustDecision device fingerprint/risk core; only `JNI_OnLoad` exported, heavily obfuscated |
| `libtdcoreplugin.so` | 108,808 | TrustDecision plugin; `JNI_OnLoad`; contains `xc_util_is_root` and a classic `su` path scan |
| `libods.so` | 189,104 | NOT root detection: `com.hihonor.secure.android.common.enc2.ODS`, exports `getwbwk`, `wbg_decrypt`, `honor_aes_gcm_decrypt` (Honor Cloud SKIT crypto) |
| `libAkSdk.so`, `libkyctoolkit.so`, `libturingmfa.so`, `libCtaApiLib.so`, `libYTCommonLiveness.so`, `libentryexpro.so`, `libexocrenginec.so`, `libweconvert.so`, `libweyuv.so`, `libimage_processing_util_jni.so` | … | FIDO/KYC/liveness/UnionPay/WeChat SDKs (not root detection) |
| `libmmkv.so`, `libconscrypt_jni.so`, `libtensorflowlite_jni.so`, `libnbscrash*.so` | … | storage/TLS/ML/crash SDKs |

---

## 2. Root detection — exact paths

### 2.1 Observed runtime sequence (main process PID 17068, thread 18203, 14:32:52)

```
6930  .719 nativeloader: Load .../base.apk!/lib/arm64-v8a/libhisec.so ... caller=base.apk!classes5.dex : ok
6931  .719 AegisSecComp: JNI_OnLoad begins
6932  .719 AegisSecComp: Begin to registerNativeMethods
6933  .719 AegisSecComp: return JNI_VERSION_1_6
6935  .720 AegisSecComp: binary name is exist in /data/local/tmp/su
6936  .720 E AegisSecComp: check su exists
6942  .731 nativeloader: Load /data/data/com.hihonor.id/app_p_n/-1902912772/arm64/libhonordetect.so ... : ok
6934  .727 GeneralDeliver: [I/Mms_Plugin_Lib[10.0.70.100]/GeneralDeliver] try reflect deliver
...  .773 HUKS keys 0/10126_USRPKEY_com_honor_cloudservice_riskinfoCollect_com+^hih****+^id
...  .799-863 "ric": sToolKeyRandomKey, said/smdid/ssfs/skafi/ssdct read from device
```

Both root‑detection stacks (`libhisec` and `libhonordetect`) were loaded on the **same binder/worker thread** that builds the device‑risk payload. The `libhisec` check found a real `su` binary at `/data/local/tmp/su` (the device is rooted, and that path is readable by the `platform_app` domain; SELinux AVCs in the same log are `permissive=1`).

### 2.2 Path A — risk/device‑info collector in `Kit_Data_Collector` plugin (the actively used path)

Plugin: `assets/plugins/Kit_Data_Collector.jar` → `classes.dex` (also a partial, older copy of the same package exists in base APK `classes12.dex`).

Collector method:
`com.hihonor.cloudservice.usm.skit.riskinfocollect.proguard.i.a(Context,String×6):String`
DEX offset **0x0387b0** (2447 code units) — builds the whole device/risk JSON, including root flags **and** the Widevine DRM ID.

Root sub‑calls (all in the same method):

| DEX offset | Call | Cached field |
|---|---|---|
| 0x038b2c | `RiskDetect.isRT()` → `RtResult.getCode()`; `code>0` ⇒ `"1"` else `"0"` | `proguard.i.b` → `proguard.f.m` |
| 0x038ba2 | `RiskDetect.isSMT()` → `SmtResult.getCode()`; `code>0` ⇒ `"1"` | `proguard.i.f` → `proguard.f.n` |
| 0x038bc4 | `RiskDetect.isRT().isBasicRootInfo()` | `proguard.i.c` |
| 0x038be6 | `RiskDetect.isRT().isRootSPInfo()` | `proguard.i.d` |
| 0x038c08 | `RiskDetect.isRT().isHookInfo()` | `proguard.i.e` |

`RiskDetect` is a thin Java wrapper (`com.hihonor.cloudservice.usm.skit.detect.RiskDetect`, DEX offsets 0x036cc0 `isDG`, 0x036cf8 `isRT`, 0x036d30 `isSMT`) that calls `NativeLib.isDG/isRT/isSMT` only when `NativeLib.isArmAbi()` is true. `NativeLib.<clinit>` (0x036c80) does `System.loadLibrary("honordetect")` at **0x036ca0**. The three natives are declared `PUBLIC STATIC NATIVE` at 0x036ab0‑0x036ac0.

`RtResult` code is a bitmask: `isBasicRootInfo()` = `code & 0xff` (0x036e94), `isRootSPInfo()` = `(code>>8) & 0xff` (0x036ee0), `isHookInfo()` = next byte. `SmtResult.isSMTInfo()` = `code & 0xff` (0x036f50).

Native side (`libhonordetect.so`, exported JNI names, no `RegisterNatives`):

| Export | VA | Checks / strings (string‑xref instruction addresses) |
|---|---|---|
| `Java_com_hihonor_cloudservice_usm_skit_detect_NativeLib_isRT` | **0x5cd4** | `/magisk` (0x5d18), `/su` (0x5d20), `/cache/.disable_magisk` (0x5df8), `ro.secure` (0x5e8c), `ro.build.tags` (0x5ed0), `/proc/self/maps` (0x5f28) — root + hook/map scan |
| `..._isSMT` | **0x5fc8** | `/proc/cpuinfo` (0x5ff0), `ro.product.name` (0x605c), `ro.hardware` (0x6110), `ro.build.flavor` (0x61d4), `ro.product.model` (0x623c), `ro.product.manufacturer` (0x62c4), `ro.board.platform` (0x6340), `ro.product.board` (0x6370), `gsm.version.baseband` (0x63d4) — emulator detection (also contains the huge list of Nox/BlueStacks/Genymotion/Xposed/Magisk/Riru paths in `.rodata`) |
| `..._isDG` | **0x6548** | `/proc/net/tcp | grep :5D8A` (0x6590; 0x5D8A = 23946, IDA `android_server` port), `android/os/Debug` (0x6614), `isDebuggerConnected` (0x6630), `/proc/%d/status` (0x6694) — debugger detection |

Confidence: **high** (code + device log + exact `app_p_n/-1902912772/arm64/libhonordetect.so` load line).

### 2.3 Path B — `libhisec.so` / `com.hihonor.secure.android.common.detect`

Java:
- `com.hihonor.secure.android.common.detect.S` (obfuscated class, `S.java`):
  - `<clinit>` at DEX **0x17c8f0**: `System.loadLibrary("hisec")` at 0x17c908 (log tag `"S"`).
  - four `PUBLIC STATIC NATIVE` methods `idj/iej/irpj/irtj` (`()Z`), DEX 0x17c980‑0x17c9e0.
- `SecurityDetect` (0x17c7a4 `idj`, 0x17c804 `iej`, 0x17c864 `irpj`) contains try/catch wrappers around `S.*`; on exception they return `true` (fail‑closed). **There is no `SecurityDetect.irtj`** — the root native is called directly from `RootDetect.isRoot()` / `DetectUtil.isRooted()`.
- `RootDetect.isRoot()` at **0x17c67c**:
  - `SDK_INT >= 27` → `S.irtj()` (0x17c69e); if true logs `"root exists"` and returns true.
  - `SDK_INT < 27` → Java fallbacks: `a()` su files, `e()` `ro.secure=="0"` (0x17c650), `d()`, `c()`, `b()`.
- `DetectUtil.isRooted()` at **0x17c384**: returns `S.idj() || S.irtj()` (i.e. anti‑debug OR root). This is the method used by the game SDK (see §2.5).

Native (`libhisec.so`, `JNI_OnLoad` at **0x2568** registers into class `com/hihonor/secure/android/common/detect/S`; JNINativeMethod table at **.data.rel.ro 0x1bc90**):

| Entry VA | Name | Sig | Stub | Impl VA | Behavior (strings) |
|---|---|---|---|---|---|
| 0x1bc90 | `idj` | `()Z` | 0x2558 | **0x14dc** | anti‑debug: `/proc/%d/status` (0x151c/0x154c/0x1588), `TracerPid` (`TracePid Debugging...` 0x1594), `/proc/net/tcp` (0x1620), `android_server`/`android_server64` (0x175c/0x1760) |
| 0x1bca8 | `iej` | `()Z` | 0x255c | **0x18ac** | emulator: `init.svc.vbox86-setup/droid4x/qemud/su_kpbs_daemon/noxd/ttVM_x86-setup/xxkmsg/microvirtd` (0x19dc‑0x1b2c), `ro.product.*`, `/system/bin/qemu-props` etc. (0x1c04‑0x1d2c) |
| 0x1bcc0 | `irpj` | `()Z` | 0x2560 | **0x229c** | compares a 65‑char hex string against 24 pre‑computed SHA‑256 values at `.data.rel.ro 0x1bb28` (e.g. `B92825C2…`, `1E3EEE2A…`) using `strncmp`; most consistent with **APK signature/cert allow‑list** (anti‑tamper), not root. Native signature is declared `()Z` although the code reads a string argument — treat the semantic label as medium confidence |
| 0x1bcd8 | `irtj` | `()Z` | 0x2564 | **0x234c** | **root check**: `__system_property_get("ro.secure")` (0x2380), first char compared with `'0'` (0x2394‑0x239c), error log `check ro.secure error` (0x23ac); then `su` path scan (`check su exists` 0x2424), `/magisk` (0x2430, `check magisk exist` 0x2448), `binary name is exist in %s` (0x251c); returns true when found. This is the function that produced the 14:32:52.720 device log |

`irpj` and `irtj` are declared in Java but the device log proves **`irtj` executed** (the only source of `binary name is exist in %s` + `check su exists`). Exact `/data/local/tmp/su` hit shows the scan includes `/data/local` + `/tmp` + `su`.

Confidence: **high** for native behavior/offset; **medium** for the `irpj` semantic; **medium** for the immediate Java caller (see next).

### 2.4 Who calls the `libhisec` natives? (locally called vs dead)

Static xref scan over all 21 DEX (custom `dexdump` xref filter, exact class refs):

- `S.idj` / `S.irtj` are referenced **only** by:
  - `RootDetect.isRoot()` (0x17c67c) — **no caller of `RootDetect.isRoot()` exists in any base‑APK DEX**.
  - `SecurityDetect.idj/iej/irpj` wrappers — **no caller in base‑APK DEX** (`SecurityDetect` has no `irtj`).
  - `DetectUtil.isRooted()` (0x17c384) — **used** by `com.hihonor.gamecenter.gamesdk.core.net.utils.DetectUtil.isRooted()` at DEX **0x26b364**: it reads its cached flags and otherwise calls `com.hihonor.secure.android.common.detect.DetectUtil.isRooted()` at **0x26b386** (`classes15.dex`).
- No base‑APK DEX calls `RootDetect.isRoot()`, and the `SecurityDetectActivity` (`com.hihonor.hnid.cloudsettings.ui.SecurityDetectActivity`, `classes16.dex`) is only a settings UI (`onCreate` at 0x0e9940 inflates `cloudsetting_security_detect_activity_new`; no detection code).
- The observed `libhisec` call therefore most plausibly came from `DetectUtil.isRooted()` (game SDK initialised in the **main** process; PID 17068 also logs `GCORE_UGMM`/AdAttr) or from a runtime plugin not present in the base APK (`app_p_a/-1902912772.jar` was the caller of `libhonordetect`). The exact Java stack was not logged (`DetectUtil` has no log line; `RootDetect`'s `"root exists"` line is absent, which is consistent with `DetectUtil.isRooted` returning via `S.idj` or plugin reflection rather than `RootDetect`).

**Verdict:** `libhisec` root/anti‑debug logic **did run** (high confidence); the Java trigger is either `DetectUtil.isRooted()` (game SDK) or a plugin/reflection path (medium confidence). `RootDetect.isRoot()` is **dead code in the base APK** unless invoked reflectively.

### 2.5 Other root checks and status fields

| Location | What it does | Status |
|---|---|---|
| `com.hihonor.gamecenter.gamesdk.core.net.utils.DetectUtil` (`classes15`, 0x26b364) | caches `isRooted`/`isRootedDetected`, delegates to `com.hihonor.secure...DetectUtil.isRooted()` (Java/native `S`) | Live when game SDK runs (`:game`/main) |
| `com.hihonor.gamecenter.gamesdk.core.utils.cookie.DeviceInfo.rootStatus` + `CookieCenter.COOKIE_KEY_ROOT` (`classes15`) | puts root flag into game WebView cookies sent to game/H5 servers | Live for game H5 flows |
| `com.hihonor.wallet.business.loan.infra.web.ItH5ContainerUtils$H5DeviceInfo.rootStatus` (`classes11`) | Kotlin data class field, serialized to loan H5 (`getRootStatus` at 0x10e198, setter 0x10e2a8); source of the value is the loan H5 bridge, not a detector in this class | Live only in wallet loan H5 |
| `com.hihonor.hm.h5.container.js.method.DeviceMethods$StatusInfo.isRoot` (`classes15`) | H5 JS bridge status field | Live for H5 containers |
| `com.gmrz.appsdk.util.ThreatDetector.checkRootMethod1/2/3`, `isDeviceRooted`, `FidoParam.enableDeviceCheckRoot`, `Constant.CHECK_ROOT` (`classes12`) | FIDO SDK's own Java root checks | Not observed in log; runs only in FIDO enrollment/auth flows |
| `com.trustdecision.mobrisk.TDRisk` + `libtrustdevice`/`libtdcoreplugin` | third‑party risk SDK with native root checks (`xc_util_is_root`; `/data/local/su`, `/system/xbin/su`, …, `/sbin/su`; `/proc/self/maps`) | Initialised in `:pay` by IAP (see §4.4); no runtime evidence during the captured `:core`/main session |
| `HwSecurityDiagnose`, `HwSecurityDiagnose.getRootStatus`, `isRoot`, `rootStatus` as system APIs | **No `HwSecurityDiagnose` symbol at all**: 0 occurrences in all 21 DEX and all 6 plugin JARs (byte scan) | Absent / not implemented here |
| `persist.sys.root.status`, `ro.root*`, `sys.root*` | **No reference in the APK** (only `ro.debuggable` appears once in `classes7.dex`, unrelated) | APK does not read the system root property; the earlier harness shell command `getprop persist.sys.root.status` was external, not app code |

`HwSecurityDiagnose` absence is a notable negative finding: Honor ID relies on the in‑house `com.hihonor.secure.android.common.detect` SDK (libhisec) plus `com.hihonor.cloudservice.usm.skit.detect` (libhonordetect), not on a platform `HwSecurityDiagnose` service.

### 2.6 Cheat‑sheet: what actually protects what

| Mechanism | Called at runtime? | Evidence |
|---|---|---|
| `NativeLib.isRT/isSMT/isDG` → `libhonordetect` | **Yes** (plugin loaded, `ric` fields populated) | log 6942 + code 0x038b2c‑0x038c26 |
| `S.irtj` → `libhisec` root scan | **Yes** (su log) | log 6930‑6936 |
| `S.idj`/`iej` anti‑debug/emulator | Likely evaluated together in `DetectUtil.isRooted()`; no positive log | code 0x17c384 |
| `RootDetect.isRoot()` | **No static caller** (dead unless reflection) | xref scan |
| `SecurityDetect.*` wrappers | **No static caller** | xref scan |
| FIDO `ThreatDetector` | Not observed | no FIDO/`gmrz` log lines |
| TrustDecision `TDRisk`/`libtrustdevice` | Initialised in `:pay` (IAP), not in the captured risk flow | `com.hihonor.iap.core.ui.inside.b.<clinit>` 0x356920 |
| `libods` | Not root detection (crypto, `enc2.ODS`) | exports `getwbwk`, `wbg_decrypt`; Java `com.hihonor.secure.android.common.enc2.ODS` |

---

## 3. DRM / Widevine

### 3.1 The exact Widevine code path (and why the lazy service started)

**Code** (in the **plugin** `Kit_Data_Collector.jar!classes.dex`, the copy that actually ran):

`com.hihonor.cloudservice.usm.skit.riskinfocollect.proguard.h.a():String`
DEX offset **0x038750**, code units:

```
0x038760  const-string v0, "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"   ; Widevine UUID
0x038764  UUID.fromString
0x03876c  new-instance Landroid/media/MediaDrm;
0x038770  MediaDrm.<init>(UUID)          ; <-- lazy widevine service is started here
0x038776  const-string v0, "deviceUniqueId"
0x03877a  MediaDrm.getPropertyByteArray("deviceUniqueId")
0x038784  Base64.encodeToString(bytes, 2)
0x038798  log "getDId err : " (tag "ric") on exception; returns ""
0x0387a2  return
```

Caller: `proguard.i.a(Context,String×6):String` at **0x0387b0** calls `h.a()` at **0x0395b0**, immediately after the log `"smdid read from device."` (0x0395a6) and before `"ssfs read from device."` (0x0395d0). The value is cached in `proguard.i.k` and stored into `proguard.f.u0`.

Base APK `classes12.dex` contains an **older/different copy** of `riskinfocollect` whose `proguard.h.a` takes 6 arguments (`Context,String×5`) at 0x46e4ac/0x46e528/0x46e5a4 and contains **no MediaDrm / UUID string** (no `edef8ba9` in `classes12`). So the DRM‑ID collection is **only in the downloaded/plugin version**, not in the base APK's local copy. The FIDO SDK in `classes12` has a separate `MediaDrm` getter (`com.gmrz.fido.asmapi.uq3.a()`, DEX 0x290cf4, `"deviceUniqueId"` at 0x290d20), but no FIDO/`gmrz` log line appears in the session, so it was not the caller.

**Device log chain (14:32:52.830–.861, thread 17068:18203):**

```
7055  .830 HidlServiceManagement: Cannot list manifest for android.hardware.drm@1.x::IDrmFactory without hwservicemanager
7060  .831 DrmHalHidl: No hidl drm factories found
7063  .832 DrmUtils: found IDrmFactory. Instance name:[android.hardware.drm.IDrmFactory/clearkey]
7064  .848 android.hardware.drm-service-lazy.widevine: Is commercial user: 1
7065  .848 libbinder.AidlLazyServiceRegistrar: Registering service android.hardware.drm.IDrmFactory/widevine
7067  .849 ... "widevine has clients: 1"
7068  .849 DrmUtils: found IDrmFactory. Instance name:[android.hardware.drm.IDrmFactory/widevine]
7072  .850 WVCdm: Level 3 Build Info ...
7083  .857 WVCdm: Could not load oemcrypto from path liboemcrypto.so; falling back to L3
      .857 WVCdm: Keybox error: 25. Falling back to L3.
7096  .858 WVCdm-DrmFactory: [app][com.hihonor.id] calling ... WVDrmFactory::createDrmPlugin(...)
7125  .861 MediaDrm-JNI: MediaDrm_native setup drm 0xb400006eeda400d0
      .861 WVCdm: QueryStatus security_level = Default, query_token = DeviceID
      .861 WVCdm: crypto_session Open, security_level = L3
```

Interpretation: `MediaDrm` was constructed with the **Widevine** UUID (not ClearKey). The framework enumerated DRM factories (`clearkey` found first), then contacted `android.hardware.drm.IDrmFactory/widevine`; because it is a **lazy AIDL service**, the framework started `android.hardware.drm-service-lazy.widevine` (PID 22171) and registered it; the WV CDM logged the client app as `com.hihonor.id`, created a plugin, and `getPropertyByteArray("deviceUniqueId")` issued `QueryStatus(DeviceID)` and opened a crypto session. The service start is therefore a **side effect of DRM ID collection**, triggered by `com.hihonor.id`'s risk collector, not by a media playback request.

DRM security level: **L3 only** on this device — `liboemcrypto.so` is missing, L1 keybox validation returns `Keybox error: 25`, so Widevine falls back to Level 3 ("HAYSTACK_ONLY" build). `"Is commercial user: 1"` is emitted by the vendor DRM service at start.

### 3.2 Root gating of DRM / attestation / key provisioning

- In the app code path there is **no branch on root status around the DRM call**: `i.a(...)` computes root/SMT/hook flags first (0x038b2c‑0x038c26) and later calls `h.a()` (0x0395b0) unconditionally except for the cache check (`proguard.i.k == null`). No comparison of the root result guards `h.a()`, `MediaDrm`, provisioning, or key generation.
- The risk collector **sends both** the root/hook flags and the Widevine Device ID in the same payload; whether the server correlates or rejects rooted devices is a **server‑side decision** that cannot be verified statically (risk payload goes through Honor cloud `riskinfoCollect`, HUKS‑protected key `10126_USRPKEY_com_honor_cloudservice_riskinfoCollect...`).
- HUKS/TEE usage around the same flow (`HUKS_KeystoreManager` get/export, `CERTCHAIN`, TEE `teecd` compare) is for the risk payload key/cert, **not gated by the local root result** in code.
- Widevine provisioning/keybox validation is entirely inside the vendor `drm-service-lazy.widevine` process (L1 keybox error 25 → L3). Honor ID cannot influence L1/L3 beyond picking the Widevine UUID.
- FIDO key attestation (`FpUtil.verifyAttestionExtension`, `ThreatDetector`) is separate and only used in FIDO flows; it was not observed.

Confidence: **high** for "no local root gating of DRM ID collection"; **unverifiable** for server‑side enforcement.

### 3.3 Other DRM/DRM‑ID references

- `com.gmrz.fido.asmapi.uq3.a()` (base APK `classes12`, DEX 0x290cf4): `MediaDrm.isCryptoSchemeSupported(widevine UUID)`, `getPropertyString("deviceUniqueId")`/`getPropertyByteArray`, releases DRM. Used by FIDO `FidoAppSDK.getDeviceInfo`; not observed.
- TrustDecision: `com.trustdecision.mobrisk.TDRisk.OPTION_DRM_ID = 1048576`, `TDDeviceManager.OPTION_DRM_ID = 1048576` (`classes9`). The SDK is initialised in `:pay` (`com.hihonor.iap.core.ui.inside.b.<clinit>`, DEX 0x356920: partner `honor_cloud`, appKey `3c11cee5f314d6edb4e5bccd666f6411`, appName `honor_cloud_and`, country CN, `TDRisk.initWithOptions` at 0x3569a0). No runtime evidence that the DRM‑ID option is enabled or that TDRisk ran during the captured session.

---

## 4. AI sidebar / assistant integration

### 4.1 Direct string search

| Token | Hits in APK | Meaning |
|---|---|---|
| `hndockbar` | **0** | No dock‑bar integration |
| `magicvoice` | **0** | No MagicVoice integration |
| `sidebar` | 8 per DEX | **Only icon resource names** `icsvg_public_sidebar_off/open[_bold/_filled/_regular]` in the shared icon font — no sidebar API/component |
| `assistant`/`Assistant` | many | `com.hihonor.gameassistant` (game assistant), `com.hihonor.kitassistant` (kit assistant/permission service), `ScopeAssistant` (OAuth scope helper), `AssistantHelper` (game coupon dialog). No `com.hihonor.assistant` / AI assistant package |
| `hshop` | `classes15` | Honor Shop SSO **cookie names** (`hshop_accessToken`, `hshop_appid`, `Domain=hihonorcloud.com; Path=/`) — web identity/token sharing, not AI |
| `aigc` | 1 (`com.hihonor.aigcsdk` in `classes15` string pool) | AIGC SDK package string, no code path in this APK |

**Conclusion (high confidence):** Honor ID has **no direct AI‑sidebar/assistant integration** and does not pass root/DRM state to any `hndockbar`/`magicvoice` component.

### 4.2 What Honor ID *does* expose to assistant‑type consumers

1. **Kit Assistant service** (`com.hihonor.kitassistant.service.KitAssistantService`):
   - Manifest: process `:p1`, **exported=true**, permission `com.hihonor.id.permission.BIND_KIT_ASSISTANT_SERVICE` with **protectionLevel `0x0` (normal)** — i.e. any installed app is granted it automatically at install, so the service is bindable by third parties (the plugin may still perform its own caller checks; not verifiable without its DEX).
   - Host implementation is only a proxy: `onBind` at DEX **0x162128** forwards to the plugin service object (`kitAssistantService` field); `onCreate` 0x162294, `onDestroy` 0x1622bc. Log: `"Bind KitAssistant Plugin's KitAssistantService success!"`.
   - Plugin: `assets/plugins/kitassistant.jar`, package `com.hihonor.mms.permissionservice`, version **7.0.4.301**, services `com.hihonor.kitassistant.service.KitAssistantService` / `...core.KitAssistantCoreService` in process `:kitAssistant`, plus `RefreshSinglePermissionCacheJobService`, `RefreshAllCacheJobService`, `RefreshContinueScopeJobService` and a `PackageChangedReceiver`. Manifest declares `QUERY_ALL_PACKAGES`, `INTERNET`, and its own `BIND_KIT_ASSISTANT_SERVICE`.
   - The class/service naming ("permissionservice", "Refresh…PermissionCache", "ContinueScope") and the plugin's resource strings (only 3 occurrences of "permission", no "scope/identity/account/root/drm" strings) indicate a **permission/authorization scope cache service**, not an identity/DRM/root oracle. The plugin contains **no DEX** in the bundled JAR, so its business logic is supplied at runtime (downloaded plugin); payload details are **medium confidence**.
   - This is the only plausible "assistant" data path: an assistant/permission UI can bind (with the signature permission) to query cached runtime‑permission/scope state from Honor ID.
2. **Identity providers** in `:core` (HnIDProvider, PlatformProvider, CoreUuidProvider, HnIdPreferencesProvider, DataSourceProvider, CoreRepositoryProvider) — account/UUID/advice‑card data for system apps; `PlatformProvider` is gated by signatureOrSystem `ADVICECARD_READ/WRITE`, but **`HnIDProvider` is exported without a permission** (`query` supports `deviceUniqueId`, `honor_id_account_status`), so any app can query it subject to the provider's internal checks.
3. **Game assistant** surface (`com.hihonor.gameassistant`, `GameAssistantProvider`, AIDL `IGameServiceCallback`) — game‑only, unrelated to root/DRM.
4. **Honor Shop SSO cookies** (`hshop_*`) — identity/token sharing to `hihonorcloud.com`.

No code was found that serializes root flags (`isRT`, `isSMT`, `isDG`, `rootStatus`) or DRM ID into any KitAssistant/assistant‑facing API. Root/DRM data flows only into the **risk‑info payload** sent to Honor cloud (`riskinfoCollect`).

---

## 5. Concrete hook / patch / hide points (for a permitted lab environment only)

> The task is read‑only; nothing below was applied. All addresses are file‑relative VAs (SO) or DEX offsets.

### 5.1 Java hooks (highest leverage)

| Target | Offset | Suggested action |
|---|---|---|
| `com.hihonor.cloudservice.usm.skit.detect.NativeLib.isRT/isSMT/isDG` | native decls 0x036ab0‑0x036ac0 | Hook to return `0` (no root / no emulator / no debugger) |
| `...detect.RiskDetect.isRT/isSMT/isDG` | 0x036cf8 / 0x036d30 / 0x036cc0 | Hook to return a `RtResult`/`SmtResult` with `code=0` |
| `...detect.bean.RtResult.getCode` / `isBasicRootInfo` / `isRootSPInfo` / `isHookInfo` | getters around 0x036e94‑0x036f50 | Force `0`/`false` |
| `...riskinfocollect.proguard.i.a(...)` | 0x0387b0 | Hook/fake the returned JSON (root fields `m,n,c,d,e` and DRM `u0`) |
| `...riskinfocollect.proguard.h.a()` | 0x038750 | Return cached/fake DRM ID (avoids MediaDrm + widevine service start) |
| `com.hihonor.secure.android.common.detect.DetectUtil.isRooted()` | 0x17c384 | Return `false` (`S.idj`/`S.irtj` short‑circuit) |
| `com.hihonor.secure.android.common.detect.RootDetect.isRoot()` | 0x17c67c | Return `false` (currently no static caller) |
| `com.hihonor.secure.android.common.detect.SecurityDetect.idj/iej/irpj` | 0x17c7a4 / 0x17c804 / 0x17c864 | Return `false` (no `irtj` wrapper exists) |
| `com.hihonor.secure.android.common.detect.S.idj/iej/irtj` | 0x17c980 (native decls; `irtj` impl in libhisec 0x234c) | Hook Java natives or patch libhisec |
| `com.hihonor.gamecenter.gamesdk.core.net.utils.DetectUtil.isRooted()` | 0x26b364 | Return cached `false`; stops game SDK root flag/cookie |
| `...gamesdk.core.utils.cookie.DeviceInfo.rootStatus` / `CookieCenter.COOKIE_KEY_ROOT` | classes15 | Blank the cookie value if game H5 must not see root |
| `com.hihonor.wallet.business.loan.infra.web.ItH5ContainerUtils$H5DeviceInfo.getRootStatus()` | 0x10e198 | Return `"0"`/`""` for wallet loan H5 |
| `com.trustdecision.mobrisk.TDRisk` / `TDDeviceManager` | `classes9` | Block init (`TDRisk.initWithOptions` at 0x3569a0) or hook native `isRoot` results; also removes `OPTION_DRM_ID` collection risk |

### 5.2 Native patches

| Library | VA | Patch |
|---|---|---|
| `libhonordetect.so` | `isRT` **0x5cd4**, `isSMT` **0x5fc8**, `isDG` **0x6548** | `mov w0,#0 ; ret` (`0x52800000 0xd65f03c0`) — returns "clean" |
| `libhisec.so` | `irtj` **0x234c** (root), `idj` **0x14dc** (anti‑debug), `iej` **0x18ac** (emulator) | `mov w0,#0 ; ret`; or redirect the JNINativeMethod table at **0x1bc90/0x1bca8/0x1bcc0/0x1bcd8** (name/sig/fn triples) to stubs and patch `JNI_OnLoad` (0x2568) to register stubs |
| `libhisec.so` `irpj` **0x229c** | signature allow‑list (24 SHA‑256 at `0x1bb28`) | patch compare loop to always succeed or always fail, only if anti‑tamper is in scope |
| `libtdcoreplugin.so` | su path block around string refs **0xa188–0xa250** (`/data/local/su`, `/system/bin/su`, …, `/sbin/su`), `/proc/self/maps` at 0x5558 | Patch the `xc_util_is_root` logic/return; lib is loaded via `com.trustdecision.android.bugly.NativeBugly.<clinit>` (`classes9` 0x1ba174: `System.loadLibrary("tdcoreplugin")`) |
| `libtrustdevice.so` | `JNI_OnLoad` 0x6da30 | Obfuscated/VM‑style; hook exported Java entry points instead |
| `libods.so` | `JNI_OnLoad` 0x298b4; `getwbwk` 0x298ac, `wbg_decrypt` 0x29740, `honor_aes_gcm_decrypt` 0x2960c | Not root related; only relevant if cloud‑crypto payloads are in scope |

### 5.3 Filesystem / environment hide points (what the detectors actually look at)

- **`libhisec` `irtj`**: `ro.secure` must not be `0`; scans `su` in `/system/bin`, `/system/xbin`, `/system/sbin`, `/system/bin/.ext`, `/system/sd/xbin`, `/system/usr/we-need-root`, `/system/vendor/bin`, `/system/vendor/xbin`, `/product/bin`, `/product/xbin`, `/data/local/tmp`, `/data/local/bin`, `/data/local/xbin`, `/data/local`, `/system/bin/failsafe`, `/sbin`, `/vendor/bin`; plus `/magisk`. **Observed real hit: `/data/local/tmp/su`.**
- **`libhisec` `iej`**: `init.svc.vbox86-setup|droid4x|qemud|su_kpbs_daemon|noxd|ttVM_x86-setup|xxkmsg|microvirtd`, QEMU/Genymotion/Nox/BlueStacks files under `/system/bin`, `/system/lib`, `/data/.bluestacks.prop`.
- **`libhisec` `idj`**: `/proc/<pid>/status` `TracerPid`, `/proc/net/tcp` (23946/android_server), process names `android_server`, `android_server64`.
- **`libhonordetect` `isRT`**: `/magisk`, `/su`, `/cache/.disable_magisk`, `ro.secure` (must be `1`), `ro.build.tags` (not `test-keys`), `/proc/self/maps` (frida/Xposed/LSPosed maps).
- **`libhonordetect` `isSMT`**: emulator props/`/proc/cpuinfo` and Magisk/Riru/LSPosed/Xposed/Frida/`/data/adb/*` path list (strings at 0x5e00‑0x6540).
- **`libhonordetect` `isDG`**: `/proc/net/tcp` with `:5D8A` (23946), `Debug.isDebuggerConnected`, `/proc/<pid>/status` TracerPid.
- **`libtdcoreplugin`**: `su` at `/data/local/su`, `/data/local/bin/su`, `/data/local/xbin/su`, `/system/xbin/su`, `/system/bin/su`, `/system/bin/.ext/su`, `/system/bin/failsafe/su`, `/system/sd/xbin/su`, `/system/usr/we-need-root/su`, `/sbin/su`, `/su/bin/su`; `/proc/self/maps`.
- **Device reality check**: SELinux was `permissive=1`; the app's `platform_app_36` domain could stat `/data/local/tmp/su` (AVC denial logged only for `/proc/net/tcp` reads). A hide solution must also cover `/proc/net/tcp`, `/proc/self/maps`, `ro.secure`, `ro.build.tags`, and `Debug.isDebuggerConnected`; simply hiding `su` binaries is insufficient.

### 5.4 DRM‑side hook points

- `proguard.h.a()` 0x038750 (plugin) — return a fixed/empty DRM ID to prevent the lazy Widevine service from starting and to avoid `DeviceID` provisioning.
- `android.media.MediaDrm#getPropertyByteArray("deviceUniqueId")` — generic hook for all paths (FIDO `uq3.b` 0x290d5c, risk collector).
- `MediaDrm#<init>(UUID)` — log/block only if the goal is service‑start suppression; blocking globally may break legitimate playback in other apps.
- Note: faking the DRM ID can itself be a risk signal server‑side; and the L3/L1 state is determined by `liboemcrypto.so`/keybox, not by the app.

---

## 6. What is confidently established vs open

**High confidence**
1. Package/version/process map and the two root‑detection stacks (`libhisec`/`libhonordetect`) with exact offsets, strings and JNI tables.
2. `libhonordetect` was loaded from the `Kit_Data_Collector` plugin and its `isRT/isSMT/isDG` results are cached as `"1"/"0"` fields in the risk payload.
3. `libhisec` `irtj` actually ran and detected `/data/local/tmp/su` on 2026‑10‑28 14:32:52.720.
4. The Widevine lazy service start at 14:32:52.848 was caused by `MediaDrm(UUID=edef8ba9-79d6-4ace-a3c8-27dcd51d21ed).getPropertyByteArray("deviceUniqueId")` in the risk collector (`proguard.h.a`, caller `proguard.i.a`), not by playback.
5. There is **no `HwSecurityDiagnose`** anywhere in the APK/plugins, and no `persist.sys.root.status` read by the app.
6. No local root‑gating of DRM/attestation/key provisioning; DRM ID collection is unconditional apart from an in‑memory cache.
7. No AI‑sidebar (`hndockbar`/`magicvoice`) integration; Honor ID exposes a KitAssistant **permission/scope** service and account providers, but no root/DRM payload to them.
8. Exported identity endpoints: `HnIDProvider` (exported=true, no permission; `deviceUniqueId`/`honor_id_account_status` queries), `CloudAccountService`/`HnCloudAccountService`/`PPSChannelInfoService` (exported, no permission), `KitAssistantService` (exported, **normal** permission) — high confidence from manifest + `dumpsys`.

**Medium confidence / open**
1. The exact Java caller of the observed `S.irtj` invocation (static callers are `RootDetect.isRoot` (no users) and `DetectUtil.isRooted` (used by game SDK); runtime plugin `app_p_a/-1902912772.jar` is another candidate; the log has no stack).
2. `irpj` semantic (SHA‑256 allow‑list of 24 values; signature pinning is the best fit).
3. KitAssistant plugin payload (bundled JAR has no DEX; the running plugin is downloaded, so its business logic is not inspectable here).
4. Actual server‑side enforcement of root/DRM flags, and whether TDRisk's `OPTION_DRM_ID` is enabled in the IAP `:pay` path.

---

## 7. Evidence / artifact index

| Artifact | Purpose |
|---|---|
| `work/reverse/honor-id/out/c5_detect.txt` | dexdump of `com.hihonor.secure.*` (S, SecurityDetect, RootDetect, DetectUtil) |
| `out/kitdc.txt` | dexdump of `Kit_Data_Collector` (NativeLib, RiskDetect, RtResult, riskinfo `i`/`h` incl. MediaDrm) |
| `out/c12_drm.txt` / `out/c12_risk.txt` | base‑APK FIDO `uq3` MediaDrm getter + local riskinfo copy |
| `out/hisec_strrefs.txt`, `out/hd_strrefs.txt`, `out/td_strrefs.txt` | string‑xref maps for `libhisec`, `libhonordetect`, `libtdcoreplugin` |
| `out/global/*.txt` | per‑DEX cross‑reference scan for `SecurityDetect/RootDetect/TrustDevice/ODS` |
| `dexdump_filter.py`, `scan_string_refs.py`, `xref_arm64.py` | reproducible analysis scripts |
| `work/m6-recreate-log.txt` lines 6930‑6936, 6942, 7055‑7125 | runtime proof of libhisec/libhonordetect loads and Widevine service start |
| `extract/` | full APK extraction (DEX, libs, plugin JARs) |
