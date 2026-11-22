# AI 侧边栏 ROOT 检测静态分析报告

**Device:** Honor MLY-AN00 / MagicOS 10 / Android 16 / kernel 6.12.58
**Scope:** offline APKs in `work/ai-sidebar` only. No device pull, no reboot, no modification.
**Date:** 2026-10-28
**Analyst:** static analysis (Python DEX parser + aapt2 + dexdump; no full jadx decompile)

---

## 0. TL;DR

| Question | Answer |
|---|---|
| Which package implements the sidebar UI? | **`com.hihonor.magicvoice`** (YOYO Agent, v90.10.34.064), **not** `com.hihonor.assistant` and **not** `com.hihonor.aipluginengine`. |
| Which component hosts it? | `com.hihonor.magicvoice.startup.MagicFloatActivity` → `MainFragment` → `SidebarFragment` (DrawerLayout drawer). |
| Does it detect root? | **Yes**, via two independent native SDKs plus Alipay APS: `libhisec.so` (`DetectUtil`/`RootDetect`) and `libhonordetect.so` (`RiskDetect`). |
| Is the native sidebar list filtered locally on root? | **No local branch found.** The native sidebar list request (`SkillAgentManager.getSideBarAgentData` → `HosManager`) does **not** include root status. |
| Where does root status actually leak? | Into **WebView content**: Base64 `hshop_deviceInfo` cookie (`rootStatus:"1"/"0"`), H5 JS bridge `getAppDeviceInfo` (`isRoot`), and the AISO `deviceFallbackCertification` request (`rawData` JSON). |
| Most likely cause of “应用显示不全” | H5/server-side content filtering based on these exported root flags (agent-shop/`hshop` pages and H5 AI pages), not a local `if (root) hide` in `SidebarModel`. |
| `HwSecurityDiagnoseManager` / `getRootStatusSync` / `IHwSecurityDiagnosePlugin` / `ASSET_COMMON` / `persist.sys.root.status` | **Not present** in any of the 7 APKs (dex byte scan + dex string tables + resource strings); also absent from the two magicvoice native detector libs. They appear to be framework/system-service APIs, not referenced by these packages by name. |

---

## 1. Package / activity identification

### 1.1 Evidence table (all 7 APKs)

| APK | Package / version | Sidebar UI classes | App-level root detection | Verdict |
|---|---|---|---|---|
| `com.hihonor.magicvoice-base.apk` (499 MB, 40 dex) | `com.hihonor.magicvoice` 90.10.34.064 / “YOYO 智能体” | **1219** matching `Sidebar*`/root classes: `frameworkui/scene/full/sidebar/**`, `SidebarFragment`, `SidebarModel`, `SidebarDelegate`, `SidebarContainerLayout`, `SidebarListAdapter` | **Yes**: `com.hihonor.secure...DetectUtil/RootDetect`, `com.hihonor.aiso...SecurityDetectUtils`, `com.hihonor.cloudservice.usm.skit.detect.RiskDetect`, Alipay APS | **Owner** |
| `com.hihonor.assistant-base.apk` (82 MB) | `com.hihonor.assistant` 11.0.3.315 / “YOYO 建议” | 0 `Sidebar*` classes (`sidebar` string only in a uikit resource name) | 0 root classes; only okhttp `TrustRootIndex`/`ro.debuggable` | Not the sidebar UI |
| `com.hihonor.aipluginengine-base.apk` (167 MB) | `com.hihonor.aipluginengine` 7.1.9.740 / “荣耀 AI · 基础服务” | 0 `Sidebar*` classes; the 9/8 `sidebar` byte hits are uikit drawable resource names (`icsvg_public_sidebar_*`) plus one Brotli-dictionary blob | 0 root classes; `isRoot`/`commonIsRoot` only appear as method/field names, not a detection path | Not the sidebar UI |
| `com.hihonor.brain-base.apk` | `com.hihonor.brain` 11.0.0.739 / “智慧决策” | 0 | only `SceneDebugUtils.isRootEnabled` (debug-tree flag); “安全检测不合规” belongs to `Erase.initVisionSdk` (photo erase), unrelated | Not the sidebar UI |
| `com.hihonor.voiceengine-base.apk` | `com.hihonor.voiceengine` 11.0.34.2 | 0 | 0 app-level detection | No |
| `com.hihonor.smartiot-SmartIot.apk` | `com.hihonor.smartiot` 11.0.0.6 | 0 | 0 | No |
| `com.honor.aimm-AIModelManager.apk` | `com.honor.aimm` 11.0.3.038 | 0 | 0 | No |

### 1.2 Concrete UI evidence in `com.hihonor.magicvoice`

- Manifest activity (`AndroidManifest.xml` line=3523):
  `com.hihonor.magicvoice.startup.MagicFloatActivity`
  `exported=false`, `taskAffinity="com.hihonor.magicvoice.float.new"`, `launchMode=2`, `resizeableActivity=true`, `showOnLockScreen=true`, label `@0x7f130390`.
- `MagicFloatActivity` injects `MainFragment` and queries the drawer:
  `Lcom/hihonor/magicvoice/startup/MagicFloatActivity$4;->onFragmentViewCreated(...)` string `"onFragmentViewCreated: MainFragment listener injected"`;
  `MagicFloatActivity;->isSidebarOpenFromMainFragment()Z` calls `SidebarInternalView.isSidebarOpen()`.
- `MainFragment` creates the drawer:
  `Lcom/hihonor/magicvoice/frameworkui/scene/full/mainfragment/MainFragment;->initDelegates()` → `SidebarDelegate.<init>`, `initDrawerLayout`, `initSidebarFragment`, `openSidebar/closeSidebar/toggleSidebar`.
- Drawer fragment:
  `Lcom/hihonor/magicvoice/frameworkui/scene/full/sidebar/view/SidebarFragment` (extends `androidx.fragment.app.Fragment`), `initMVP()` creates `SidebarModel` + `SidebarPresenter`.
- Layout/resource IDs (from `aapt2 dump resources`):
  - `0x7f0d03fa layout/fwk_fragment_sidebar_v1` (`fwk_fragment_sidebar_v1.xml`)
  - `0x7f0a210a id/sidebar_layout`, `0x7f0a210b id/sidebar_list`
  - `0x7f131bfc string/sidebar_item_agent_shop` = **“探索” / “Explore”**
  - `0x7f131c08 string/sidebar_item_recent_agent` = “最近使用的智能体”
  - `0x7f1308ab` / `0x7f1308ac` = “以下服务将固定显示在 YOYO 侧边栏” / “以下服务将在 YOYO 侧边栏不可见”
  - `0x7f081801/0x7f081802 drawable/icsvg_hnyoyo_sidebar_switch_{off,on}`
  - `0x7f081d26..0x7f081d2d drawable/icsvg_public_sidebar_*`
- App strings call it **“YOYO 侧边栏”** (“YOYO sidebar”), e.g. string #86659/#86673/#86674/#86675, plus “收起侧边栏/展开侧边栏” (#89204/#89205). The literal label **“AI侧边栏” is not in this APK**; it is the Settings-app marketing label (`设置 > 荣耀AI & YOYO > AI侧边栏`). In-package name is YOYO sidebar.

**Conclusion:** the sidebar implementation among the supplied APKs is `com.hihonor.magicvoice`, hosted by `MagicFloatActivity` + `MainFragment` + `SidebarFragment`. `com.hihonor.assistant` only supplies YOYO suggestion cards and `com.hihonor.aipluginengine` supplies AI engine/plugin services; neither contains a sidebar view.

---

## 2. Root-detection paths (exact classes/methods)

All paths below are defined **inside the magicvoice APK** (bundled SDK code); none are in `assistant` or `aipluginengine`.

### 2.1 Honor “hisec” detection — `DetectUtil` / `RootDetect` (classes19.dex)

| Item | Value |
|---|---|
| Entry | `Lcom/hihonor/secure/android/common/detect/DetectUtil;->isRooted()Z` (public static) |
| Implementation | calls `Lcom/hihonor/secure/android/common/detect/S;->idj()Z` **and** `S;->irtj()Z` |
| Native | `S.idj()` / `S.irtj()` are `public static native` (`code_off=0`), loaded from **`libhisec.so`** (`System.loadLibrary("hisec")` in `S.<clinit>`) |
| Secondary wrapper | `Lcom/hihonor/secure/android/common/detect/RootDetect;->isRoot()Z` → `S.irtj()`; helpers `a()` (su in PATH), `b()` (magisk), `c()` (test-keys), `e()` (ro.secure == 0), `d()` (emulator) |
| Native checks (`lib/arm64-v8a/libhisec.so`) | `check su exists`, `check magisk exist`, `check ro.secure error`, `/system/usr/we-need-root`, `/magisk`, `init.svc.su_kpbs_daemon`, `ro.secure` |
| Log tag / message | tag `RootDetect`, message `"SD.irtj isRoot exception : "`; tag `SDUtils` for SDK errors |

Verified code:
```
DetectUtil.isRooted():
    invokes S.idj()Z
    invokes S.irtj()Z
RootDetect.isRoot():
    invokes S.irtj()Z
```

### 2.2 Honor “usm skit” detection — `RiskDetect` / `NativeLib` (classes37.dex)

| Item | Value |
|---|---|
| Entry | `Lcom/hihonor/cloudservice/usm/skit/detect/RiskDetect;->isRT()Lcom/hihonor/cloudservice/usm/skit/detect/bean/RtResult;` (public static) |
| Native | `Lcom/hihonor/cloudservice/usm/skit/detect/NativeLib;->isRT()I` (`static native`, `code_off=0`), loaded from **`libhonordetect.so`** (`System.loadLibrary("honordetect")`) |
| Result bean | `RtResult.isBasicRootInfo()Z`, `RtResult.isRootSPInfo()Z`, `RtResult.isHookInfo()Z` |
| Aggregation | `Lcom/hihonor/aiso/network/utils/SecurityDetectUtils;->isRoot()Z` returns true if any of the three `RtResult` flags is true (private static) |
| Sibling checks | `RiskDetect.isDG()` (debuggable), `RiskDetect.isSMT()` (simulator) |
| Native strings (`libhonordetect.so`) | `/sbin/.magisk/modules/taichi`, `/sbin/.magisk/modules/riru_edxposed`, `/sbin/.magisk/modules/dreamland`, `/sbin/.magisk/modules/zygisk_lsposed`, `/sbin/.magisk/modules/riru_lsposed`, `/system/app/SuperUser`, `/system/xbin/noxsu`, `/cache/.disable_magisk`, `/magisk`, `/system/usr/we-need-root`, `ro.secure`, `init.svc.su_kpbs_daemon`; exports `Java_..._NativeLib_isRT/isSMT/isDG` |
| Log tag | `SDUtils`, `TokenRepositoryImpl` |

### 2.3 H5/agent-gallery path — `DeviceInfo.rootStatus` (classes25.dex)

This is the most relevant path to displayed content.

`Lcom/honor/agentGallery/basebusiness/web/manager/b;->c()Ljava/lang/String;` (obfuscated `SourceFile`) was disassembled with `dexdump -d`; exact sequence:

```
new DeviceInfo()
o2.c()                         -> DeviceInfo.g(String)   // udid property
DetectUtil.isRooted()          -> "1" / "0"               // rootStatus property
   const-string "1" (true) / "0" (false)
DeviceInfo.f(String)           // setter stores backing field b = rootStatus
DetectUtil.isProxy(context)    -> "1" / "0"
DeviceInfo.e(String)           // proxyStatus property
... pkg/version/cert/wifi ...
Moshi adapter -> JSON string "deviceInfoStr"
```

`DeviceInfo` JSON keys (from generated `DeviceInfoJsonAdapter`):
`udid, rootStatus, proxyStatus, pkgName, deviceCategory, appVersion, certResult, wifiSSID, appVerifyResut`

Bytecode cross-check: the JSON writer’s `rootStatus` branch calls getter `DeviceInfo.g()`, which returns backing field `b`; setter `DeviceInfo.f(String)` writes the same field `b`. So the `"1"/"0"` produced from `DetectUtil.isRooted()` lands exactly in JSON key `rootStatus`.

Cookie setter `Lcom/honor/agentGallery/basebusiness/web/manager/b$a;->a()V`:
```
b.a(b)                        // returns b.c() deviceInfoStr
getBytes(UTF_8)
Base64.encodeToString(..., 0)
Pattern.matcher(...).replaceAll("")
String.format("hshop_deviceInfo=%s", base64)
CookieManager.setCookie(url, ...)
CookieManager.flush()
```
Log tag: `WebViewManager`; cookie names: `hshop_accessToken`, `hshop_appid`, **`hshop_deviceInfo`**.

So every `hshop`/agent-gallery WebView receives a Base64 JSON blob with **`rootStatus:"1"`** on a rooted device.

### 2.4 H5 JS bridge — `DeviceMethods$StatusInfo` (classes38.dex)

- `Lcom/hihonor/hm/h5/container/js/method/DeviceMethods;->getAppDeviceInfo(Lorg/json/JSONObject;)V` builds `DeviceMethods$Info` = `AppInfo` + `DeviceInfo` + **`StatusInfo`** and returns it via `callbackSuccess`.
- `StatusInfo` fields include **`isRoot:Z`** (and `proxyStatus:Z`). Constructor calls `DetectUtil.isRooted()`; on exception logs tag `DeviceMethods`, message `"DetectUtil.isRooted error:"`.
- Any H5 page loaded by magicvoice’s `com.hihonor.hm.h5.container` can call `getAppDeviceInfo` and read the `isRoot` field.

### 2.5 AISO token fallback — `SecurityDetectUtils` → `deviceFallbackCertification` (classes37.dex)

- `SecurityDetectUtils.getSecurityDataJson()` builds:
  `{"rootStatus": isRoot(), "debugStatus": isDG(), "simulatorStatus": isSmt(), "apkSignature": <sha256>}`
- `SecurityDetectUtils.getEncryptedRawData()` encrypts it (`ThirdPartEncrypt`, `hihonor/tk1.png`…`tk3.png`, AES-GCM).
- `com.hihonor.aiso.network.token.data.TokenRepositoryImpl;->deviceFallbackCertification(...)` puts it in `FallbackTokenRequest.rawData` and calls endpoint **`v1/apiGateWay/deviceFallbackCertification`**.
- Normal path is `getRemoteToken` → `v3/apiGateWay/deviceCertification` with a HUKS certificate chain (`HuksUtilsKt.generateCertChain`). `TokenUseCase.getRemoteToken()` also invokes the fallback path (`ITokenRepository.deviceFallbackCertification`); the fallback is the branch that carries `SecurityDetectUtils.getEncryptedRawData()`.
- Log tag: `TokenRepositoryImpl`.

**Interpretation:** on devices where HUKS/key attestation fails (common after root/bootloader unlock), the fallback request explicitly reports `rootStatus:true` to Honor’s gateway. The server can then restrict AI capabilities. This is server-side gating; no local UI branch is involved.

### 2.6 Alipay APS (secondary, payment SDK)

`classes24.dex` contains Alipay `alipaysecuritysdk`:
`BICDataUtil.buildSecData2JSONByCache/getGlobalSecDataJson/secData2Json` → `BICDataModel.getRootStatus`, with strings `/system/xbin/su`, `test-keys`, `rootStatus`. This is for payment/member pages, not the sidebar content. Include only as a secondary detection surface.

---

## 3. What is actually gated by root?

### 3.1 Verified data paths (code-level)

| Detection result | Consumer | What it can affect |
|---|---|---|
| `DetectUtil.isRooted()` → `"1"` | `agentGallery b.c()` → `DeviceInfo.rootStatus` → `hshop_deviceInfo` cookie | H5 pages in agent shop / “探索” can read it and hide/omit cards |
| `DetectUtil.isRooted()` → `isRoot` | `DeviceMethods$StatusInfo` → H5 `getAppDeviceInfo` | any magicvoice H5 page can hide content |
| `SecurityDetectUtils.isRoot()` → `true` | `getSecurityDataJson().rootStatus` → `FallbackTokenRequest.rawData` | AISO/AI token server may downgrade/refuse AI content |
| Alipay `BICDataModel.getRootStatus` | Alipay payment/member WebView | payment/member flows, not sidebar list |

### 3.2 Verified negative: native sidebar list is not locally gate

- `Lcom/hihonor/magicvoice/frameworkui/skills/core/SkillAgentManager;->getSideBarAgentData()` builds the HOS request body with:
  `"deviceInfo"` = `Lcom/hihonor/magicvoice/frameworktempbase/util/FwHosUtil;->generateDeviceInfo()`.
- `FwHosUtil.generateDeviceInfo()` contains only:
  `udid`, `appFeatureCode`, `userId`, `privacySwitch`, `ueoSwitch`, `magicOsVersion` (`ro.build.version.magic`).
  **No rootStatus / root / debug / simulator field.**
- `AgentRepositoryImpl.requestAgentListFromCloud()` posts to `/aicloud/uc/personal-data/v1/customResource/list` with a body of privacy switches only; headers carry udid/device model/account token (`SkillHeaderHelper`), no root field.
- `RecentRecommendAgentRegionFeature` / `SkillStoreAgentRegionFeature` never call `DetectUtil`/`SecurityDetectUtils`/`RootDetect`.
- The sidebar's **cloud** agent list is produced by `SkillAgentManager.getSideBarAgentData()` (HOS `generateDeviceInfo`) and `AgentRepositoryImpl.requestAgentListFromCloud()` (`customResource/list`); neither request carries root status. Therefore **the native sidebar item list is not filtered by root status locally**.

### 3.3 “应用显示不全” strings

No string matching `应用显示不全` exists in any of the 7 APKs. Related strings found and ruled out:

| String | Owner | Relevance |
|---|---|---|
| `安全检测不合规` | `com.hihonor.brain...photoedit.tools.erase.Erase.initVisionSdk` (classes.dex) | photo erase feature, not sidebar |
| `以下服务将在 YOYO 侧边栏不可见` (0x7f1308ac) | magicvoice sidebar service picker | normal user toggle to hide services |
| `%d张图片不符合平台规则，已过滤` | magicvoice image feature | image filtering, unrelated |
| `当前照片头部存在遮挡或显示不全` | magicvoice photo feature | camera/photo, unrelated |

So there is **no localised UI string** that says “content hidden because root”. If content is missing, it is hidden by the remote H5/server logic that consumes the exported flags. The 684 bundled js/html/json/xml assets (<8 MB each) were also scanned for `显示不全` / `应用显示` / `应用内容`: zero hits.

### 3.4 Most likely causal chain

1. App starts (MagicFloatActivity) and loads sidebar + agent-shop pages.
2. Any agent-gallery/`hshop` WebView load runs `b$a.a()`, which Base64-encodes `DeviceInfo` with `rootStatus:"1"` into the `hshop_deviceInfo` cookie.
3. The remote H5 (or the H5 `getAppDeviceInfo` caller) sees `rootStatus/isRoot` and renders a reduced list (hidden apps/agents/cards).
4. In parallel, if the HUKS device certificate fails, `deviceFallbackCertification` reports `rootStatus:true`; the AI gateway can restrict content server-side.
5. The native sidebar list itself is not root-gated, so if only native agents are missing, root is probably not the direct cause (check account/network/minors mode).

---

## 4. Log tags and strings to watch

| Tag / message | Owner |
|---|---|
| `RootDetect`, `SD.irtj isRoot exception : ` | `com.hihonor.secure.android.common.detect.RootDetect` |
| `SDUtils` | `SecurityDetectUtils` / secure SDK |
| `TokenRepositoryImpl` | AISO token/fallback |
| `WebViewManager`, `hshop_deviceInfo` | agentGallery WebView cookie |
| `DeviceMethods`, `DetectUtil.isRooted error:` | H5 JS bridge |
| `H5Logger` | H5 container |
| `SidebarModel`, `RecentRecommendAgent`, `SkillStoreAgent`, `SkillAgentManager->`, `AgentRepositoryImpl->` | native sidebar data |
| `SkillHeaderHelper`, `getHeaderParams: %s` | sidebar cloud headers |
| `RootDetect` / `S` `load so throwable : ` | libhisec load failures |

Useful `logcat` filters (for the parent, not executed here):
`RootDetect|SDUtils|TokenRepositoryImpl|WebViewManager|DeviceMethods|SidebarModel|RecentRecommendAgent|SkillStoreAgent`

---

## 5. Confidence

### 5.1 Not verified (explicit)

- **Remote code**: the actual `if (rootStatus) hide` decision in the `hshop`/agent-gallery H5 or Honor gateway is not in the APK; only the data export is proven.
- **Settings label ownership**: the literal `AI侧边栏` lives in the Settings app, not in these APKs; the mapping to magicvoice’s “YOYO 侧边栏” is inferred from feature/resource match.
- **Runtime invocation frequency**: the hook points are present in bytecode; we did not run the app to confirm every page load executes `b$a.a()`.
- **Framework API involvement**: `HwSecurityDiagnoseManager` classes may exist in `/system/framework`, but these APKs do not reference them by name.

### 5.2 Claim confidence

| Claim | Confidence | Basis |
|---|---|---|
| Sidebar UI owner is `com.hihonor.magicvoice` | **High (0.9)** | 1219 sidebar/root-related class descriptors, layout/string resource IDs, manifest host activity; assistant/aipluginengine have no sidebar UI |
| “AI侧边栏” == this YOYO sidebar | **Medium-high (0.75)** | Settings label is external; in-package strings consistently say “YOYO 侧边栏” and the feature set (推荐/最近使用/探索) matches the AI sidebar description |
| Root detection code exists and runs | **High (0.95)** | Java + native symbols (`libhisec.so`, `libhonordetect.so`) + exact bytecode |
| `rootStatus` exported to H5 cookie / JS bridge / AISO fallback | **High (0.95)** | `dexdump` bytecode and JSON/cookie strings |
| Native sidebar list is not locally root-gated | **High (0.9)** | `generateDeviceInfo`/`customResource/list` bodies contain no root field; no detection calls in sidebar model |
| Root status causes the observed “content incomplete” | **Medium (0.5–0.6)** | Data export is proven; the actual hide decision is in remote H5/server code not present in the APK |
| `HwSecurityDiagnoseManager` etc. are involved | **Very low / ruled out for these APKs** | 0 occurrences in all 7 APKs’ dex/string tables (and magicvoice `.so` strings) |

---

## 6. Fix options

> These are analysis options, not executed. Do not modify the device as part of this report.

### Option A — Hook the Java detection surface (recommended, least invasive)

Scope: `com.hihonor.magicvoice` (LSPosed/zygisk module or runtime instrumentation).

Hook these to return false/0:

1. `Lcom/hihonor/secure/android/common/detect/DetectUtil;->isRooted()Z` → `false`
   - This alone fixes `DeviceInfo.rootStatus` and `DeviceMethods$StatusInfo.isRoot`, because both call this method.
2. `Lcom/hihonor/aiso/network/utils/SecurityDetectUtils;->isRoot()Z` → `false`
   - Removes `rootStatus:true` from the AISO fallback JSON.
3. (Defensive, only if something bypasses #1) `Lcom/hihonor/secure/android/common/detect/S;->idj()Z` / `irtj()Z` (native static) → `false`; or inline-hook `libhisec.so` exports.
4. (Defensive) `Lcom/hihonor/cloudservice/usm/skit/detect/NativeLib;->isRT()I` → `0` (`libhonordetect.so`), or hook `RiskDetect.isRT()` to return a `RtResult` with all flags false.
5. (Optional) `com.honor.agentGallery...b;->c()` / `DeviceInfo.f(String)` to force `"0"` if the cookie must be neutral even if #1 is bypassed.

Caveat: server-side HUKS/attestation and the fallback gateway can still detect a modified/rooted environment; hooking only changes the client-reported flag.

### Option B — Root-hide environment

- Magisk DenyList / Zygisk hide for `com.hihonor.magicvoice` (and only if needed `com.hihonor.assistant`, `com.hihonor.aipluginengine`; they have no detection code).
- Hide/rename the paths checked by the native libs:
  - `su` anywhere in `PATH`; `/system/usr/we-need-root`; `/magisk`
  - `/sbin/.magisk/modules/{taichi,riru_edxposed,dreamland,zygisk_lsposed,riru_lsposed}`
  - `/system/app/SuperUser`; `/system/xbin/noxsu`; `/cache/.disable_magisk`
- Hide/report as absent: `init.svc.su_kpbs_daemon`
- Reset props to stock-looking values: `ro.secure=1`, `ro.debuggable=0`, `ro.build.tags=release-keys`
- Caveat: `libhisec` explicitly checks `ro.secure`; `libhonordetect` checks Magisk module paths. HUKS attestation can still fail and trigger the fallback with `rootStatus:true`.

### Option C — APK patch / repack (not recommended)

- Patch smali so `DetectUtil.isRooted()` and `SecurityDetectUtils.isRoot()` return `false`; force `DeviceInfo.f("0")`.
- Requires bypassing the system-app signature/privilege checks and re-signing; risks breaking privileged permissions, OTA, and payment SDKs. Prefer Option A.

### Option D — If the missing content is server-side only

If the H5/server filters on `rootStatus`, client-side hooks must cover every reporting path (H5 cookie + JS bridge + fallback cert). If the gateway independently attests the device, a client patch cannot restore content; a server allowlist or an unrooted device is the only reliable fix.

---

## 7. Artifacts and reproduction

All under `work/ai-sidebar/analysis/`:

| File | Content |
|---|---|
| `scan_terms.out` | per-APK/per-dex keyword counts for root/sidebar terms |
| `com.hihonor.magicvoice-base.classes.txt` | 1219 sidebar/root-related class descriptors |
| `dump_securitydetectutils.txt` | `SecurityDetectUtils` methods/strings/invokes |
| `dump_riskdetect.txt` | `RiskDetect`, `NativeLib`, `RtResult` |
| `dump_rootdetect.txt` | `DetectUtil`, `RootDetect`, `SecurityDetect` |
| `dump_b.txt`, `dexdump25.txt` | `agentGallery b.c()` and `hshop_deviceInfo` cookie bytecode |
| `dump_devicemethods.txt` | H5 `DeviceMethods$StatusInfo` |
| `dump_tokenrepo.txt` | AISO fallback token path |
| `dump_sidebarmodel.txt`, `dump_sidebarfragment.txt`, `dump_mainfragment.txt` | sidebar UI/data classes |
| `dump_fwhosutil.txt`, `dump_skillagentmgr.txt`, `dump_agentrepo.txt` | native sidebar data requests (no root) |
| `magicvoice.resources.txt` | resource IDs for sidebar layouts/strings |
| `so/libhisec.so`, `so/libhonordetect.so` | extracted native detectors |

Key commands used:

```powershell
aapt2 dump xmltree --file AndroidManifest.xml <apk> > manifest.xml
aapt2 dump resources <apk> > resources.txt
aapt2 dump strings <apk> > strings.txt
dexdump -d classesN.dex > dexdumpN.txt
python dump_class.py classesN.dex '<class regex>'
```

No device commands were run; no APK on the device was modified.
