# Honor `HwSecurityDiagnoseManager.getRootStatusSync()` — real provider, cache and bypass analysis

Device: HONOR `MLY-AN00` (`ro.build.fingerprint=HONOR/MLY-AN00/HNMLY:17/HONORMLY-AN00/11DLDLD111SP7C00E111:user/release-keys`, `ro.build.id=HONORMLY-AN00`).
Scope: **read only**. No system/vendor partition change, no remount, no reboot, no root install, no data clear.
All paths below are relative to `C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260`.

---

## 0. TL;DR

The implementation behind

```text
HwSecurityDiagnoseManager.getRootStatusSync()
  -> IHwSecurityService.querySecurityInterface(2)
  -> IHwSecurityDiagnosePlugin.getRootStatusSync()
```

is **not** the `com.hihonor.securityserver` APK. It is Honor code inside **`/system/framework/services.jar`, running in `system_server`**:

```text
system_server
  com.android.server.security.HwSecurityService               (SystemService)
    -> com.hihonor.server.security.HwSecurityServiceProxy      (registered as binder "securityserver")
       -> HwSecurityDiagnosePlugin (resident plugin id 2, in the same process)
          -> AppLayerStpProxy.getRootStatusSync()
          -> HwStpHidlAdapter.stpGetStatusByCategory(8)         (STP_ROOT_THREAT=8)
          -> vendor.honor.hardware.hwstp.IHwStp/default
             served by /vendor/bin/hw/vendor.honor.hardware.security-service (security-hal)
             -> /vendor/lib64/libstp.so StpGetStatusByCategory()
                -> Unix socket "/dev/socket/hisecd", cmd 2002, key 8
                   -> /vendor/bin/hisecd
                      -> /vendor/etc/hisecd/stp.conf checks + /proc/kernel_stp
                      -> status cached/persisted in OEMINFO (`oeminfo_root_info`)
```

The live root decision is therefore in **native `hisecd` / kernel STP / OEMINFO**, not in HUKS/ASSET and not in `persist.sys.root.status`.

The parallelspace dialog is a second, independent gate:

```text
com.hihonor.parallelspace InitActivity.onCreate
  -> parallel.g1.e()  (returns 1 = block)
     -> HwSecurityDiagnoseManager.getRootStatusSync()
     -> if (status == 0 || msc.parallelspace.debug_mode == 1 || g1.c() == 0)
           allow
        else
           block (dialog)
```

`HnSecurityServer.apk` registers **`security_server`** (underscore), a different binder used for `ISecurityServer`/`DeviceHealthService`. Killing it does not remove **`securityserver`**. Killing `hisecd`/`system_server` does not clear the STP judgment and, worse, makes the framework return a negative error code which is also non-zero and therefore still treated as root.

---

## 1. Component / process map

| Binder / process | Owner | Implementation | Role |
|---|---|---|---|
| `securityserver` | **system_server** | `com.android.server.security.HwSecurityService` + `com.hihonor.server.security.HwSecurityServiceProxy` in `services-magic.jar` | Real `IHwSecurityService`; returns plugin binders, including id 2 |
| `security_server` | `com.hihonor.securityserver` app | `com.hihonor.securityserver.HwSecurityService` / `ISecurityServer$Stub` in `HnSecurityServer.apk` | Auxiliary device-health/security service; **not** the diagnose service |
| `vendor.honor.hardware.hwstp.IHwStp/default` | `vendor.honor.hardware.security-service` (`security-hal`, PID 2023 in `stp-inspect.txt`) | `/vendor/bin/hw/vendor.honor.hardware.security-service` + `libstp.so` | Vendor AIDL STP front-end |
| `hisecd` socket | `hisecd` (`/vendor/bin/hisecd`, system) | native STP engine | Computes/loads/persists STP status, including root category 8 |
| HUKS plugin | `com.hihonor.securityserver` app (split `huksplugin`) | `HwKeystoreServiceImpl` + `libhwkeystore_jni.so` | Consumer of the same `getRootStatusSync`; ASSET root gate |
| parallelspace | `com.hihonor.parallelspace` | `InitActivity` + `parallel.g1` | Shows the root dialog |

Evidence for the two different binder names:

```text
dumpsys -l:
  security_server
  securityserver
```

`HnSecurityServer.apk` `HwSecurityService.registerServiceManager()` uses literal `"security_server"`:

```text
13f5c2: const-string v0, "security_server"
13f5ca: invoke-static {v0, v2}, Lcom/hihonor/android/os/ServiceManagerEx;.addService:(Ljava/lang/String;Landroid/os/IBinder;)V
```

`HwSecurityServiceProxy.onStart()` uses literal `"securityserver"`:

```text
2a7942: const-string v1, "securityserver"
2a7946: invoke-static {v1, v0}, Lcom/hihonor/android/os/ServiceManagerEx;.addService:(Ljava/lang/String;Landroid/os/IBinder;)V
```

The app binder is `ISecurityServer$Stub`:

```text
Class descriptor  : 'Lcom/hihonor/securityserver/HwSecurityService$1;'
Superclass        : 'Lcom/hihonor/securityserver/ISecurityServer$Stub;'
```

So `com.hihonor.securityserver` can be killed/restarted without removing the binder the framework uses.

---

## 2. Exact Java/binder chain

### 2.1 Framework client

`framework-magic.jar` (dumped as `work/fw-classes.dex.txt`), class `Lcom/hihonor/android/securitydiagnose/HwSecurityDiagnoseManager;`:

Constructor (`0x379b9c`) gets and **caches** the binder:

```text
const-string/jumbo v0, "securityserver"
ServiceManagerEx.getService("securityserver")
IHwSecurityService$Stub.asInterface(...)
iput-object v1, mSecurityService
```

`getHwSecurityDiagnosePlugin()` (`0x3796e4`) calls:

```text
querySecurityInterface(2)   // plugin id 2
IHwSecurityDiagnosePlugin$Stub.asInterface(binder)
```

`getRootStatusSync()` (`0x3797d8`):

```text
ret = -2000
plugin = getHwSecurityDiagnosePlugin()
if (plugin != null) ret = plugin.getRootStatusSync()
catch RemoteException -> ret stays -2000
return ret
```

There is **no death recipient** for `mSecurityService`; if `system_server` restarts, a long-lived app can keep a dead binder and every call throws `RemoteException` -> `-2000`, which is non-zero and therefore still "root".

AIDL transaction codes (from framework `Stub$Proxy`):

| Interface/method | Transaction code |
|---|---|
| `IHwSecurityService.querySecurityInterface` | **3** (`const/4 v3, #3`) |
| `IHwSecurityService.unBind` | 2 |
| `IHwSecurityDiagnosePlugin.getRootStatusSync` | **4** (`const/4 v3, #4`) |
| `IHwSecurityDiagnosePlugin.getStpStatusByCategory` | 7 |

### 2.2 system_server publishes `securityserver`

`services-magic.jar` `classes.dex` (`work/svc-classes.dex.txt`), class `Lcom/android/server/security/HwSecurityService;`:

```text
Superclass : 'Lcom/android/server/SystemService;'
<init>  -> HwServiceSecurityPartsFactoryEx.getInstance()
           .getHwSecurityServiceProxy(context)
onStart -> proxy.onStart()
onBootPhase -> proxy.onBootPhase(phase)
```

`services-magic.jar` `classes2.dex` (`work/svc-classes2.dex.txt`), class `Lcom/hihonor/server/security/HwSecurityServiceProxy;`:

```text
onStart() @0x2a7910:
  new HwSecurityServiceWrapper
  ServiceManagerEx.addService("securityserver", wrapper)
  registerCorePlugins()
  registerOtherPlugins()

registerCorePlugins() @0x2a795c:
  if (IS_SUPPORT_HW_SECURE_DIAGNOSE) {
      obj = new HwSecurityPluginObj(this, flag=1, priority=500,
                                    HwSecurityDiagnosePlugin.CREATOR,
                                    null, false)
      registerPlugin(2, obj, 0)          // DEVICE_SECURE_DIAGNOSE_ID = 2
  }

queryInterface(2) @0x2a74b0:
  pluginObj = mMapPlugins.get(2)
  if (pluginObj.flag == 1 /* resident */) {
      checkPluginPermission(pluginObj)
      plugin = pluginObj.pluginRef.get()
      return plugin.asBinder()
  }
  return null
```

Constants in `HwSecurityServiceProxy`:

```text
DEVICE_SECURE_DIAGNOSE_ID = 2
RESIDENT_PLUGIN_FLAG      = 1
SECURITY_SERVICE          = "securityserver"
IS_SUPPORT_HW_SECURE_DIAGNOSE = SystemPropertiesEx.getBoolean("ro.config.support_securitydiagnose", ...)
```

`HwSecurityServiceWrapper.querySecurityInterface()` is a thin call into the private `queryInterface()` above. There is no second process.

### 2.3 The plugin itself

Class `Lcom/hihonor/server/security/securitydiagnose/HwSecurityDiagnosePlugin;`:

```text
Superclass : 'Lhihonor/android/security/IHwSecurityDiagnosePlugin$Stub;'
Interfaces : 'Lcom/hihonor/server/security/core/IHwSecurityPlugin;'
asBinder() : return this
```

So `querySecurityInterface(2)` returns the plugin's own Binder.

`getRootStatusSync()` (`0x2d2340`) is only:

```text
checkUserPermission()
return AppLayerStpProxy.getInstance().getRootStatusSync()
```

`checkUserPermission()` requires one of:

```text
com.hihonor.permission.SECURITY_DIAGNOSE
com.hihonor.security.permission.ACCESS_THREAT_DETECTION
```

`com.hihonor.parallelspace` declares `com.hihonor.permission.SECURITY_DIAGNOSE` (verified with `aapt2 dump permissions work\HnParallelSpace.apk`), which is why it can call the method.

### 2.4 STP adapter

`Lcom/hihonor/server/security/securitydiagnose/AppLayerStpProxy;` `getRootStatusSync()` (`0x2d1754`):

```text
adapter = getHwStpHidlAdapter()
if (adapter == null) {
    log "stp hidl deamon is not ready..."
    return -1000
}
ret = adapter.stpGetStatusByCategory(8, false, false, mStpGetStatusByCategoryCallback)
if (ret == -1002) { log "sync get root status from stp hidl failed."; return -1002 }
return mStpGetStatusByCategoryRetValue
```

`HwStpHidlAdapter`:

```text
STP_ROOT_THREAT = 8
STP_SERVICE_NAME = "hwstp"
EXCEPTION_FAIL = -1002
SUCCESS = 0
```

`stpGetStatusByCategory()` (`0x227dd0`) first tries AIDL:

```text
ServiceManager.getService("vendor.honor.hardware.hwstp.IHwStp/default")
IHwStp.Stub.asInterface(...)
IHwStp.stpGetStatusByCategory(category, false, false, IStpRet)
```

If AIDL is unavailable it falls back to HIDL `vendor.honor.hardware.hwstp@1.0/1.1`, `getService("hwstp")`.

The callback stores the raw status:

```text
AppLayerStpProxy$StpGetStatusByCategoryCallback.onValues(int status, String buffer):
    mStpGetStatusByCategoryRetValue = status
    mStpGetStatusByCategoryOutBuff = buffer
```

So `getRootStatusSync()` returns the integer hisecd returned for category/key 8, with no transformation.

---

## 3. Native stack: `security-service` -> `libstp` -> `hisecd`

### 3.1 Vendor service

VINTF declaration (`work/reverse/securityserver-huks/device/vintf/manifest/vendor.honor.hardware.security-service.xml`):

```xml
<hal format="aidl">
    <name>vendor.honor.hardware.hwstp</name>
    <fqname>IHwStp/default</fqname>
</hal>
```

Init (`device/vendor.honor.hardware.security-service.rc`):

```text
on early-boot
    start security-hal

service security-hal /vendor/bin/hw/vendor.honor.hardware.security-service
    class core
    user system
    group system nfc
```

The executable depends on `vendor.honor.hardware.hwstp-V1-ndk.so` and `libstp.so`, and contains HTEE/QTEE strings (`ExecuteHtee`, `ExecuteQtee`, `libHTEEAntiTheftCA.so`, `libstp.so`, `vendor.honor.hardware.hwstp-V1-ndk.so`).

### 3.2 `libstp.so`

Exported symbols:

```text
StpGetStatus                0x40e0
StpGetStatusByCategory      0x4280
StpGetStatusById            0x41a8
StpClearStatus              0x43e4
StpCleanKshieldStatus       0x453c
StpStaticCheck              0x4358
StpTriggerKshieldCheck      0x45d4
StpUpdateKshieldConfig      0x4684
```

Strings show it is a socket client to `hisecd`:

```text
HISEC
SOCKETC
/dev/socket
hisecd
[%-10s] client >> cmd %d, key %u, detail %d, history %d
[%-10s] client << len %u, ret %d
```

`StpGetStatusByCategory` is a thin C++ wrapper (0x4280) that obtains the STP engine object and invokes its status-by-category method; the actual transport is the hisecd socket.

### 3.3 `hisecd`

Init (`device/init/hisecd.rc`):

```text
service hisecd /vendor/bin/hisecd
    class main
    user system
    group system radio root
    socket hisecd stream 0660 system system
    ...
    disabled

on boot
    start hisecd
```

It is **not `oneshot`**, so init normally restarts it if killed. More importantly, even if it stayed dead, `libstp` would fail and `AppLayerStpProxy` would return `-1000`/`-1002`, which is non-zero and therefore still blocked.

`hisecd` reads `/vendor/etc/hisecd/stp.conf` (pulled as `device/stp.conf`). Relevant checks:

```ini
[check-su]      id=0x00000208  paths=/sbin /system/bin /vendor/bin /odm/bin /system/vendor/bin
[sysrw]         id=0x00000305  mount_points=/ /system /vendor /odm /cust /hw_product /version /patch_hn /preload
[root-prop]     id=0x00000300  property_list=ro.secure 0 ro.debuggable 1 ro.build.tags test-keys
[verifyboot]    id=0x00000200
[verity-enable] id=0x00000201
[verified-state] id=0x00000203
[key-files]     id=0x00000202
[image-valid]   id=0x00000211
[sd-rollback]   id=0x00000212
```

Other strings/behavior in `hisecd`:

```text
/vendor/etc/hisecd/stp.conf
/proc/kernel_stp
oeminfo_root_info
status loaded from storage
status stored into storage
status refreshed on first run
ro.vendor.hisecd.refreshed
persist.vendor.hisecd.firstrun
root-prop
check-su
sysrw
```

Function-level observations in `hisecd` (stripped but disassembled into `hisecd.disasm.txt`):

| Address | Meaning |
|---|---|
| `0x15208`, `0x15384` | compare command word to `0x7d2` (2002, status-by-category) |
| `0x157f0` | handler for cmd `0x7d2`; calls `0xf480` with `(engine, out, category, arg3, arg4)` |
| `0xf480` | get-status-by-category engine call |
| `0xff70` | status load from storage (`"status loaded from storage"`) |
| `0x10220` | status store to storage (`"status stored into storage"`) |
| `0x1c064` | `/proc/kernel_stp` read path |
| `0x13b24`, `0x1334c` | OEMINFO `oeminfo_root_info` read/write path |

`hisecd` thus combines static userspace checks, the kernel STP module (`/proc/kernel_stp`; kernel workers `HN_KERNEL_STP_MODULE`/`HN_KERNEL_STP_SCANNER` visible in `work/stp-inspect.txt`) and OEMINFO-persisted state. The judge is cached/persisted, so a process kill or framework restart does not automatically clear it.

### 3.4 Direct log proof

`work/m6-recreate-log.txt` (boot at 14:32:42):

```text
14:32:42.249  2094  2144 I HISEC : [SOCKETC] client >> cmd 2002, key 8, detail 0, history 0
14:32:42.249  2094  2144 I HISEC : [SOCKETC] client << len 6, ret 1
14:32:42.277  2094  2144 I HISEC : [SOCKETC] client >> cmd 2002, key 8, detail 0, history 0
14:32:42.277  2094  2144 I HISEC : [SOCKETC] client << len 6, ret 1
14:32:42.350  2094  2144 I HISEC : [SOCKETC] client >> cmd 2002, key 8, detail 0, history 0
14:32:42.350  2094  2144 I HISEC : [SOCKETC] client << len 6, ret 1
14:32:42.350 22024 22024 W HnParallelSpace_1320001105: InitActivity-1:Root check failed.
```

`ret 1` is the root-category status returned by hisecd; the parallelspace `Root check failed.` line follows in the same millisecond. That is the entire "securityserver" root path, observed end to end.

---

## 4. Where the root status is computed/cached — and what is *not* the source

### 4.1 Computed/cached by `hisecd` / kernel / OEMINFO

The status is not computed by HUKS, ASSET, `persist.sys.root.status`, or the HnSecurityServer APK. It is computed by the native STP engine in `hisecd` from:

- `stp.conf` checks (`check-su`, `sysrw`, `root-prop`, `verifyboot`, verity, key files, etc.);
- `/proc/kernel_stp` (kernel STP module);
- OEMINFO (`oeminfo_root_info`).

It is cached in the `hisecd` in-memory status table and persisted to OEMINFO. Boot logs/strings include `status loaded from storage`, `status stored into storage`, `status refreshed on first run`, `ro.vendor.hisecd.refreshed`, `persist.vendor.hisecd.firstrun`. This is why a pure process kill/reboot does not necessarily clear the judgment.

The vendor `security-service` also contains HTEE/QTEE code paths (`ExecuteHtee`, `ExecuteQtee`, `libHTEEAntiTheftCA.so`). The observed root-category query is nevertheless served through `hisecd`'s socket, so `hisecd` is the effective userspace authority/cache; TEE- or kernel-backed inputs may feed individual checks, and we did not fully map them.

### 4.2 `persist.sys.root.status` is a report/decoy, not an input

`RootDetectReport` (services.jar) is an observed writer of the property:

```text
com.hihonor.server.security.securitydiagnose.RootDetectReport.setRootStatusProperty(int)
2d3990: const-string v1, "persist.sys.root.status"
2d3994: and-int/lit16 v0, v2, #int -1025  // 0xFBFF, clear BIT_RPROC
2d39a0: SystemPropertiesEx.set(v1, v0)
```

`HwDevicePolicyManagerService.isRooted()` reads it for MDM:

```text
2330aa: const-string/jumbo v3, "persist.sys.root.status"
2330b0: SystemProperties.get(v3)
...
2330c4: const-string v4, "0"
2330c8: equals(...)
```

But the **live** diagnose path (`HwSecurityDiagnosePlugin.getRootStatusSync -> AppLayerStpProxy -> HwStpHidlAdapter -> hisecd`) never reads `persist.sys.root.status`. No native string exists in `hisecd`, `libstp.so`, `security-service`, or `libhwkeystore_jni.so`. Setting it to `0` only changes the report/MDM view; it cannot change the next STP query. It can also be overwritten/stale relative to the live STP state.

### 4.3 Failure codes are non-zero and therefore "root"

`AppLayerStpProxy` initializes the cached status to `-1001`; `getRootStatusSync` returns:

| Condition | Return |
|---|---|
| hwstp adapter not connected | `-1000` |
| AIDL/HIDL call throws | `-1002` |
| callback never updates initial value | `-1001` |
| `HwSecurityDiagnoseManager` has no service / RemoteException | `-2000` |
| safe | `0` |
| root threat | `1` (observed) |

Parallelspace and HUKS both test `!= 0`. Therefore killing `hisecd`, killing `system_server`, or having a stale binder cannot produce "safe"; it produces a negative error, which is still blocked. This is a fail-closed design.

---

## 5. HUKS/ASSET is a consumer, not the provider

`work/HnUniKeystoreService.txt` (`HnUniKeystoreService.dex`, split `huksplugin` of `com.hihonor.securityserver`):

```text
com.hihonor.securityserver.HwKeystoreServiceImpl.isRoot:()Z   @0x002100
  Binder.clearCallingIdentity()
  HwSecurityDiagnoseManager.getInstance()
  status = getRootStatusSync()
  Binder.restoreCallingIdentity()
  LogUtil.error("HwKeystoreServiceImpl", "root:" + status)
  return status != 0
```

Observed log (`work/ps-full-log.txt`):

```text
I ASSET_COMMON: CheckRootStatus
E HUKS_HwKeystoreServiceImpl:  - root:1
I ASSET_COMMON: the device is rooted
E ASSET_COMMON: IsRoot: debug file is not exist
E ASSET_PWD: AssetHandleReq: the device has been rooted!
```

The HUKS native library `libhwkeystore_jni.so` has its own ASSET-only debug-file bypass. At `0x7c428` it logs `CheckRootStatus`, calls the Java `isRoot` method via JNI, and if root checks:

```text
path = "/data/user/0/com.hihonor.securityserver/asset_debug_info.txt"   // 0x1004c
if (access(path, F_OK) == 0) {
    read up to 64 bytes;
    compare exactly with "msc.asset.debug=true"   // 0x7c5ec..0x7c630
    if match: log "content match success!"; return 0;   // ASSET treats as non-root
}
log "the device is rooted"; return 1;
cache result in a global byte at 0xacb00
```

Relevant strings:

```text
0x1004c  /data/user/0/com.hihonor.securityserver/asset_debug_info.txt
0x10689  get isRoot method not found
0x10fdf  %s: the device has been rooted!
0x11465  IsRoot
0x11a9f  strictRoot
0x11f3e  CheckRootStatus
0x151cb  exception occurred when get isRoot method from security server
0x18ffd  isRoot
0x10b0a  %s: content match success!
0x1409f  the device is rooted
```

This debug file only affects the HUKS/ASSET native root gate (specifically the JNI `CheckRootStatus` path; any other caller of that native function would also see the relaxed result). It does not clear the STP status, does not write `persist.sys.root.status`, and does not change `HwSecurityDiagnoseManager.getRootStatusSync()`. That is why the parallelspace dialog survives after creating `asset_debug_info.txt`.

---

## 6. Parallelspace final gate

`work/classes.txt` (`HnParallelSpace` `classes.dex`), class `Lparallel/g1;`.

`g1.e()` at `0x2e6530` returns **1 = block**, **0 = allow**:

```text
manager = HwSecurityDiagnoseManager.getInstance()
if (manager == null) return 1;                  // fail-closed
status = manager.getRootStatusSync()
debug  = SystemPropertiesEx.getInt("msc.parallelspace.debug_mode", 0)
if (status == 0) return 0;                      // not root -> allow
if (debug == 1) return 0;                       // explicit debug override -> allow
if (g1.c() == 0) return 0;                      // OEM demo exception -> allow
return 1;                                       // root -> block
```

`g1.c()` at `0x2e6494`:

```text
if (!"demo".equalsIgnoreCase(msc.sys.vendor)) return true;
if ("demo".equalsIgnoreCase(msc.sys.country)) return true;
return false;
```

Current properties (`work/ps-props-now.txt`):

```text
msc.sys.vendor  = all
msc.sys.country = cn
persist.sys.root.status = 0
msc.parallelspace.debug_mode = absent (default 0)
```

So `g1.c()` is true; `msc.parallelspace.debug_mode` is 0; and `getRootStatusSync()` returns 1. `g1.e()` returns 1 (block).

`InitActivity.onCreate` at `0x29b3e8`:

```text
if (g1.e() == 0) {
    normal init / launcher
} else {
    log "Root check failed."
    new AlertDialog.Builder(this)
        .setMessage(0x7f100025)   // string/alert_message_enter_when_root
        .setPositiveButton(0x7f1000ee, ...)
        .show()
}
```

Resource mapping from `work/HnParallelSpace.resources.txt`:

```text
0x7f100025  string/alert_message_enter_when_root
zh-rCN: "该设备已经 Root，使用“平行空间”会存在风险，已禁止使用。"
```

Observed dialog (`work/confirm2-ps.xml`, `work/m6-recreate.xml`):

```text
package=com.hihonor.parallelspace
android:id/message = 该设备已经 Root，使用“平行空间”会存在风险，已禁止使用。
android:id/button1 = 知道了
```

`HnParallelSpace` declares `com.hihonor.permission.SECURITY_DIAGNOSE`, so the binder call itself succeeds.

---

## 7. Why the attempted countermeasures still leave the dialog

| Attempt | Actual effect | Why it fails |
|---|---|---|
| `kill hisecd` | init restarts it (not `oneshot`); or `libstp` call fails | `AppLayerStpProxy` returns `-1000`/`-1002`; non-zero -> still blocked. Persisted/kernel status also survives. |
| kill `securityserver` app / `com.hihonor.securityserver` | only `security_server` (underscore) binder dies | The framework uses `securityserver` from **system_server**, not the app. HUKS/ASSET is a consumer, not the provider. |
| kill `system_server` | system_server restarts; new proxy re-registers | STP status is still 1 in hisecd/OEMINFO/kernel. Existing app may hold a dead binder -> `RemoteException` -> `-2000` -> still blocked. |
| `persist.sys.root.status=0` | changes MDM/report property only | Not read by `getRootStatusSync`; live STP query still returns 1. |
| `asset_debug_info.txt` = `msc.asset.debug=true` | HUKS/ASSET native gate only | `libhwkeystore_jni.CheckRootStatus` returns 0 for ASSET, but parallelspace calls `HwSecurityDiagnoseManager` directly and still gets STP 1. |
| `msc.parallelspace.debug_mode=1` | would make `g1.e()` return 0 | This is the actual app-level backdoor, but the property is protected; normal `setprop`/`ksud resetprop` attempts failed in earlier tests. |

The `securityserver` naming is the main trap: `com.hihonor.securityserver` is a **different binder** (`security_server`) from the framework's `securityserver`.

---

## 8. Concrete hook/patch points and risks (no patch was applied)

### 8.1 App-level (recommended for the dialog only)

| Target | Exact point | Effect | Risk |
|---|---|---|---|
| `parallel.g1.e()` | `classes.dex` `0x2e6530`, return 0 | Dialog bypass in parallelspace only | App update/reobfuscation; integrity/anti-hook checks |
| `HwSecurityDiagnoseManager.getRootStatusSync()` | framework method, return 0 in parallelspace process | Dialog bypass; HUKS/other checks in that process also see 0 | Hooking framework in app process; hidden-API/update risk; masks root from other components in that process |
| Binder transaction | `IHwSecurityService.querySecurityInterface` code **3**; replacement plugin's `getRootStatusSync` code **4** | Return a local fake `IHwSecurityDiagnosePlugin` whose sync method returns 0 | Must stub the AIDL correctly; interface changes; per-process scope |
| Property | `msc.parallelspace.debug_mode=1` | `g1.e()` returns 0 (allow) | Property is protected; failed from shell; setting it globally may be detected |

For a narrow, low-blast-radius fix, hook `parallel.g1.e()` or return a fake plugin only for id 2. Do **not** replace the whole `securityserver` binder: other plugins (anti-mal, device usage, etc.) use the same service.

### 8.2 System-side / operational

| Target | Exact point | Effect | Risk |
|---|---|---|---|
| `StpClearStatus()` | `libstp.so` symbol `0x43e4` | Clears the live STP root judgment; sibling test reports dialog disappears | Global security state; may re-detect if `su` traces remain; not persistent |
| `StpCleanKshieldStatus()` | `libstp.so` `0x453c` | Returned `-32` in sibling test; not needed | Same |
| `HwStpHidlAdapter.stpGetStatusByCategory()` | system_server Java `0x227dd0` | Force status 0 | System_server injection; instability; SELinux; affects all consumers |
| AIDL `IHwStp.stpGetStatusByCategory` | `security-service` / `vendor.honor.hardware.hwstp-V1-ndk.so` | Force 0 for category 8 | Native HAL injection; affects all clients |
| `libstp.so StpGetStatusByCategory` | `0x4280` | Force 0 for category 8 | Runs in `security-service`; system-wide |
| `hisecd` cmd `0x7d2` handler | `0x157f0` / get-by-category `0xf480` | Force 0 for key 8 | Native daemon injection; system-wide; fragile |
| OEMINFO clear | `oeminfo_root_info` / `oeminfo` | Force recheck | **Do not** modify OEMINFO blindly; device-specific/anti-theft data; may brick features |

The cleanest operational fix validated by the parallel test (`work/reverse/stp-clear-fix.md`) is:

```text
dlopen("/vendor/lib64/libstp.so")
StpClearStatus()      // returns 0
```

from a rootd context with sufficient capabilities, then relaunch parallelspace. It clears the live status but does not remove `/system/bin/su` traces; with KSU root, STP can re-detect and re-block, so root hiding or per-launch clear is required.

### 8.3 Do not do

- Do not modify `/system`, `/vendor`, `/product`, `system_ext`, or APEX partitions.
- Do not clear/rewrite OEMINFO or `persist.vendor.hisecd.*`/`ro.vendor.hisecd.*` casually.
- Do not assume `persist.sys.root.status=0` is a fix; it is a report property.
- Do not kill system_server/hisecd as a "clear"; negative errors still block.

---

## 9. Confidence

| Claim | Confidence | Basis |
|---|---|---|
| `securityserver` is system_server, not `com.hihonor.securityserver` | **High** | `HwSecurityService extends SystemService`, `onStart` registers `securityserver`; app registers `security_server`; both names in `dumpsys -l` |
| `querySecurityInterface(2)` returns `HwSecurityDiagnosePlugin` | **High** | code path + plugin registration + transaction codes + observed root:1 |
| `getRootStatusSync` -> STP category 8 -> hisecd | **High** | full code chain + HISEC `cmd 2002, key 8, ret 1` immediately before dialog |
| status cached/persisted by hisecd/OEMINFO/kernel | **High/medium** | strings/init/config/logs; exact internal aggregation not fully decompiled |
| `persist.sys.root.status` is not an input | **High** | no read in diagnose path; writer/reader code identified; no native string |
| HUKS debug file only affects ASSET | **High** | native exact compare + logs + app calls framework directly |
| parallelspace `g1.e` logic | **High** | dexdump; current props; dialog resource match |
| `StpClearStatus` clears dialog | **Medium-high** | sibling empirical test in `work/reverse/stp-clear-fix.md`; our code analysis supports it, not independently re-run here |

Open questions:
- Exact mapping of `stp.conf` check IDs to category 8's aggregate bits (the engine's internal `0xf480` logic is only partially reversed).
- Whether OEMINFO status survives a full power cycle in all cases; logs say "status loaded from storage", but we did not clear/test it.
- Whether `msc.parallelspace.debug_mode` can be set on this build without modifying init/property contexts; earlier attempts failed.

---

## 10. Evidence inventory

### 10.1 Primary dumps

| Path | Content |
|---|---|
| `work/services-magic.jar` | `classes.dex` + `classes2.dex`; system_server Honor classes |
| `work/framework-magic.jar` | framework classes, including `HwSecurityDiagnoseManager` and AIDL |
| `work/svc-classes.dex.txt`, `work/svc-classes2.dex.txt` | dexdump of services jars |
| `work/fw-classes.dex.txt`, `work/fw-classes2.dex.txt` | dexdump of framework |
| `work/securityserver-apks/HnSecurityServer.apk` | `com.hihonor.securityserver` 12.1.0.1 |
| `work/securityserver-apks/HnUniKeystoreService.apk` | split `huksplugin` of `com.hihonor.securityserver` |
| `work/HnParallelSpace.apk` | `com.hihonor.parallelspace` 132.0.1.105 |
| `work/classes.txt`, `work/classes2.txt` | HnParallelSpace dexdump |
| `work/HnUniKeystoreService.txt` | HUKS split dexdump |
| `work/libhwkeystore_jni.so` | HUKS native library |

### 10.2 Device pulls (read-only)

All under `work/reverse/securityserver-huks/device/`:

```text
hisecd
libstp.so
vendor.honor.hardware.security-service
vendor.honor.hardware.hwstp-V1-ndk.so
vendor.honor.hardware.honorsigntool-V1-ndk.so
vendor.honor.hardware.weaver-V1-ndk.so
vendor.honor.hardware.honorantitheft-V1-ndk.so
vendor.honor.hardware.securecamera-V2-ndk.so
stp.conf
vintf/...                  (vendor VINTF manifests)
init/...                   (vendor init rc files)
```

### 10.3 Key hashes (SHA-256)

```text
services-magic.jar                 6DDFB180C7E81149FC3D0834C15E2DCC789C1425153395773028A48E264245DF
framework-magic.jar                C66CE2134D5D1B84083A7BB4098AA8C15A9F0EC916A2814BE05D9B67D5B138A4
HnSecurityServer.apk               98CA749984935FAE2242F26706889D3D8EC3959FC44B3A5B5134975EC61319A1
HnUniKeystoreService.apk           D9E4AC0CAB338DE00A2EFC645458B5B4B455C63E61808505AF9E1E859CFC450D
HnParallelSpace.apk                98AD509F36B05411396451CA5606F95DE54B3C33EBE407557E112614FD3F16C7
libhwkeystore_jni.so               75137E108537D4725EEC9160D5A7C090F77275EF2F48018E88BB2B17E5E34A80
hisecd                             53534F70577254D74AAAB441197ABE54A52407D1FCE82CB5F9BD58D89F907FE1
libstp.so                          CAE5F4528913C1762978843BAF48D8DD4823B11AEB8C4AD0808F6FC282E699FF
vendor.honor.hardware.security-service  F71D5B0F93855F417D8F08B8261BF2933910BAE5A9B189F5101BA632AECCD675
vendor.honor.hardware.hwstp-V1-ndk.so   D0E9F25538AD35F2A15D56A2CD23DA54D36D57DBB41D538EBF5BFBC157D5C813
```

### 10.4 Key logs and UI

```text
work/m6-recreate-log.txt        boot + HISEC cmd 2002 + Root check failed
work/m6-recreate.xml            root dialog
work/confirm2-ps-log.txt        later confirm run
work/confirm2-ps.xml            root dialog (exact Chinese message)
work/ps-full-log.txt            HUKS CheckRootStatus / root:1 / debug file not exist
work/ps-props-now.txt           msc.sys.vendor/country, persist.sys.root.status
work/stp-inspect.txt            hwstp service, hisecd/security-service processes, kernel STP workers
work/reverse/stp-clear-fix.md   sibling empirical StpClearStatus test (corroboration)
```

### 10.5 Analysis outputs in this directory

```text
HnSecurityServer.manifest.txt          aapt2 manifest dump
classes.dex.txt / classes.dex.utf8.txt HnSecurityServer dexdump (UTF-16/UTF-8)
HwSecurityServiceProxy.full.txt        proxy class section
HwSecurityServiceProxy.methods.txt     proxy methods
libstp.disasm.txt                      libstp disassembly
hisecd.disasm.txt                      hisecd disassembly
dumpsys-services.txt                   dumpsys -l (security_server + securityserver)
logcat-now.txt                         snapshot logcat
scan_dumps.out.txt                     class/reference scan
```

---

## 11. Recommended next steps (read-only / low risk)

1. If the goal is only the parallelspace dialog, prefer an app-scoped hook of `parallel.g1.e()` or return a fake `IHwSecurityDiagnosePlugin` for id 2 in the parallelspace process. Avoid system_server-wide hooks.
2. If the goal is a real root-status clear, use `StpClearStatus()` from a rootd/root context, then relaunch parallelspace. Re-check `HISEC ... key 8 ... ret 0` in logcat to confirm; if `su` is still visible, STP will re-detect.
3. Do not use `persist.sys.root.status=0` as a fix; it only affects MDM/report. If desired, verify with `HwDevicePolicyManagerService.isRooted`.
4. If testing HUKS/ASSET, keep `asset_debug_info.txt` only for ASSET experiments; it does not affect parallelspace.
5. If further native reverse is needed, instrument `hisecd` around `0xf480` and the `0x7d2` handler to dump category/key/status, and correlate with `stp.conf` item IDs. This is the remaining unknown: the exact aggregation behind category 8.

---

## Appendix A — pseudocode of the real chain

```java
// system_server
class HwSecurityService extends SystemService {
    HwSecurityService(Context c) {
        proxy = HwServiceSecurityPartsFactoryEx.getInstance()
                  .getHwSecurityServiceProxy(c);
    }
    void onStart() { proxy.onStart(); }
}

class HwSecurityServiceProxy {
    void onStart() {
        ServiceManagerEx.addService("securityserver", new HwSecurityServiceWrapper());
        registerCorePlugins();   // plugin 2 = HwSecurityDiagnosePlugin
        registerOtherPlugins();
    }
    IBinder queryInterface(int id) {
        HwSecurityPluginObj obj = mMapPlugins.get(id);
        if (obj != null && obj.flag == 1) {
            checkPluginPermission(obj);
            return obj.pluginRef.get().asBinder();
        }
        return null;
    }
}

class HwSecurityDiagnosePlugin extends IHwSecurityDiagnosePlugin.Stub {
    int getRootStatusSync() {
        checkUserPermission();  // SECURITY_DIAGNOSE or ACCESS_THREAT_DETECTION
        return AppLayerStpProxy.getInstance().getRootStatusSync();
    }
}

class AppLayerStpProxy {
    int getRootStatusSync() {
        HwStpHidlAdapter a = getHwStpHidlAdapter();
        if (a == null) return -1000;
        int r = a.stpGetStatusByCategory(8, false, false, callback);
        if (r == -1002) return -1002;
        return mStpGetStatusByCategoryRetValue;  // 0 safe, 1 root
    }
}

// vendor
class security-service {  // vendor.honor.hardware.hwstp.IHwStp/default
    void stpGetStatusByCategory(int cat, boolean b1, boolean b2, IStpRet cb) {
        int ret = libstp.StpGetStatusByCategory(cat, b1, b2);
        cb.callback(ret, buffer);
    }
}

// hisecd
int handle_cmd_2002(int key) {
    // key 8 = root threat
    return stp_engine.get_status_by_category(key);  // 0 safe, 1 root
}
```

## Appendix B — pseudocode of `parallel.g1.e()`

```java
// returns 1 = block, 0 = allow
static int e() {
    HwSecurityDiagnoseManager m = HwSecurityDiagnoseManager.getInstance();
    if (m == null) return 1;
    int status = m.getRootStatusSync();
    int debug = SystemPropertiesEx.getInt("msc.parallelspace.debug_mode", 0);
    if (status == 0) return 0;
    if (debug == 1) return 0;
    if (c() == 0) return 0;    // OEM demo exception
    return 1;
}

static boolean c() {
    if (!"demo".equalsIgnoreCase(msc_sys_vendor)) return true;
    if ("demo".equalsIgnoreCase(msc_sys_country)) return true;
    return false;
}
```

`InitActivity` shows the dialog when `e() != 0`.

---

*End of report. No device or system partition was modified; all analysis used existing dumps plus read-only `adb pull`/`dumpsys`/`logcat`.*
