# Native RE Report — Root Detection & Widevine Lifecycle

Workspace: `C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260`
Output: `work\reverse\native\` (read-only analysis; no device/system/APEX modification)

---

## 0. Scope, method, artifacts

### 0.1 Constraints honoured

* No write to any device partition, no reboot, no root, no install, no clear.
* Only local artifacts were read; all outputs written under `work\reverse\native\`.
* No hook was executed on a device. Section 5 lists hook **candidates** derived statically.

### 0.2 Tooling (all local)

| Tool | Path / version | Use |
|---|---|---|
| llvm-objdump / llvm-nm / llvm-strings | `work\toolchain\ndk\android-ndk-r28c\...\bin` | section/symbol/PLT truth, string inventory |
| Python 3.14 + capstone 5.0.7 + pyelftools | host | recursive disassembly, adrp/add dataflow annotation, EH-frame function boundaries |
| custom `scripts\elfx.py` | this dir | ELF wrapper, PLT-name resolution, annotated disasm, `all_strings`, xref |
| custom `scripts\ext4read.py` | this dir | pure-Python ext4 reader (WSL is **not** installed on this host; `wsl -l -v` fails) |
| custom `scripts\*.py` | this dir | per-target extraction / table recovery / diffs |

Because WSL is unavailable, `apex_payload.img` was parsed directly (ext4, 4096-byte blocks,
32 inodes, extent-mapped). Extraction is byte-exact — verified by `llvm-objdump -f` on the
2,378,200-byte DRM service binary (initial naive block concatenation lost 3 blocks; fixed by
logical-block placement, see `ext4read.read_data`).

### 0.3 Artifact identity (hashes)

| Artifact | Size | SHA-256 (first 16) | Note |
|---|---|---|---|
| `gameassistant-libhisec.so` | 51,224 | `1bbb319dc7774466` | identical to Honor-ID APK `libhisec.so` |
| `ai-sidebar libhisec.so` (MagicVoice) | 51,224 | `2f26afd127808b7d` | **same code** (`.text`/`.rodata` byte-identical), only `.shstrtab` name ordering differs |
| `gameassistant-libhonordetect.so` | 31,608 | `035eddbd9da680bb` | identical to ai-sidebar copy |
| Honor-ID APK `libhonordetect.so` | 31,448 | `82c7e509b46be0ca` | different build, same tables (offsets shift) |
| `libods.so` (gameassistant = hndockbar = APK) | 189,104 | `6b433447615ab2f4` | identical everywhere |
| `libwhitebox.so` | 213,512 | — | securityserver |
| `libdatabus_session.so` | 293,104 | — | securityserver |
| `libsecurityserver_ca.so` | 10,216 | — | TEE DeviceHealthService |
| `libtrustdevice.so` (APK) | 638,648 | `b79c709fd8a3b590` | TrustDecision, obfuscated |
| `libtdcoreplugin.so` (APK) | 108,808 | `e69fb682c2530230` | xCrash crash reporter |
| Widevine `apex_payload.img` | 5,529,600 | — | 16 entries |
| `android.hardware.drm-service-lazy.widevine` | 2,378,200 | — | whole WVCdm statically linked |

---

## 1. `libhisec.so` — “AegisSecComp” (Honor secure SDK detector)

### 1.1 ELF facts

```
.text    VA 0x14a0  size 0x7bc4   (stripped, 53 heuristic functions)
.rodata  VA 0x9064  size 0x16c4
.data.rel.ro VA 0x1bb28 size 0x1c8   (registration table + hash table + path table)
exports: only JNI_OnLoad 0x2568
imports: access, __system_property_get, fopen/fgets/fclose, getpid, strstr/strncmp/strlen,
         __android_log_print, memcpy/memset/malloc/free, mbrtowc/wcrtomb/strtod, __vsprintf_chk
(no popen, no dlopen, no ptrace, no fork)
```

No `dlopen`, no `ptrace`, no `fork` — it is a pure *string/file/property* detector plus
one Java-reflection signature check.

### 1.2 JNI registration (reconstructed)

`JNI_OnLoad` @ **0x2568**, log tag `"AegisSecComp"` @ 0x9074:

```c
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI(4, "AegisSecComp", "JNI_OnLoad begins");
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != 0) {   // vm->GetEnv = vtbl[6]
        LOGE(6, "AegisSecComp", "GetEnv return JNI_ERR");
        return -1;
    }
    static const JNINativeMethod methods[4] = {   // .data.rel.ro @ 0x1bc90
        {"idj",  "()Z", (void*)0x2558},
        {"iej",  "()Z", (void*)0x255c},
        {"irpj", "()Z", (void*)0x2560},
        {"irtj", "()Z", (void*)0x2564},
    };
    jclass c = (*env)->FindClass(env, "com/hihonor/secure/android/common/detect/S");
    if (!c) { LOGE(6, ..., "registerNativeMethods findClass return null"); return -1; }
    if ((*env)->RegisterNatives(env, c, methods, 4) < 0) {        // JNIEnv vtbl[0x6b8]
        LOGE(6, ..., "RegisterNatives return value < 0");
        return -1;
    }
    LOGI(4, ..., "return JNI_VERSION_1_6");
    return JNI_VERSION_1_6;                                        // 0x10006
}
```

* Class literal: `com/hihonor/secure/android/common/detect/S` @ **0x9e9c** (literally class `S`,
  a short obfuscated SDK entry class; not truncated — NUL follows).
* Each registered name is a 4-byte tail thunk into the real implementation
  (`b 0x14dc`, `b 0x18ac`, `b 0x229c`, `b 0x234c`).

| JNI name | thunk | implementation | meaning (recovered) |
|---|---|---|---|
| `idj`  | 0x2558 | **0x14dc** | is **D**ebugging (anti-debug: TracerPid / IDA port / android_server) |
| `iej`  | 0x255c | **0x18ac** | is **E**mulator |
| `irpj` | 0x2560 | **0x229c** | is **R**e**p**ackaged (APK signature SHA-256 allow-list) |
| `irtj` | 0x2564 | **0x234c** | is **R**oo**t** (properties + su/magisk paths) |

### 1.3 `irtj` — root check (0x234c, 78 insns)

```c
jboolean irtj(JNIEnv *env, jobject thiz) {
    char buf[0x5c];

    memset_s(buf, 0x5c, 0, 0x5c);                                  // 0x2bfc
    int n = __system_property_get("ro.secure", buf);               // 0x9cf8
    if (n >= 1 && buf[0] == '0') {                                 // only "0..." trips it
        LOGE(6, "AegisSecComp", "check ro.secure error");          // 0x9ca8
        return JNI_TRUE;
    }

    memset_s(buf, 0x5c, 0, 0x5c);
    n = __system_property_get("ro.build.tags", buf);               // 0x9d02
    if (n > 0 && strstr(buf, "test-keys")) {                       // 0x9d10
        LOGE(6, ..., "check build tags error");                    // 0x9cbe
        return JNI_TRUE;
    }

    if (is_bin_exists("/su")) {                                    // 0x2484
        LOGE(6, ..., "check su exists");                           // 0x9cd5
        return JNI_TRUE;
    }
    if (is_bin_exists("/magisk")) {                                // 0x9e3f
        LOGE(6, ..., "check magisk exist");                        // 0x9ce5
        return JNI_TRUE;
    }
    return JNI_FALSE;
}
```

Important semantic details:

* `ro.secure` is only a *failure* when its value starts with `'0'` (i.e. `ro.secure=0`).
  `"1"` or absent → pass. (Same test is inverted in `libhonordetect::isRT`, see §2.2.)
* `ro.build.tags` is a **substring** test for `test-keys`.
* `is_bin_exists` @ **0x2484** does the path composition and `access()`:

```c
bool is_bin_exists(const char *name) {           // name = "/su" or "/magisk"
    char buf[0x5c];
    for (int i = 0; i <= 0x14; i++) {            // 21 prefixes, table @ 0x1bbe8
        memset_s(buf, 0x5c, 0, 0x5c);
        strcpy_s(buf, 0x5c, kPrefix[i]);         // 0x3ad4
        strcat_s(buf, 0x5c, name);               // 0x394c  (no separator added)
        if (access(buf, F_OK) != -1) {           // any result except -1
            LOGD(3, "AegisSecComp", "binary name is exist in %s", buf);   // 0x9e24
            return true;
        }
    }
    return false;
}
```

Recovered prefix table (21 entries, `.data.rel.ro` @ **0x1bbe8**):

```
/sbin, /vendor/bin, /system/sbin, /system/bin, /system/xbin, /system/bin/.ext,
/system/sd/xbin, /system/usr/we-need-root, /cache, /data, /dev, /system/vendor/bin,
/vendor/xbin, /system/vendor/xbin, /product/bin, /product/xbin, /data/local/tmp,
/data/local/bin, /data/local/xbin, /data/local, /system/bin/failsafe
```

so the effective probes are `"/system/bin/su"`, `"/system/bin/magisk"`,
`"/system/usr/we-need-root/su"`, `/dev/su`, etc. (66 paths total).
Note `access()`-style detection is **defeated by a mount namespace that hides su**
(typical KernelSU/Magisk DenyList behaviour), because the check runs inside the app's
own mount namespace.

### 1.4 `irpj` — repackage/signature check (0x229c)

```c
jboolean irpj(JNIEnv *env, jobject thiz) {
    char *sha = get_signature_sha256(env);        // 0x2758, uppercase hex
    size_t need = strlen(kHashes[0]);             // 64 (__strlen_chk(...,0x41))
    if (!sha || strlen(sha) < need) {
        LOGE(6, "AegisSecComp", "sha 256 is null");           // 0x9c82
        return JNI_TRUE;
    }
    for (int i = 0; i <= 0x17; i++)               // 24 entries @ 0x1bb28
        if (strncmp(sha, kHashes[i], need) == 0)
            return JNI_FALSE;                     // signature matches a known Honor app
    LOGE(6, "AegisSecComp", "check sign error");              // 0x9c92
    return JNI_TRUE;                              // unknown signing certificate
}
```

`get_signature_sha256` @ **0x2758** (297 insns) is a pure JNI reflection chain and uses
these .rodata literals:

```
android/app/ActivityThread   currentApplication   ()Landroid/app/Application;
getPackageManager            ()Landroid/content/pm/PackageManager;
getPackageName               ()Ljava/lang/String;
getPackageInfo               (Ljava/lang/String;I)Landroid/content/pm/PackageInfo;   flags = 0x40
signatures                   [Landroid/content/pm/Signature;
toByteArray                  ()[B
java/security/MessageDigest  getInstance  (Ljava/lang/String;)Ljava/security/MessageDigest;
SHA-256                      digest       ([B)[B
0123456789ABCDEF             (hex alphabet @ 0xa175)
```

24 known-good SHA-256 digests (`0x1bb28`, 24 pointers) — e.g.
`B92825C2BD5D6D6D1E7F39EECD17843B7D9016F611136B75441BC6F4D3F00F05`, `1E3EEE…694C`, …
(full list in `tables.json`). Because it always re-signs after patching, **any
re-signed/patched Game Assistant or Honor ID APK returns `irpj()==1`**.

### 1.5 `idj` — anti-debug (0x14dc)

```c
jboolean idj(JNIEnv *env, jobject thiz) {
    int tracer = 0, port = 0, ida = 0;

    /* 1) TracerPid in /proc/<pid>/status */
    char path[0x400]; char line[0x400];
    sprintf(path, "/proc/%d/status", getpid());                 // 0x3874
    FILE *f = fopen(path, "r");
    if (!f) { LOGE(6, ..., "open status file error"); }
    else {
        while (fgets(line, 0x400, f)) {
            if (!strncmp(line, "TracerPid:", 10)) {
                int pid = 0; sscanf(line, "TracerPid: %d", &pid);   // 0x38e0
                if (pid) { LOGI(4, ..., "TracePid Debugging , TracePid is : %d", pid); tracer = 1; }
            }
        }
        fclose(f);
    }

    /* 2) IDA debug-server port 23946 (0x5D8A) listening in /proc/net/tcp */
    f = fopen("/proc/net/tcp", "r");
    if (!f) { LOGE(6, ..., "open tcp file error"); }
    else {
        while (fgets(line, 0x400, f))
            if (strstr(line, "5D8A")) { LOGI(4, ..., "portCheck Debugging,port is : %s", "5D8A"); port = 1; }
        fclose(f);
    }

    /* 3) the tracer's own cmdline is IDA's android_server */
    int pid = getpid(); /* re-reads TracerPid, then: */
    sprintf(path, "/proc/%d/cmdline", tracer_pid);
    f = fopen(path, "r");
    if (f) {
        while (fgets(line, 0x400, f))
            if (strstr(line, "android_server") || strstr(line, "android_server64")) {
                LOGE(6, ..., "android_server can debug , name is : %s", line); ida = 1;
            }
        fclose(f);
    }
    return (tracer | port | ida) & 1;                              // 0x1868
}
```

Notes:

* Relative to `libhonordetect::isDG`, `idj` adds the **third** check: `/proc/<TracerPid>/cmdline`
  containing `android_server` / `android_server64`.
* `strstr("5D8A")` is a plain text match on `/proc/net/tcp`, so a *remote* 23946
  (non-loopback) listener also trips it, and an unrelated hex suffix could false-positive.
* `TracerPid` check is unconditional (no PPid exemption here, unlike `isDG`).

### 1.6 `iej` — emulator check (0x18ac)

Single sequential chain; each hit logs and **returns TRUE immediately**, otherwise FALSE.

| # | Source | Test |
|---|---|---|
| 1 | `ro.product.name` | `strncmp` prefix vs `ChangWan`, `Droid4X`, `nox`, `ttVM_Hdragon`, `sdk_google_phone_x86` |
| 2 | `init.svc.vbox86-setup`, `init.svc.droid4x`, `init.svc.qemud`, `init.svc.su_kpbs_daemon`, `init.svc.noxd`, `init.svc.ttVM_x86-setup`, `init.svc.xxkmsg`, `init.svc.microvirtd`, `ro.kernel.android.qemud`, `androVM.vbox_dpi`, `androVM.vbox_graph_mode` | `__system_property_get(...) > 0` (non-empty) |
| 3 | 11 files | `access(p, F_OK) == 0`: `/system/bin/qemu-props`, `/system/bin/androVM-prop`, `/system/bin/microvirt-prop`, `/system/lib/libdroid4x.so`, `/system/bin/windroyed`, `/system/bin/microvirtd`, `/system/bin/nox-prop`, `/system/bin/ttVM-prop`, `/system/bin/droid4x-prop`, `/data/.bluestacks.prop`, `/dev/socket/qemud` |
| 4 | `ro.hardware` | prefix vs `ttvm`, `nox`, `cancro`, `intel`, `vbox`, `vbox86`, `android_x86` |
| 5 | `ro.build.flavor` | contains `vbox` or `sdk_gphone` |
| 6 | `ro.product.model` | contains `google_sdk`, `emulator`, `android sdk built for x86` |
| 7 | `ro.product.manufacturer` | contains `genymotion`, `netease` |
| 8 | `ro.board.platform` | contains `android` |
| 9 | `ro.product.board` | contains `android` or `goldfish` |
| 10 | `gsm.version.baseband` | contains `1.0.0.0` |
| 11 | `/proc/cpuinfo` | for lines containing `Hardware` or `model name`: substring after `':'` contains `Genuine Intel(R)`, `Intel(R) Core(TM)`, `Intel(R) Pentium(R)`, `Intel(R) Xeon(R)`, `AMD` |

Log messages: `emulator ,because product name is %s` (0x91c0), `%s exsits, value is %s emulator!`
(0x92be), `isEmulatorFileExists emulator file exist in %s` (0x93de), `emulator ,because
hardware is %s` (0x9443), `… buildFlavor …` (0x947f), `… ro.product.model …` (0x94e2),
`… ro.product.manufacturer …` (0x9536), `… ro.product.board …` (0x9580), `Hardware is %s`
(0x9640), `can not open /proc/cpuinfo` (0x964f).

### 1.7 `libhisec` offset table

| VA | Size | Item |
|---|---|---|
| 0x14dc | 0x3d0 | `idj` anti-debug |
| 0x18ac | 0x9f0 | `iej` emulator |
| 0x229c | 0xb0 | `irpj` signature |
| 0x234c | 0x138 | `irtj` root |
| 0x2484 | 0xd4 | `is_bin_exists` |
| 0x2558/5c/60/64 | 4 B each | JNI thunks |
| 0x2568 | 0x154 | `JNI_OnLoad` |
| 0x2758 | 0x4a4 | `get_signature_sha256` |
| 0x2bfc | 0x90 | `memset_s` local wrapper |
| 0x394c | — | `strcat_s` |
| 0x3ad4 | — | `strcpy_s` |
| 0x9064 | 0x16c4 | `.rodata` (all literals) |
| 0x1bb28 | 24×8 | signature hash pointer table |
| 0x1bbe8 | 21×8 | root path prefix table |
| 0x1bc90 | 4×24 | `JNINativeMethod[4]` |

### 1.8 MagicVoice / Honor-ID variants

* `libhisec.so` in `com.hihonor.magicvoice` is **byte-identical in `.text` and `.rodata`** to the
  gameassistant one; only `.shstrtab` (section-name string table ordering) differs. Same
  registration table address (0x1bc90), same hashes. ⇒ one detector build, three consumers
  (Game Assistant, HnDockBar-adjacent MagicVoice sidebar, Honor ID).
* `libhonordetect.so` in Honor ID (31,448 B) is a *different build* of the same source
  (isRT at 0x5cd4 vs 0x5d24; isSMT 0x5fc8; isDG 0x6548). All recovered tables have the same
  contents and order (233 relocated pointers starting `/system/etc, /system, /apex/...`).
  Findings in §2 apply to both; use the per-build offsets in §2.7.

---

## 2. `libhonordetect.so` — USM SKIT `NativeLib` detector

### 2.1 Exports

```
Java_com_hihonor_cloudservice_usm_skit_detect_NativeLib_isRT   @0x5d24  (198 insns)
Java_com_hihonor_cloudservice_usm_skit_detect_NativeLib_isSMT  @0x603c  (308 insns)
Java_com_hihonor_cloudservice_usm_skit_detect_NativeLib_isDG   @0x65a8  (167 insns)
memcpy_s/memset_s family (exported by the secure-C runtime)
```

No `JNI_OnLoad` — exported `Java_…` names are resolved by the ART directly.
Imports: `access`, `__system_property_get`, `fopen/fgets/fclose`, `popen/pclose`, `getpid`,
`strstr/strcmp/strlen`, `sprintf`, `atoi`, `__android_log_print`.

### 2.2 `isRT` — root check (0x5d24)

Full decompilation:

```c
jboolean isRT(JNIEnv *env, jobject thiz) {
    int score = 0;                                  // w27
    char bufMagisk[0x5c], bufSu[0x5c];

    for (int i = 0; i < 29; i++) {                  // table @ 0xa998
        const char *p = kRootPrefix[i];
        size_t n = strlen(p);
        memcpy_s(bufMagisk, 0x5c, p, n);
        memcpy_s(bufMagisk + n, 0x5c, "/magisk", 7);            // 0x3815
        memcpy_s(bufSu, 0x5c, p, n);
        memcpy_s(bufSu + n, 0x5c, "/su", 3);                    // 0x35b1
        int a = access(bufMagisk, F_OK);            // 0x6870
        int b = access(bufSu, F_OK);
        score += (a == 0);
        score += (b == 0);                          // w21/w27 accumulation
    }

    /* six *identical* probes of /cache/.disable_magisk (0x3216) — 0x5e4c..0x5eb4 */
    int r19 = access("/cache/.disable_magisk", F_OK);
    int r20 = access("/cache/.disable_magisk", F_OK);
    int r21 = access("/cache/.disable_magisk", F_OK);
    int r22 = access("/cache/.disable_magisk", F_OK);
    int r23 = access("/cache/.disable_magisk", F_OK);
    int r24 = access("/cache/.disable_magisk", F_OK);
    int r25 = access("/cache/.disable_magisk", F_OK);   /* 7 results total */

    /* build integrity */
    int flags;
    char prop[0x5c] = {0};
    __system_property_get("ro.secure", prop);       // 0x30db
    if (*(uint16_t*)prop == '1') {                  // exact "1"
        char tags[0x5c] = {0};
        __system_property_get("ro.build.tags", tags);          // 0x2f8c
        bool release = *(uint64_t*)tags == 0x6572'656c'6561'7365ULL      /* "release" */
                    && *(uint64_t*)(tags+5) == 0x7365'2d6b'6579'7300ULL; /* "se-keys\0" */
        flags = release ? 0 : 0x100;
    } else {
        flags = 0x100;                              // ro.secure absent/not "1"
    }

    /* hooking framework */
    int bit16;
    if (scan_file("/proc/self/maps", kMapsPatterns, 3) > 0) {       // 0x5bfc
        bit16 = 0x10000;
    } else {
        int c = 0;
        for (int j = 0; j < 19; j++) c += (access(kHookPath[j], F_OK) == 0);  // @0xaa98
        bit16 = (c != 0) ? 0x10000 : 0;
    }

    score += (r19 == 0) + (r20 == 0) + (r21 == 0) + (r22 == 0) + (r23 == 0)
           + (r24 == 0) + (r25 == 0);
    if (score > 0) score = flags + 1; else score = flags;
    return (jboolean)(score | bit16);
}
```

Recovered tables:

* **29 root prefixes @ 0xa998** (each probed with `/magisk` and `/su` appended):
```
/system/etc            /system                 /apex/com.android.runtime/bin
/apex/com.android.art/bin  /system_ext/bin/    /system/app/SuperUser
/system/app/           /odm/bin                /sbin
/vendor/bin            /system/sbin            /system/bin
/system/xbin           /system/bin/.ext        /system/sd/xbin
/system/usr/we-need-root  /cache               /data
/dev                   /system/vendor/bin      /vendor/xbin
/system/vendor/xbin    /product/bin            /product/xbin
/data/local/tmp        /data/local/bin         /data/local/xbin
/data/local            /system/bin/failsafe
```
* **maps patterns @ 0xaa80**: `frida`, `libmemtrack_real.so`, `XposedBridge`
* **19 hook/Xposed paths @ 0xaa98**: riru_lsposed, /data/adb/lspd, zygisk_lsposed,
  riru_edxposed, /data/misc/riru/modules/edxp, edxp.prop, taichi, /data/misc/taichi,
  dreamland ×3, `/system/bin/app_process.orig`, `/system/xposed.prop`,
  XposedBridge.jar, libxposed_art.so ×2 (32-bit dup), lib64/libxposed_art.so,
  ZposedBridge.jar, libzposed_art.so

**Return semantics (bitmask, not a boolean):**

| bit | mask | meaning |
|---|---|---|
| 0 | `0x1` | at least one root artefact found (all counts collapse to +1) |
| 8 | `0x100` | build is “insecure”: `ro.secure != "1"` **or** `ro.build.tags != "release-keys"` |
| 16 | `0x10000` | hook framework: `/proc/self/maps` contains frida/libmemtrack_real.so/XposedBridge **or** any of the 19 LSPosed/Riru/edXposed paths exists |

So e.g. a clean retail device returns `0`; a device with Magisk paths returns `0x101` if
`ro.secure` was also touched; a device with only LSPosed returns `0x10000`.

> **Java-visible caveat.** These natives are registered as `()Z`, so Java receives a
> `jboolean`. ART’s JNI return conversion for `Z` is effectively a boolean test on the
> returned word in current releases, but older/other runtimes truncate to the low byte.
> Do not assume bits 8/16 reach the Java caller on every ART version — at minimum, the
> native contract is a bitmask and the low bit is the “root artefacts found” signal
> (`libhisec::idj` masks with `& 1` for exactly this reason, `isRT`/`isDG`/`isSMT` do not).

Implementation quirks worth knowing:

* `memcpy_s(buf+n, 0x5c, …)` passes the *whole* buffer size as `destsz` even for the tail copy
  (`strcat`-style code written with `memcpy_s`); benign but non-standard.
* The six identical `/cache/.disable_magisk` probes are a genuine artifact of this build
  (all six use the same pointer, same flag argument). A single file yields +6 score before
  the collapse to +1.
* `ro.secure` is compared as **exactly "1"** via a 2-byte load; `"1 "` or `"10"` would fall to
  the insecure branch. This is stricter than `libhisec::irtj` (which only rejects `'0'`).

### 2.3 Helper `scan_file` (0x5bfc) — used by isRT and isSMT

```c
int scan_file(const char *path, const char **patterns, int n) {
    FILE *f = fopen(path, "r");
    if (!f) { LOGE(6, "RD", "DKFF open file failed"); return 0; }
    int hits = 0;
    char line[0x400];
    while (fgets(line, 0x400, f)) {
        size_t l = strlen(line);
        if (l && line[l-1] == '\n') line[l-1] = 0;      // strip newline
        for (int i = 0; i < n; i++)
            if (strstr(line, patterns[i])) { hits++; break; }
    }
    fclose(f);
    return hits;                                        // number of matching lines
}
```

Log tag `"RD"` @ **0x2565** (`adrp 0x2000 + 0x565`); file mode `"r"` @ 0x31f9; failure text
`"DKFF open file failed"` @ 0x28b8. The return value is a *count* of matching lines, so
`> 0` means “found at least one”.

### 2.4 `isSMT` — emulator (“simulator”) check (0x603c)

Return: `w0 = bit0 | (props_bit << 8)`.

```c
jboolean isSMT(JNIEnv *env, jobject thiz) {
    int paths = 0;
    if (scan_file("/proc/cpuinfo", kCpuPatterns, 5) > 0) {   // Intel/AMD on x86 VM
        paths = 1;
    } else {
        int c = 0;
        for (int i = 0; i < 118; i++) c += (access(kEmuPath[i], F_OK) == 0);  // @0xab58
        paths = (c > 3);                                     // threshold: 4+
    }

    int props = 0;
    char p[0x5c];
    /* ro.product.name   vs {ChangWan, Droid4X, nox, ttVM_Hdragon, sdk_google_phone_x86, lgshouyou} */
    /* ro.hardware       vs {ttvm, nox, cancro, intel, vbox, vbox86, android_x86}              */
    /* ro.build.flavor   vs {vbox, sdk_gphone}                                                */
    /* ro.product.model  vs {google_sdk, emulator}                                            */
    /* ro.product.manufacturer vs {genymotion, netease}                                       */
    /* ro.product.board  vs {android, goldfish}                                               */
    /* gsm.version.baseband vs "1.0.0.0"                                                      */
    /* 37 further emulator properties: any non-empty value counts                             */
    ...
    props = (aggregate > 0);
    return (jboolean)(paths | (props << 8));
}
```

* 5 `/proc/cpuinfo` patterns @ **0xab30**: `Genuine Intel(R)`, `Intel(R) Core(TM)`,
  `Intel(R) Pentium(R)`, `Intel(R) Xeon(R)`, `AMD`.
* 118 emulator paths @ **0xab58** — Nox (`/system/bin/noxd`, `nox-prop`, `nox_setprop`,
  `noxspeedup`, `/fstab.nox`, `/init.nox.rc`, `gralloc.nox.so`, …), Droid4X, Genymotion,
  windroye/tiantianVM, microvirt, vbox/vbox86, qemu_pipe, BlueStacks (`/data/.bluestacks.prop`),
  `/sys/module/vboxsf`, `/ueventd.android_x86.rc`, `/ueventd.goldfish.rc`, …
  (full list in `tables.json`).
* Property tables: `0xaf08` (6), `0xaf38` (7), `0xaf70` (2), `0xaf80` (2), `0xaf98` (2),
  `0xafa8` (2) and the 37-entry “any non-empty” list `0xafb8` (all `init.svc.*`,
  `androVM.*`, `qemu.*`, `ro.kernel.*`, `windroyed.gps.*`, `persist…`).
* Threshold: **more than 3** (i.e. ≥4) emulator paths, or any x86 CPU signature.

> ⚠ Implementation quirk: the property comparisons are compiled as an *accumulating index*
> (`idx += (strcmp(prop, tab[idx]) == 0)`), and the accumulated index is later compared
> against the last `csetm` result. For distinct table strings this means the scan can only
> advance when `tab[0]` matches; equality with later entries does not by itself raise the
> aggregate. Net observable behaviour: the property heuristics are dominated by the *first*
> entry of each table (`ChangWan`, `ttvm`, `vbox`, `google_sdk`, `genymotion`, `android`) and by
> the 37 “non-empty” properties. This looks like an upstream optimisation/obfuscation bug;
> the check that reliably fires on emulators is the path/cpuinfo half (bit 0).
> Treat the table lists as the complete detection corpus even if only `tab[0]` is reachable
> through the compiled chain.

### 2.5 `isDG` — debugger check (0x65a8)

```c
jboolean isDG(JNIEnv *env, jobject thiz) {
    int port = 0, connected = 0, traced = 0;
    char line[0x10000];

    /* 1) IDA debug server port 23946 (0x5D8A) */
    FILE *p = popen("cat /proc/net/tcp | grep :5D8A", "r");     // 0x299b
    if (!p) { LOGE(6, "RD", "CP open file failed!"); }          // 0x3755
    else {
        if (fgets(line, 0x10000, p)) { LOGE(6, "RD", "dt CP"); port = 1; }
        pclose(p);
    }

    /* 2) Java Debug.isDebuggerConnected() via JNI */
    jclass dbg = FindClass(env, "android/os/Debug");
    jmethodID m = GetStaticMethodID(env, dbg, "isDebuggerConnected", "()Z");
    jboolean r = CallStaticBooleanMethod(env, dbg, m);
    if (r & 0xff) { LOGE(6, "RD", "dt asDG"); connected = 0x100; }

    /* 3) TracerPid != 0 and != PPid in /proc/self/status */
    sprintf(path, "/proc/%d/status", getpid());
    int ppid = 0;
    f = fopen(path, "r");
    while (fgets(line, 0x400, f)) {
        if (!memcmp(line, "PPid", 4))  ppid  = atoi(line + 5);        // "PPid:"
        if (!memcmp(line, "TracerPi", 8) && line[8] == 'd') {
            int t = atoi(line + 10);
            if (t && t != ppid) { LOGE(6, "RD", "dt tid"); traced = 0x10000; }
        }
    }
    return (jboolean)(port | connected | traced);
}
```

Log levels used by the family: `3` = DEBUG, `4` = INFO, `6` = ERROR (Android log prio).

Return bitmask: `bit0` IDA port, `bit8` `Debug.isDebuggerConnected()`,
`bit16` unexpected tracer. Note the PPid exemption: a tracer that *is* the parent
(e.g. `strace`, some eBPF/loader wrappers, `run-as`) is not reported by the TracerPid check.

### 2.6 `libhonordetect` offset table

| VA | size | Item |
|---|---|---|
| 0x5bfc | 0x128 | `scan_file(path, patterns, n)` |
| 0x5d24 | 0x318 | `isRT` |
| 0x603c | 0x4d0 | `isSMT` |
| 0x650c | 0x9c | variadic JNI `CallStaticBooleanMethod` trampoline (used by isDG) |
| 0x65a8 | 0x284 | `isDG` |
| 0xa990 | 0x750 | `.data.rel.ro` (pointer tables) |
| 0xa998 | 29×8 | isRT root prefixes |
| 0xaa80 | 3×8 | maps patterns |
| 0xaa98 | 19×8 | hook paths |
| 0xab30 | 5×8 | cpuinfo patterns |
| 0xab58 | 118×8 | emulator paths |
| 0xaf08…0xafb8 | 6/7/2/2/2/2/37 | property tables |

### 2.7 Honor-ID build offsets

`isRT` 0x5cd4, `isSMT` 0x5fc8, `isDG` 0x6548; `.data.rel.ro` 0x7940..0x8090;
`.text` 0x1c smaller; identical table contents/order. All tables above apply; add the
delta `-0x50` (isRT) / `-0x74` (isSMT) / `-0x60` (isDG) to the gameassistant offsets.

---

## 3. Other native libraries (root / hook / AI gating)

### 3.1 `libods.so` — **not** a detector, it is the white-box crypto module

* JNI class `com/hihonor/secure/android/common/enc2/ODS` (`FindClass` literal @ 0xcc2).
* Exports: `wbg_decrypt`, `getwbwk` (JNI), `honor_aes_gcm_decrypt`, plus a white-box AES
  implementation exported as `w_b_e`, `w_b_d_g_m`, `w_b_e_g_m`, `table1`, `ROTL`,
  `xor_block*`, `block_mul2`, `psr_*` (`psr_init/next/rand_bytes`).
* `.rodata` entropy 7.98, printable 36 % ⇒ the S-boxes/tables are the obfuscated content.
* **No** `access`/`su`/`magisk`/`ptrace`/`/proc` strings. Verdict: encryption helper
  (ODS = on-device secure storage crypto), no root/hook detection and no gating logic.
  Both copies (gameassistant, hndockbar) and the Honor-ID APK copy are byte-identical.

### 3.2 `libwhitebox.so` — white-box decryption for securityserver

* Class `com/hihonor/hwddmp/utils/WhiteBoxNative`; natives `decrypt(Ljava/lang/Object;[B)Ljava/lang/String;`
  and `decryptPadNoCheckSign([B)Ljava/lang/String;`.
* Contains its own anti-tamper check: `CheckSignature`, `signatures`,
  `[Landroid/content/pm/Signature;` (verifies the *calling package* signature before
  decrypting). That is package-integrity, not root detection.
* No root/emulator/hook corpus; imports are only log/mem/signal.

### 3.3 `libdatabus_session.so` — pure IPC, **no detection**

* Class `com/hihonor/hwddmp/servicebus/DataBusSessionNative`; 14 natives
  (`createListenerNative`, `openFdNative`, `sendDataNative`, `recvDataNative`,
  `bindToDeviceInner`, …) over `AF_UNIX`/epoll. No root, property, or `/proc` probing
  (0 keyword hits).

### 3.4 `libsecurityserver_ca.so` — TEE bridge

* Class `com/hihonor/securityserver/DeviceHealthService`; natives `nativeStart`,
  `nativeStop`, `nativeProcessCmd`. Only `TEEC_*` calls (TrustZone) + `jniRegisterNativeMethods`.
  No detection logic in native code.

### 3.5 `libhwkeystore_jni.so` — HUKS **consumer** of root state (important)

`com.hihonor.securityserver.HwKeystoreServiceImpl` + HUKS JNI. Recovered strings:

```
"get isRoot method not found"          "the device has been rooted!"
"IsRoot"                               "CheckRootStatus"
"strictRoot"                           "the device is rooted"
"the device is not rooted"             "EIMA key antiroot error code:%d!"
"exception occurred when get isRoot method from security server"
"%s: debug file is not exist"          "Not system signature permission, permission denied!"
"GetSignatureHash res is null"         "get hasSameSignatureByUid method not found"
```

This is where root state becomes policy: HUKS queries `isRoot`/`CheckRootStatus`
(reflectively, from `com.hihonor.securityserver`) and an internal `strictRoot`, and
tags asset/key operations with an anti-root error code. For a root-visibility study this is
the *decision point* (key/blob downgrade), whereas libhisec/libhonordetect are the *sensors*.
Static hook points here are the `isRoot` resolution and the `strictRoot` check, both inside
`libhwkeystore_jni.so` (JNI_OnLoad @ 0x2cde0; string xrefs at 0x10689 / 0x11a9f / 0x11f3e).

### 3.6 `libtrustdevice.so` + `libtdcoreplugin.so` — TrustDecision TDC

* `libtrustdevice.so` (638 KB): **heavy commercial obfuscation** — `.rodata` entropy 7.84,
  no plaintext strings (`llvm-strings` returns 0 relevant hits). `JNI_OnLoad` @ 0x6da30 is a
  4-byte thunk to 0x6d6a0, which is a NEON bit-sliced **in-place string decryptor** guarded by
  `pthread_mutex` at `0xa8190` and a one-time flag at `0xa8188`; it rewrites the metadata blob at
  `0xa28e0`/`0xa28f0`/`0xa2920` with `bit/eor/ushr/shl` vector ops before any real work.
* Its import table is the strongest static evidence of capability without plaintext:
  `ptrace`, `syscall`, `getppid`, `getpgid`, `popen`, `access`, `stat/stat64/statfs/statvfs`,
  `uname`, `opendir/readdir/readlink`, `dlopen/dlsym/dladdr`, `mprotect`, `socket`, `getpwuid`.
  That is the classic anti-debug + root/emulator + maps-scan profile.
* Practical hook: because strings are decrypted at runtime, static xrefs to method names do
  not exist. Hook `JNI_OnLoad+0x0` (0x6da30) *after* the mutex-protected decryptor returns, or
  hook `pthread_mutex_unlock` at 0x6d810, then dump `0xa28e0..0xa2960` — the decrypted
  class/method metadata is there. (Not executed here; read-only task.)
* `libtdcoreplugin.so` is **xCrash** (`com.trustdecision.android.bugly.NativeBugly`,
  `__abce`/`xc_crash_init`). It contains `xcc_util_is_root` and a su-path table
  (`/data/local/su`, `/data/local/bin/su`, `/data/local/xbin/su`, `/system/xbin/su`,
  `/system/bin/su`, `/system/bin/.ext/su`, `/system/bin/failsafe/su`, `/system/sd/xbin/su`,
  `/system/usr/we-need-root/su`, `/sbin/su`, `/su/bin/su`). This is **crash-report telemetry**
  only (recorded in the tombstone), not a gate — do not confuse it with detection.

### 3.7 `libgamemaster.so` — no root detection; “AI recommendation” is network-only

* 2.3 k exports, Lua 5.4 VM + lwIP + QPP protocol. No `su/magisk/root/ptrace/property`
  detection corpus (keyword scan: zero).
* “detect/accel recommendation” symbols (`startNodeDetect`, `isNodeDetected`, `detectGameDelay`,
  `detectAccessDelay`, `startAccelRecommendation`, `getAccelRecommendation`,
  `onAccelRecommendationWindowPop`, `startTranssionDetect*`) are **network latency / node
  selection** features of the game acceleration SDK (`com.subao.vpn.VPNJni`), not
  root-gated AI recommendation. Root gating for the Game Assistant product lives in the Java
  layer + libhisec/libhonordetect (§1/§2), not here.

---

## 4. Widevine APEX — payload, lifecycle, L1→L3

### 4.1 Payload inventory (`apex_payload.img`, ext4, 5,529,600 B)

```
/bin/hw/android.hardware.drm-service-lazy.widevine   2,378,200   (whole WVCdm + libwvdrmengine)
/lib64/libcrypto.so                                  1,543,240   (used by L3 software crypto)
/lib64/libc++.so                                     1,049,704
/lib64/libbase.so                                      218,592
/lib64/libaconfig_storage_read_api_cc.so               122,080
/lib64/libcutils.so                                    118,152
/lib64/wv_media_drm_flags_c_lib.so                      51,592
/etc/com.google.android.widevine.lazy.rc                   413
/etc/vintf/com.google.android.widevine.xml                 349
/apex_manifest.pb                                          113
```

`apex_manifest.pb` decodes to: name `com.google.android.widevine.lazy`, version `1524522994`,
and native-library list `liboemcrypto.so, libbinder_ndk.so, libc.so, libdl.so, liblog.so,
libm.so`. **`liboemcrypto.so` is declared but not shipped** — it must come from the vendor
partition, and on this device it does not exist (see device log, §4.4).

**There is no separate `libwvdrmengine.so` / `libl3oemcrypto.so` in this payload** — both are
statically linked into the 2.3 MB service executable. Evidence inside that binary:

* embedded source paths: `vendor/widevine/libwvdrmengine/src/serviceLazy.cpp`,
  `…/cdm/core/src/{cdm_engine,policy_engine,oemcrypto_adapter_dynamic,client_identification,
  device_files,service_certificate}.cpp`, `…/level3/src/{level3_adapter,generate_entropy_android}.cpp`;
* L3 symbols/strings: `Level3_DecryptCENC`, `L3_INITIALIZATION_FAILED`, `L3_RNG_FAILED`,
  `OEMCrypto version (L3 security level): %s.%s`;
* the bundled `libcrypto.so` is the L3 crypto backend: imports
  `EVP_aes_128_cbc`, `EVP_EncryptInit/Update/Final_ex`, `RSA_public_encrypt`, `SHA256*`,
  `EVP_DigestVerify*`, `X509_*` (33 OpenSSL imports total).

So “libl3oemcrypto” in Widevine terminology is the *software L3 adapter compiled into
libwvdrmengine*, not a shared object on this APEX.

`/etc/*.rc`:

```
service vendor.drm-widevine-hal /apex/com.google.android.widevine.lazy/bin/hw/android.hardware.drm-service-lazy.widevine
    interface aidl android.hardware.drm.IDrmFactory/widevine
    oneshot
    disabled
    class hal
    user media
    group media mediadrm drmrpc system
    ioprio rt 4
    task_profiles ProcessCapacityHigh
```

No seccomp/`on property` triggers besides `apex.all.ready=true` (mkdir `/data/vendor/mediadrm`).

### 4.2 Root detection: **none**

Evidence:

* Full string inventory of every payload binary: **zero** matches for
  `magisk|superuser|test-keys|ro\.secure|debuggable|frida|xposed|/system/xbin/su|rooted|
  RootDetection|ptrace|/proc/self/maps`.
* The only `root` substrings are DRM-domain: `"Could NOT install root key from %s"`,
  `"root key"` (keybox root of trust), and `"ro.hardware|ro.product.*|ro.build.*"`
  property reads used for **device identification** (`ro.vendor.cdm.device/model/manufacturer`,
  `ro.serialno`, `ro.build.fingerprint`, `ro.product.first_api_level`, …) — standard CDM
  device-info for certificate provisioning, not integrity checks.
* L1/L3 downgrade is driven by keybox/OEMCrypto availability, **not** by root state.

### 4.3 Service lifecycle (why it stays alive / dies / crashes)

`main` region (`.text` start 0x4c000, `main`-equivalent 0x4cbec):

```
0x4cbec  build service name: <base> + "/widevine"  -> "android.hardware.drm.IDrmFactory/widevine"
0x4cd94  weak-ref holder for the AIBinder (called at 0x4cc48; AIBinder_Weak_new/_promote/_delete)
0x4cc64  AServiceManager_registerLazyService(name, binder)     [PLT 0x162320]
0x4cc68  AIBinder_decStrong(binder)
0x4cc88  if (status != 0) -> cold path 0x4cd04:
             0x60cbc  android logging helper("WidevineAidlService") - CHECK-style fatal message
             "Check failed: status == STATUS_OK"
             "Failed to add Widevine Factory HAL, status=" << status
             -> LogMessage dtor -> LOG(FATAL) -> __android_log_call_aborter -> abort()
0x4cc8c  ABinderProcess_joinThreadPool()      [PLT 0x162340]  (blocks forever)
```

* **Registration is lazy**: `AServiceManager_registerLazyService` tells servicemanager that
  this HAL can be started on demand and may exit when idle. The system-side
  `AidlLazyServiceRegistrar` (libbinder, not in this APEX) emits the familiar
  `Registering service android.hardware.drm.IDrmFactory/widevine` and
  `Process has N (of 1 available) client(s) in use` lines and triggers process shutdown when
  the last client releases its binder.
* **Stay-alive condition**: at least one live binder client (an app's `DrmPlugin`/session).
  The service itself has **no idle timer, no polling loop, no L1 retry loop** — after
  `joinThreadPool()` it sleeps in binder. A leaked `MediaDrm`/session in `com.hihonor.id`
  keeps the process (and its ~2.3 MB text + libcrypto) resident indefinitely; that matches the
  “client(s) in use: 1” line in `m6-recreate-log.txt`.
* **Crash paths** (abort → SIGABRT, reported as a native crash):
  1. `AddService`/register failure → `CHECK(status == STATUS_OK)` region 0x4cd04;
  2. binder NDK `sp<>` refcount race → `__assert(..., "Race detected.")` from
     `frameworks/native/libs/binder/ndk/include_cpp/android/binder_auto_utils.h` (0x4cd78);
  3. libc++ built with `-fno-exceptions` → any `std::` failure ends in
     `__libcpp_verbose_abort` (0x162350) and `"terminating."`.
* **Restart behaviour**: `oneshot` + `disabled` means init will not auto-restart on crash, but
  the lazy-service mechanism re-`start`s the service on the next client request. A crash loop
  therefore shows as repeated “process started / died” cycles only when clients keep
  reconnecting.

### 4.4 L1 → L3 fallback: complete trigger map

All fallback reasons are collected as metrics (`drm_metrics.WvCdmMetrics`) whose literals
document the paths:

```
USING_L3_WRONG_L1_VERSION          liboemcrypto.so version mismatch
USING_L3_L1_LOAD_FAILED            liboemcrypto.so dlopen/version/symbol load failed
USING_L3_L1_OPEN_FAILED            L1 OEMCrypto open/session failed
USING_L3_BAD_KEYBOX                keybox rejected
USING_L3_COULD_NOT_INSTALL_KEYBOX  keybox installation failed
USING_L3_COULD_NOT_OPEN_FACTORY_KEYBOX   factory keybox could not be opened
L3_INITIALIZATION_FAILED / L3_RNG_FAILED
FORCE_LEVEL3_OEMCRYPTO             explicit force
USING_L1_INSTALLED_KEYBOX / USING_L1_WITH_KEYBOX / USING_L1_WITH_PROVISIONING_3_0/4_0
```

Pipeline (all in the single DRM service binary):

| Stage | Address | Code / string |
|---|---|---|
| Query supported level | **0xb3e04** (`cdm_engine.cpp`) | `CdmEngine::IsSecurityLevelSupported(level)`; log `"level = %s"`; builds an adapter (0x87cd4/0x7c4a8), for L1 passes 0, for L3 passes 1, compares result |
| Force-L3 property | **0x162180** reads `persist.drm.forcel3.enabled`; decision at 0x8c638 | `"User requested falling back to L3"` (0x7e0ac) |
| Force-L3 env | **0x7e0f8** `getenv("FORCE_LEVEL3_OEMCRYPTO")` == `"yes"` | `"Test code. User requested falling back to L3"` (0x7e0d0) |
| L3 first | 0x7e124 | `"L3 Initialized. Trying L1."` |
| Load L1 lib | **0x7e2f0** `dlopen(path, RTLD_NOW)` in loop; 0x7e238 | `"L1 library not specified. Falling back to L3"` (0x7e24c); `"Could not load oemcrypto from path %s.  %s"` (0x7e330); `"Could not load oemcrypto. Falling back to L3."` (0x7e5a8) |
| Version check | **0x83564–0x835b0** (`LoadLevel1`) | `"liboemcrypto.so is version %d, not %d. Falling back to L3."` (0x835a0) |
| Symbol resolve | **0x8325c…0x83abc** (`LoadLevel1`, dlsym) | `_oecc01, _oecc02, _oecc22, _oecc93, _oecc63, _oecc61, _oecc132, _oecc10 …`; failure → `"Could not load L1 %s."` + `"Still falling back to L3."` (0x83290) |
| Keybox validate/install | **0x7e40c–0x7e618** (`ValidateOrInstallL1KeyboxOrCert`, `TryToInstallKeybox`) | `"L1 not initialized. Falling back to L3"` (0x7e420); `"L1 invalid function pointers. Falling back to L3"` (0x7e574); `"Could NOT install root key from %s"` (0x7e538); `OEMCrypto_InitializeAndCheckKeybox` → `"Keybox error: %d. Falling back to L3."` (0x7e608) |
| L1 success | 0x7e174 | `"OEMCrypto_Initialize Level 1 success. I will use level 1."`, `"Level 1 Build Info (v%d): %s"` |
| Per-session downgrade | **0xaef38** (`cdm_engine.cpp` `OpenSession`) | `"Engine is falling back to L3"` (0xaef5c) when opening the requested L1 session fails |
| Per-request downgrade | **0xb3ed0** (`GetProvisioningRequest`) | `"Engine is falling back to L3"` (0xb40b8) |
| Policy downgrade | **0x104840** (`policy_engine.cpp`) | `"App requested L1 security on a non-L1 device."` (0x104a5c) |
| OTA keybox | **0xbb294** (`~OtaKeyboxProvisioner`) | `"OTA Provisioning not processed. Falling back to L3"` (0xbb328) |

**Keybox error 25.** In `ValidateOrInstallL1KeyboxOrCert`, when the adapter's keybox-status
field is zero the code substitutes `0x19` (25) — `ldr w8,[x24,#4]; mov w9,#0x19;
csel w20, w9, w8, eq` at 0x7e430–0x7e43c — and the failure path at 0x7e5f4 logs
`"Keybox error: 25. Falling back to L3."`. A status of `0x3d` (61) is explicitly treated as
non-fatal (0x7e5e4). So “Keybox error: 25” means *L1 keybox is absent/uninitialised for this
boot*, which is exactly what happens when the L1 crypto adapter never loaded.

**On this device** (`m6-recreate-log.txt`) the sequence is:

```
WVCdm: IsSecurityLevelSupported level = L1                    (0xb3e04)
WVCdm: Could not load oemcrypto … liboemcrypto.so not found   (0x7e330, dlerror text)
WVCdm: Falling back to L3
WVCdm: ValidateOrInstallL1KeyboxOrCert L1 not initialized. Falling back to L3 (0x7e420)
WVCdm: Keybox error: 25. Falling back to L3                   (0x7e5f4)
```

i.e. `vendor` provides no `liboemcrypto.so`, therefore L1 is impossible, therefore every
session is L3. **Root/KernelSU is not an input to this decision.** (If root experiments change
anything here it would only be via APEX/binder visibility, not via a detector.)

> Note: the string `Is commercial user: %d` present in the captured logcat is **not** in this
> pulled APEX payload (all payload binaries scanned). Either the device runs a different
> Widevine APEX build than the pulled artifact, or the line comes from another component in
> the same process namespace. Flagged for completeness; no behavioural conclusion drawn.

### 4.5 Widevine quick-reference offsets

| VA | Item |
|---|---|
| 0x4c000 | `_start` (PIE entry) |
| 0x4cbec | service main / lazy registration block |
| 0x4cc64 | `AServiceManager_registerLazyService` call |
| 0x4cc8c | `ABinderProcess_joinThreadPool` call |
| 0x4cd04 | CHECK/abort cold path (`"Check failed: status == STATUS_OK"`) |
| 0x4cd94 | AIBinder weak-ref holder |
| 0x7d504–0x7e620 | `oemcrypto_adapter_dynamic.cpp::Initialize` + keybox validation |
| 0x7e2f0 | `dlopen(liboemcrypto.so)` |
| 0x7e330 / 0x7e5a8 | oemcrypto load failure logs |
| 0x7e40c–0x7e618 | `ValidateOrInstallL1KeyboxOrCert` / `TryToInstallKeybox` |
| 0x8325c… | `LoadLevel1` (dlsym `_oecc*`) |
| 0x83564 | version check + more dlsym |
| 0xaef38 | `CdmEngine::OpenSession` L1→L3 fallback |
| 0xb3da0/0xb3e04 | `IsSecurityLevelSupported` |
| 0xb3ed0 | `GetProvisioningRequest` fallback |
| 0x104840 | policy engine (L1 request on non-L1 device) |
| 0xbb294 | OTA keybox provisioner |
| 0x162180 | reads `persist.drm.forcel3.enabled` |

---

## 5. Concrete hook points (analysis only — not applied)

### 5.1 libhisec (`com/hihonor/secure/android/common/detect/S`)

| Target | VA | Suggested action for behavioural study |
|---|---|---|
| `irtj` | 0x234c | return 0 (`mov w0,#0; ret`) → root sensor blind |
| `is_bin_exists` | 0x2484 | return 0 → all su/magisk probes blind (covers both `irtj` calls) |
| `irpj` | 0x229c | return 0 → accept re-signed APK |
| `get_signature_sha256` | 0x2758 | return a known-good hash string (`B928…0F05`) |
| `idj` | 0x14dc | return 0 → hide tracer/IDA |
| `iej` | 0x18ac | return 0 → hide emulator |
| `JNI_OnLoad` | 0x2568 | patch the 4 method pointers @0x1bc90.. (`.data.rel.ro`/RELRO, needs mprotect or a pre-load memory write) |

Note: `RegisterNatives` binds at load time, so either hook after `JNI_OnLoad` or patch the
table before `System.loadLibrary` completes (constructor-time hooking).

### 5.2 libhonordetect (`...usm.skit.detect.NativeLib`)

| Target | VA (gameassistant / Honor-ID) | Action |
|---|---|---|
| `isRT` | 0x5d24 / 0x5cd4 | force return 0 (or force `0x10000` to emulate LSPosed) |
| `isSMT` | 0x603c / 0x5fc8 | force return 0 |
| `isDG` | 0x65a8 / 0x6548 | force return 0 |
| `scan_file` | 0x5bfc | return 0 → disables maps/cpuinfo scans for both isRT and isSMT |
| isRT insecure-build branch | 0x5ee4 (`cmp w8,#0x31`) / 0x5f48 | force the `flags=0` path to drop bit 8 |
| isRT hook-path loop | 0x5f90 | make the 19 `access()` calls fail |

### 5.3 Widevine (CDM policy / lifecycle experiments)

| Goal | Target | Note |
|---|---|---|
| Force L3 (clean, no patching) | property `persist.drm.forcel3.enabled=1`(read @0x162180) or env `FORCE_LEVEL3_OEMCRYPTO=yes` | both are first-class switches in the binary |
| Force L1 (make CDM *try* L1) | `IsSecurityLevelSupported` @0xb3e04 | return `true` for level 1; CDM will still downgrade if the adapter fails |
| Keep the process alive | skip `AServiceManager_registerLazyService` @0x4cc64 (branch over) or hook the lazy-registrar shutdown callback | process then never idle-exits; `joinThreadPool` blocks |
| Stop idle restart | hook `main` @0x4cbec to exit after `joinThreadPool` returns | |
| Suppress “App requested L1 … non-L1 device” downgrade | 0x104a50/0x104a5c region | forces policy to keep requested level |
| Make L1 init “succeed” without vendor lib | `dlopen` result @0x7e2f0 or `LoadLevel1` @0x8325c | return a fake handle / skip version+dlsym checks; keybox validation then becomes the next gate (0x7e2e4) |
| Skip keybox gate | branch at 0x7e5e4 (`cmp w20,#0x3d`) / 0x7e5f0 | return success path |
| Observe L1/L3 decisions | log function @0x63434 (writes `WVCdm` tag) or metrics hook | all reasons carry the `USING_L3_*` metric names |

### 5.4 Root-state consumers

| Target | Library | Note |
|---|---|---|
| `isRoot` reflective lookup | `libhwkeystore_jni.so` (strings @0x10689/0x18ffd) | HUKS/asset anti-root gate; the real “policy” point |
| `strictRoot` | `libhwkeystore_jni.so` @0x11a9f | stricter local check |
| `xcc_util_is_root` | `libtdcoreplugin.so` (name string @0x22f8) | telemetry only (crash report) |
| TrustDecision root/hook sensors | `libtrustdevice.so` | encrypted; hook after NEON decryptor @0x6d6a0/0x6d810 |

---

## 6. Cross-cutting findings

1. **Three distinct detector families are in play**, with different corpora and semantics:
   * `libhisec` (`AegisSecComp`) — property + path + APK-signature + anti-debug, boolean returns;
   * `libhonordetect` (USM SKIT) — huge path/property corpora, **bitmask** returns incl. a
     hook-framework bit (`0x10000`) and an insecure-build bit (`0x100`);
   * TrustDecision (TDC) — fully obfuscated, telemetry-oriented, no static strings.
2. **`libhisec` is shared verbatim** by Game Assistant, MagicVoice (AI sidebar) and Honor ID —
   one binary, three apps. The Honor-ID `libhonordetect` is a rebuild with identical tables.
3. **The AI sidebar's own native code is not the root gate.** MagicVoice ships the same
   `libhisec`/`libhonordetect` sensors; `libods` is crypto only; `libdatabus_session` is IPC only.
   Game acceleration / “AI recommendation” (`libgamemaster`) is network QoS, not root-gated.
4. **Real root policy sits in `libhwkeystore_jni.so` (securityserver/HUKS)** — it consumes
   `isRoot`/`CheckRootStatus`/`strictRoot` and stamps an anti-root error code onto asset keys.
5. **Widevine contains no root detection at all.** Its L1→L3 fallback on this device is caused
   by the missing vendor `liboemcrypto.so` (APEX declares it, payload does not ship it),
   followed by keybox error 25. The lazy HAL stays alive exactly as long as a DRM client holds
   a binder; it has no internal retry loop, so “abnormal CPU” should be sought in client-side
   session leaks, not in detector loops.
6. **The most useful static levers** for further dynamic work are:
   `persist.drm.forcel3.enabled` / `FORCE_LEVEL3_OEMCRYPTO` (Widevine), the `0x10000` hook bit
   (libhonordetect, easiest way to test “does anything act on hook detection?”), and the
   `irpj` signature allow-list (libhisec) which will fire on any re-signed APK.

---

## 7. Method notes & limitations

* All function boundaries in Widevine come from `.eh_frame_hdr` FDE parsing (2,519 functions);
  clang hot/cold splitting produces several adjacent FDE fragments for one logical function
  (e.g. `LoadLevel1` spans 0x8325c–0x83abc across fragments), so ranges are cited as regions.
* libhisec/libhonordetect boundaries come from `llvm-nm` exports + heuristic prologue
  detection; they are function-exact for the exported JNI entries cited.
* `isSMT` property-chain semantics are reported as compiled, including the accumulating-index
  quirk; a behavioural confirmation would need instrumentation on an emulator image (not
  performed here).
* `libtrustdevice.so` was *not* decrypted (no execution); only its obfuscation scheme, imports
  and the decryptor entry points are documented.
* The `Is commercial user: %d` log line could not be located in the pulled APEX payload;
  the pulled artifact may differ from the installed one.

## 8. Reproducibility

```
work\reverse\native\
  scripts\elfx.py            ELF/capstone helpers (PLT names, annotated disasm, strings, xref)
  scripts\ext4read.py        pure-python ext4 (extents, 64-bit group desc)
  scripts\triage.py          generic per-.so triage (JNI tables, keyword strings)
  scripts\wv_funcs.py        EH-frame function discovery + Widevine key dumps
  scripts\wv_extract.py      APEX payload extraction
  scripts\export_tables.py   -> tables.json
  disasm\                    annotated disassembly dumps (hisec.*, gameassistant-libhonordetect.*, wv.*)
  apk-libs\                  extracted Honor-ID native libs (libtrustdevice, libtdcoreplugin, ...)
  widevine\                  extracted APEX payload
  tables.json                all recovered path/property/hash tables
```

Example:

```
python work\reverse\native\scripts\triage.py work\native-analysis\gameassistant-libhisec.so
python work\reverse\native\scripts\wv_funcs.py
python -c "import sys;sys.path.insert(0,'work/reverse/native/scripts');import elfx;..."
```
