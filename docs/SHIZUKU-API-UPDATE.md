# Shizuku API update

Source fork:

```text
https://github.com/XiaoTong6666/Shizuku-API
branch main
HEAD 2089614f9e763d9a2f990db6fde2b0c06b9502ba
date 2026-10-30T05:16:30Z
```

The repository was fetched from the fork itself (codeload tarball), not from a
cached local copy.  It is based on the RikkaApps Shizuku-API tree and adds the
recent API/server fixes:

```text
13aeedbc fix(api): harden Binder forwarding and handoff
5b02a897 fix(server): support API 23 remote process tracking
a51d9fe5 fix(rish): read synchronous Binder replies
```

## Version delta

Old bundled jars:

```text
SERVER_VERSION       13
SERVER_PATCH_VERSION 5
```

New fork jars:

```text
SERVER_VERSION       13
SERVER_PATCH_VERSION 6
```

## Rebuilt jars

Built with the fork's Gradle modules:

```text
:aidl:assembleRelease
:shared:assembleRelease
:api:assembleRelease
:provider:assembleRelease
```

Replaced in `main/app/libs/`:

```text
shizuku-api.jar
  size    28,258
  sha256  EBCD657ED2375BBA323AE6FC8F0ED2B4A9B6978F6B0D84B805F318CB250066C8

shizuku-provider.jar
  size     6,850
  sha256  561E3E54B4455E3C3B36DFD303C5EC4D2F3D485E1DC42538FABFF6F0708498C5

shizuku-aidl.jar
  size    26,433
  sha256  3738B260B59EACBDF65BD18DD81C04D8A81AC565C2CD23EE24A4FE0BD6A729C4

shizuku-shared.jar
  size     9,769
  sha256  FE49B8E83874D212A1F2412227AB596C0019D1F193F1D8F2608FE246C0E7F7EB
```

Build verified:

```text
:checkReleaseDuplicateClasses
:compileReleaseJavaWithJavac
:minifyReleaseWithR8
:packageRelease
BUILD SUCCESSFUL
```

The application still uses only the Shizuku API.  Stellar-specific classes,
provider, and jars were already removed; a Stellar installation that exposes a
Shizuku-compatible binder is handled through the same Shizuku code path.

## Provider

The existing manifest provider is unchanged:

```xml
<provider
    android:name="rikka.shizuku.ShizukuProvider"
    android:authorities="com.aoki.magicroot.shizuku"
    android:enabled="true"
    android:exported="true"
    android:multiprocess="false" />
```

The fork's provider jar contains the updated provider and binder container.

## Device verification

Installed and verified on the connected test device:

```text
model  MLY-AN00
kernel 6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
android 17
```

Application UI:

```text
✓ Shizuku 已连接
通道 Shizuku · Shizuku 已授权
```

`dumpsys package com.aoki.magicroot` after install:

```text
Registered ContentProviders:
  com.aoki.magicroot/rikka.shizuku.ShizukuProvider

queriesPackages=[moe.shizuku.privileged.api, ...]
```

No `StellarProvider`, no `roro.stellar.manager` query.  The Shizuku binder
connected successfully through the rebuilt fork jars.

## Remote shell fix

The first fork build could bind correctly (`Shizuku 已连接`) but `newProcess`
returned no output.  The cause was app-side: `MainActivity` wrapped the
returned service binder in `ShizukuBinderWrapper` even though
`Shizuku.getBinder()` already is the `IShizukuService` binder.

Fixed to:

```java
IShizukuService service = IShizukuService.Stub.asInterface(binder);
```

After this change the device deployment completed:

```text
WORKDIR_PROBE=WRITABLE
ASSET_MISSING=ksud_fina
ASSET_SYNC=ok count=95 chain=98260
MANAGER_LKM=... ko-fina.ko
部署完成
```

Also, optional bundled `ksud_*` helpers that are not present are skipped with
`ASSET_MISSING=...`; manager extraction supplies the selected flavor.
