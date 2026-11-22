# 一加16 2.12.19 管理器 KMI .ko 自适应提取逻辑

样本：

- 文件：`一加16提权越狱_2.12.19.APK`
- SHA-256：`143A5C27D311A376F15F950CBE49CAD1FB07F44C36800B489AF1882D9E0FD0D8`（占位，构建时以实际为准）
- 反编译工具：jadx 1.5.6
- 关键类：`defpackage.ts`、`defpackage.ne1`、`defpackage.z61`、`defpackage.x61`

## 1. 结论

管理器 APK 的 `lib/arm64-v8a/libksud.so` 不是单纯 ksud，它内部**内嵌多个 raw-deflate 压缩的 KMI .ko**。
2.12.19 的管理器自适应不是扫描 `.ko` zip entry，而是：

```text
管理器 APK / split APK
-> 提取 lib/arm64-v8a/libksud.so
-> 扫描 0xED 前缀的 raw-deflate 流
-> Inflater(true) 解压
-> 校验 ELF 头 + 64KB..900KB
-> 解析 .modinfo vermagic
-> 选择匹配 KMI 的唯一模块
-> 重写 vermagic 为 uname -r
-> 写入 adapters/<hash>/module.ko + ksud
-> 交给 onuce 加载
```

## 2. 反编译证据

### ts.F：管理器自适应入口

`ts.F(context, managerPkg, signature, trustRoot, yy)`：

1. 取 `PackageInfo.applicationInfo.sourceDir` 与 `splitSourceDirs`；
2. 复制到 `/data/local/tmp/onekey-adapters/<nanoTime>/`；
3. 从每个 APK 提取 `lib/arm64-v8a/libksud.so`；
4. 对每个库调用 `ts.j(bytes, yy, true)` carve；
5. 选中后调用 `ts.D(fy0, uname -r)` 重写 vermagic；
6. 写入 `adapters/<apkHash>/module.ko`、`ksud`；
7. 返回 `ey0`（manager pkg/flavor/version/module path/ksud path/vermagic）。

### ts.j：carve 算法

```text
for off in libksud.so:
    if byte[off] != 0xED: continue       # raw-deflate 快筛
    inflater = Inflater(true)
    inflater.setInput(lib, off, len-off)
    head = inflate(4)
    if head != 7F 45 4C 46: continue     # ELF
    inflate rest, limit 900000
    if size < 65536 or > 900000: continue
    metadata = v(ko)                     # .modinfo
    select vermagic contains 6.18        # 2.12.19 目标
```

完整扫描回退：0xED 快筛未命中时 `j(..., false)` 对每个字节 probe。

### ts.D：vermagic 重写

- 解析 ELF64 section headers，找 `.modinfo`；
- 读取 `vermagic=`；
- 替换为当前 `uname -r` + 原后缀（如 ` SMP preempt mod_unload modversions aarch64`）；
- 将新 `.modinfo` 追加到 ELF 末尾，更新 section header offset/size；
- 返回新 bytes + sha + vermagic。

### 2.12.19 的加载路径

- `98260` 目标固定校验：
  `6.18.21-android17-5-gf957accaf563-ab15926176-4k`
- 管理器非 SukiSU：使用 `ey0.f`（刚提取的 module.ko）
- SukiSU：使用 assets `core/onuce/sukisu.ko`
- `onuce run <dir> <flavor>` 执行；`onuce finalize` 收尾。

因此 2.12.19 是**单机型 6.18.21 自适应**，不是通用多 KMI；其 carve 机制可用于任意 KMI。

## 3. 样本实测 carve 结果

对当前已下载的官方/Next 管理器执行同一算法：

### 官方 KernelSU 3.3.1

```text
lib/arm64-v8a/libksud.so  4,990,848 B
6.12.76-4k   404,928 B  off=854759
6.6.127-4k   330,664 B  off=743310
6.18.32-4k   375,328 B  off=987194
5.10 / 5.15 / 6.1 亦存在
```

### KernelSU-Next 3.4.2

```text
lib/arm64-v8a/libksud.so  7,059,584 B
6.12.76-4k   500,656 B  off=2262539
6.12.76-4k   508,928 B  off=2401146
6.6.127-4k   435,208 B  off=1827442
```

所以“管理器 .ko 自动提取”的正确来源是 `libksud.so` 内嵌流，而不是 APK `.ko` entry；这也解释了之前 `MANAGER_LKM=none reason=no_ko_entry`。

## 4. 本工程移植

`MainActivity.extractManagerLkm(flavor)` 已改为：

```text
sourceDir + splitSourceDirs
-> lib/arm64-v8a/libksud.so
-> carve 0xED raw-deflate
-> ELF + 64K..900K + .modinfo vermagic
-> 选择当前 KMI（如 6.12）的唯一模块
-> WORK/ko-<flavor>.ko
-> kernel_profiles.sh per-flavor override
-> ko_patch 重写 vermagic/符号
```

日志：

```text
MANAGER_LKM=/data/local/tmp/magic/ko-<flavor>.ko source=...!lib/arm64-v8a/libksud.so bytes=... kernel=6.12 vermagic=6.12.76-4k ...
MANAGER_LKM=none package=... reason=no_embedded_ko
```

回退顺序：

1. `libksud.so` 内嵌 carve；
2. 管理器 APK 真 `.ko` entry；
3. 内置 per-flavor 模板。

## 5. 与旧实现差异

旧实现只找 `.ko` zip entry，因此对官方/Next/SukiSU 管理器全部返回 none。
新实现按 2.12.19 的 carve 逻辑从 `libksud.so` 提取 KMI 模块，并保留 vermagic 校验。

## 6. 限制

- 代码只验证了 carve 算法在样本上的结果，未在 6.12.58 真机执行；
- 选中的 6.12.76 KMI 仍需 `ko_patch` 重写 vermagic 和符号，无法直接 insmod；
- 设备当前 adb 离线，未实机回归。
