# .ko 提取逻辑修复

## 问题

SukiSU Ultra 管理器 APK 的 native lib 内嵌多个 KMI 的 raw-deflate `.ko`：

```text
5.10.252
5.15.202-android13
5.15.202
6.1.166
6.6.127-4k
6.12.76-4k
6.18.32-4k
```

设备内核是：

```text
6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
```

旧逻辑错误选中了：

```text
vermagic=6.6.127-4k-g46a034eca005-dirty
```

导致 `ko-sukisu.ko` 与当前内核 KMI 不匹配。

## 原因

1. KMI 来源过于依赖 `uname -r`，可能被 SuSFS/内核 spoof 影响。
2. 普通 `.ko` 兜底没有校验 KMI。
3. 选择候选时没有严格比较 `major.minor`，也没有优先同 patch。
4. 选择失败后没有先删除旧的 `ko-<flavor>.ko`，可能继续使用上次的错误模块。

## 修复

`extractManagerLkm` / `carveKmiKo` 现在：

1. **KMI 来源优先级**：
   ```text
   System.getProperty("os.version")     // App 实际 os.version，优先
   uname -r                              // 兜底
   /proc/version                         // 最后兜底
   ```
2. 解析目标：
   ```text
   KMI   = major.minor       (6.12)
   patch = major.minor.patch (6.12.58)
   ```
3. 所有候选严格满足：
   ```text
   vermagicKmi == targetKmi
   ```
   例如目标 6.12 时，6.6.127 永远不会被选中。
4. 同 KMI 下优先精确 patch（6.12.58）；没有时选同 KMI（6.12.76），由 `ko_patch` 后续改写 vermagic。
5. 管理器内没有匹配 KMI 时，才回退内置模板：
   ```text
   ksu-template-<flavor>.ko
   ksu-template.ko
   ```
   回退前同样校验 KMI。
6. 如果没有匹配候选：
   ```text
   rm -f /data/local/tmp/magic/ko-<flavor>.ko
   MANAGER_LKM=none reason=no_matching_kmi target=6.12
   ```
   不允许静默使用错误 KMI。
7. 写盘前再次校验选中模块的 `vermagicKmi == targetKmi`，失败则拒绝。

## 实测

修复后部署日志：

```text
MANAGER_LKM=/data/local/tmp/magic/ko-sukisu.ko
source=.../base.apk!lib/arm64-v8a/libeexgslcpwg.so
bytes=601056
kernel=6.12
patch=6.12.58
vermagic=6.12.76-4k SMP preempt mod_unload modversions aarch64
```

修复前：

```text
bytes=523744
kernel=6.12
vermagic=6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64
```

修复后选中 601056 字节的 6.12 KMI 模块，root 链可正常加载。

## 相关文件

- `main/compose-app/app/src/main/java/com/aoki/magicroot/MainActivity.java`
  - `extractManagerLkm`
  - `carveKmiKo`
  - `kmiOfKernel` / `kmiOfVermagic` / `patchOfKernel`
  - `readBundledTemplate`


## 64560 利用链同步

64560 链在 
un.sh 里原本有自己的 manager .ko 扫描逻辑，会绕过 App 已经修好的提取结果。现已同步：

1. 优先读取 App 写出的：
   `	ext
   /data/local/tmp/magic/ko-<flavor>.ko
   `
2. 读取该文件 .modinfo vermagic，严格比较 major.minor 与目标 KMI；
3. 只有 ELF 且 KMI 匹配时才设置：
   `	ext
   KO_TEMPLATE=<app-staged ko>
   KO_COMPAT=app-staged
   `
4. App-staged 文件无效时删除它，才回退到原来的 APK 内 .ko 扫描；
5. 旧扫描结果同样增加 vermagic/KMI 校验，不再直接接受任意 ELF；
6. 64560 的 
oot_stage.sh su 探测同步支持：
   `	ext
   /system/bin/su
   /product/bin/su
   /data/adb/ksu/bin/su
   /debug_ramdisk/su
   `

日志示例：

`	ext
MANAGER_LKM=/data/local/tmp/magic/ko-sukisu.ko source=app-staged bytes=601056 kernel=6.12 vermagic=6.12.76-4k...
KO_TEMPLATE_SOURCE=app-staged template=ko-sukisu.ko
ROOT_STAGE_SU_USED=/system/bin/su
`
