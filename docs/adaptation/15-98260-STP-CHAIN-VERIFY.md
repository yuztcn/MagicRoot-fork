# 98260 链路与 STP commit 对比核验

对比基线：

- STP/SUSFS 资产引入：`3fb1fa4 feat: su product/bin entry, SUSFS LKM assets, 64560 STPClear and About refs`
- su_entry 门控修正：`3fcdce3 fix: gate 98260 su entry on KSU loaded state`
- 当前 HEAD：`6ede7f9`

## 1. 98260 链路步骤

按 STP commit 与当前 `run.sh` / `run98260.sh` 对照，链路包含：

```text
PREFLIGHT
CHAIN=98260
98260 exploit/rootd
98260 KSU patch + late-load ksud
98260 KSUD install / manager refresh
98260 su_entry.sh
98260 features (kernel_umount / selinux_hide / adb_root / su_compat)
98260 success
optional SUSFS (only when switch on)
optional soft reboot (blocked if SUSFS live)
rootd cleanup
```

STP commit 中 `stp_clear_fix` 只是函数定义，链上没有自动调用；STP clear 仍由手动按钮执行。当前保持一致，不属于链路缺失。

## 2. 实际日志发现的链路缺陷

最近一次 98260 run.log：

```text
SU_ENTRY_REAL_SU=-rwxr-xr-x 1 root root 5932624 ... /system/bin/su
SU_ENTRY_SAFE_SU=/data/local/tmp/magic/su
SU_ENTRY_PRODUCT_BIN=/product/bin/su
SU_ENTRY_BACKEND=/data/local/tmp/magic/su
SU_ENTRY=failed backend=/data/local/tmp/magic/su uid=unknown
98260_SU_ENTRY_RC=1
```

原因：

- STP commit 的 su_entry 先选 `SAFE_SU`（rootd 包装器）；
- KSU late-load 后处于 Enforcing，rootd socket 路径对 su 上下文不一定可用；
- `/system/bin/su` 实际存在且可用，却被排在后面。

修复：

```sh
if [ -x /system/bin/su ]; then
    SU_BIN=/system/bin/su
elif [ -x "$SAFE_SU" ]; then
    SU_BIN="$SAFE_SU"
elif [ -x /data/adb/ksu/bin/su ]; then
    SU_BIN=/data/adb/ksu/bin/su
fi
```

Termux 的 `/product/bin/su` 与 rootd safe wrapper 仍保留为入口/回退。

## 3. SUSFS 死机与正确加载

最近日志中：

```text
SUSFS_LOAD=disabled reason=switch_off
SOFT_REBOOT_REPAIR=disabled
```

该次运行没有加载 SUSFS，因此不是 SUSFS 死机现场；设备在读取日志时重启，未取到有效 dmesg。

结合上游 OnePlus16 与已知路径，正确方式是：

```text
KSU late-load 成功
-> ksud insmod susfs_guard_lkm.ko expose_proc=1
-> 验证 /sys/module/susfs_guard_lkm
-> 不执行 soft reboot
```

已实现：

- 优先 `ksud insmod ... expose_proc=1`；
- 失败回退 `susfs_insmod` / 普通 insmod；
- SUSFS 已加载时 `soft_reboot_repair` 直接跳过并打印：

```text
SOFT_REBOOT_REPAIR=skip reason=susfs_lkm_loaded full_reboot_required
```

SUSFS 需要 framework 刷新时使用完整重启，不要用 soft reboot。

## 4. 管理器 KMI .ko 提取

已实现管理 APK 扫描：

```text
extractManagerLkm(flavor)
-> 仅接受 ELF .ko
-> 优先 kernelsu/ksu + 当前 KMI
-> 排除 susfs
-> 输出 WORK/ko-<flavor>.ko
```

当前官方/Next/SukiSU 管理器 APK 内没有 `.ko` entry，日志会是：

```text
MANAGER_LKM=none package=...
```

KSU 运行时自己的 `/data/adb/ksu/lib/*.ko` 是 **已 patch 的 live 模块**，不能直接当未 patch 模板重复 `ko_patch`；暂不自动用作 override。

## 5. 结论

- 98260 链路步骤完整，与 STP commit 对齐；
- 实际错误是 su_entry 后端选择，已修复；
- SUSFS 加载方式改为上游 `ksud insmod expose_proc=1`，并禁止加载后软重启；
- 设备重启后 adb 离线，修复未实机回归。

## 6. 管理器 .ko 提取修正

上游 OnePlus16 实际是把 ksu-base*.ko 作为越狱 App 自带 assets，管理器 APK 只负责 UI/授权；KernelSU 源码的 manager APK 也没有内置 KMI .ko（只有 libkernelsu.so 这类 userspace JNI）。

因此“从管理器提取”必须按 APK 实际内容处理，不能假定一定有：

- 应用侧 extractManagerLkm(flavor) 扫描 APK .ko；
- 
un.sh 在 KSUD 提取同阶段用 unzip -l/-p 再扫描一次；
- 仅接受 ELF、匹配当前 KMI、排除 susfs；
- 提取为 $D/ko-<flavor>.ko 并覆盖 KO_TEMPLATE，标记 KO_COMPAT=manager-apk；
- 当前官方/Next/SukiSU 管理器 APK 都没有 .ko，会回退到 bundled 模板并打印 MANAGER_LKM=none ...。

/data/adb/ksu/lib/*.ko 是已 patch 的 live 模块，不能直接当未 patch 模板重复 ko_patch，不作为自动 override。
