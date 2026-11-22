# SuSFS LKM 可选开关（非独立 Flavor）

参考：<https://github.com/Yunnijian/OnePlus16-Jailbreak>（MIT，vendored SuSFS GPL-2.0）。
上游实现把 SuSFS LKM 作为流程开关；本工程按同样思路接入，但不合并机型名称。

## 设计

KernelSU Flavor 保持五个：

```text
kernelsu / resukisu / next / sukisu / fina
```

SuSFS LKM 位于 Flavor 选择器下方，是独立可选开关：

```text
SUSFS
默认关 · 与 Flavor 独立，仅加载 guard LKM
```

默认关闭；可配合任意 Flavor 使用。

## 运行逻辑

MainActivity 在启动链路前写 marker：

```text
/data/local/tmp/magic/susfs
```

`run.sh` 读取：

```text
SUSFS_ENABLE=${MAGICROOT_SUSFS:-$(cat "$D/susfs" 2>/dev/null || echo 0)}
```

只有 `SUSFS_ENABLE=1` 才执行 `susfs_load()`，否则：

```text
SUSFS_LOAD=disabled reason=switch_off
```

## 加载

```text
susfs_insmod /data/local/tmp/magic/susfs_guard_lkm.ko
```

成功后：

```text
echo "add kernelsu" > /proc/susfs_hide_modules
echo "add_open_redirect /system/bin/su /dev/null 0" > /proc/susfs_open_redirect
```

## 上游做法参考

- SuSFS LKM guard 内置 assets；
- 由流程开关控制是否部署；
- `ksud insmod` 加载，失败回退 `insmod`；
- 日志 `SuSFS_LKM_LOADED` / `SuSFS_LKM_LOAD_FAIL`；
- 源码 vendored 在 `lkm/susfs4ksu-lkm`；
- 对上游机型内核的 BTI 兼容做了修改；
- 仅作为技术参考，不在本产品中合并机型名称。

## 资产与风险

- 当前 APK 使用 6.12 SuSFS LKM guard；6.6 资产在 `binary-sources/66118/susfs/`。
- SuSFS LKM 为 GPL-2.0 第三方 LKM，发布保留来源/许可。
- `open_redirect` 对 hisecd check-su 的覆盖仍需实机验证。
- 默认关闭，不会自动加载。
## SuSFS LKM 与软重启

SuSFS LKM guard 加载后，KSU 的 userspace soft reboot（ksud soft-reboot / ctl.restart zygote）会保留 LKM 的 hook，跨 framework 重启可能导致死机。
因此 soft_reboot_repair 在检测到 /sys/module/susfs_guard_lkm 或 /proc/susfs_path 时直接跳过：

`	ext
SOFT_REBOOT_REPAIR=skip reason=susfs_lkm_loaded full_reboot_required
`

需要模块加载时请完整重启，不要软重启。

## 从已安装管理器提取 KMI .ko

extractManagerLkm(flavor) 会扫描已安装管理器的 APK：

- 只接受 ELF 头 .ko；
- 优先名字包含 kernelsu/ksu、当前 KMI（如 6.12）的条目；
- 排除 susfs guard；
- 输出到 /data/local/tmp/magic/ko-<flavor>.ko；
- kernel_profiles.sh 的 per-flavor override 会优先使用该文件。

官方/Next/SukiSU 管理器当前 APK 若不含 .ko，日志为 MANAGER_LKM=none，仍使用内置模板。

