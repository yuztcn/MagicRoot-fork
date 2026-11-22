# SUSFS LKM 适配说明

## 预编译 LKM

来源：<https://github.com/inforcqb/susfs4ksu-lkm> release `v2.3.0-r18.4`。
目标资产：`susfs_guard_lkm-android16-6.12.ko`，加载器 `susfs_insmod`。

设备实测（Honor 6.12.58，rootd system_server）：

```text
susfs_insmod: undefined symbols: 110
resolved 110/110; unresolved 0
init_module(...); loaded
OK: /sys/module/susfs_guard_lkm exists
```

`/proc/susfs_*` 节点出现：

```text
/proc/susfs_path
/proc/susfs_open_redirect
/proc/susfs_kstat
/proc/susfs_hide_modules
/proc/susfs_hide_mounts
/proc/susfs_avc_spoof
/proc/susfs_enable_log
/proc/susfs_opath
```

说明预编译 SUSFS LKM 能在 Honor 6.12.58 上加载，属于可用的运行时隐藏基建。

## 已集成

- APK assets：`susfs_guard_lkm.ko`、`susfs_insmod`。
- `run.sh susfs_load()`：在 root 可用后通过 `su` 或 rootd 调用 `susfs_insmod`，成功后执行
  `echo "add kernelsu" > /proc/susfs_hide_modules`。
- 64560 收尾与 98260 成功路径都会尝试加载；失败非致命。
- About 页增加 SUSFS4KSU-LKM；No-World/rootkit 仅作为 64560 链路优化参考。

## 接口要点

- `sus_path` 默认 `hide_from_apps=1`：只对 app 进程隐藏；`hide_from_apps=0` 对所有进程隐藏。
- `open_redirect` 的 `uid_scheme=0` 只对非 app 进程（uid%100000<10000）生效。
- `susfs_hide_modules` 可隐藏 `/proc/modules` 行（包括 root）。
- 需要隐藏 `/system/bin/su` 时，必须组合 `sus_path`/`open_redirect` 并实测 hisecd 的
  stat/access 路径，不能只靠路径改名。

## 风险

- SUSFS 为 GPL-2.0 第三方 LKM，源码/release 需保留对应许可与来源。
- 与 KSU 重新加载的时序、`/proc/susfs_*` 可见性目前仍可能变化，需上机重测。
- 不改系统分区，不刷 boot；模块随开机加载。
