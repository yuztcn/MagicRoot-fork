# SuSFS LKM 下载恢复与临时加固绕过

日期：2026-10-29

## 下载恢复

- 恢复 GitHub release API：inforcqb/susfs4ksu-for-lkm（旧 susfs4ksu-lkm 会重定向）
- 按当前 release 的 ndroid<NN>-<major.minor>.ko 精确选择：
  - 6.12.58 -> susfs_guard_lkm-android16-6.12.ko
  - 6.6.118  -> susfs_guard_lkm-android15-6.6.ko
  - 6.18.21  -> susfs_guard_lkm-android17-6.18.ko
- 校验：大小、release digest（若有）、ELF、KMI、susfs_or_entry_expected_hook
- 保存到 app 私有目录，并尝试暂存 $WORK/susfs_guard_lkm.updated.ko
- UI：关于页“SuSFS LKM 在线更新”卡片

## 加固校验是否必须

不是数学上必须，但默认必须：

- 旧 guard 的 openat2/syscall-table 路径缺少 susfs_or_entry_expected_hook 时会崩溃；
- 因此下载和加载都默认拒绝无标记模块。

## 临时禁用

UI 开关（默认关闭）：

`	ext
临时允许未加固 guard
`

同时支持：

`	ext
MAGICROOT_SUSFS_ALLOW_UNHARDENED=1
/data/local/tmp/magic/susfs_allow_unhardened
`

绕过范围：

- 下载校验的 hardening 检查；
- susfs_load 的 hardening 检查。

仍然强制：

- ELF；
- 文件大小；
- vermagic 的 KMI 必须匹配；
- susfs_load 的精确 vermagic 检查。

风险：可能直接 kernel panic/重启；仅用于对比/回收旧模块。

## 实测

- 设备 6.12.58，点击“检查并更新 SuSFS LKM”；
- 请求已发出，设备到 GitHub API 网络超时：
  `	ext
  SuSFS LKM 更新失败: java.net.SocketTimeoutException: timeout
  `
- 因此下载代码恢复，但当前网络环境未完成一次成功下载。

## 构建

见发布 APK；没有重建 6.6.118 测试包。
