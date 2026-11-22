# 98260 fake/real 双分支 late-load 与软重启防护

日期：2026-11-09。状态：本地候选，未合入，未做双分支真机验证。

## 1. 目标与边界

- 模块只在系统已完成启动后加载，不抢开机/zygote 时间窗。
- 不 chmod、不重命名、不编辑 `/data/system/packages.list`，不修改
  PackageManager 数据。
- ksud 与 LKM 必须来自当前选中的同一个管理器 APK；禁止内置模板、其他版本
  管理器或不配套组件回退。
- 保持一次性临时 root，不写分区、不做持久化。

## 2. 两条实际链路

### fake-cred

1. `--no-real-cred` 进入恢复后的 fake-cred 主分支；此前该参数虽被解析，主流程
   却仍错误地进入 real-cred。
2. 使用原有 task->cred 安装、`CRED + SELINUX + NONE` tile 和 rootd 交付；
   runner 显式传 `PC98260_ROOTD=1`，确保子进程是 mintwait-rootd 而不是普通 shell。
3. rootd 直接调用当前管理器的
   `ksud late-load --kmi <KMI> --package-name <pkg> [--allow-shell]`，不先执行
   外部模板的 ko_patch。
4. 管理器从自己的 ksud 资产加载匹配 LKM，并完成 late-load 用户态与管理器识别。

**ko_patch 必要性复核**：fake 分支在 `KSU_ENABLE=1` 且模块未加载时直接进入上述
manager late-load，分支内没有 `KOPATCH_BIN`，也不读取 `ksu-patched.ko`。
SukiSU 4.3.0-r2 `userspace/ksud/src/late_load.rs` 的已加载检查、内嵌资产读取和
`ksuinit::load_module()` 分别位于 49–51、60–63、85–86 行。因此 fake 不需要
ko_patch；real direct-finit 使用外部管理器 LKM，仍需 ko_patch 完成当前内核符号
重定位。回归 `test_fake_cred_branch_is_reachable_and_separate` 已锁定该差异。

### real-cred

1. 保持真实 cred 原位 uid/gid 清零，uid/SELinux 阶段不携带 cap tile。
2. 独立 PLANT_PTR cap pass 验证 bit16，失败时禁止 finit。
3. mintwait 进程内 direct-finit 加载当前管理器提取并经 ko_patch 的 LKM；不能用
   exec 代替，因为本机 CapBnd 不含 CAP_SYS_MODULE。
4. KSU su 可用后，调用**同一管理器**的 ksud late-load。SukiSU 4.3.0-r2 源码在
   `has_kernelsu()` 为真时跳过内嵌 KO 加载，只执行用户态安装、sepolicy、
   late-load/service 阶段与管理器重启。

## 3. no_preinit / no_custom_rc

SukiSU 4.3.0-r2 的 boot-patch 配置把 `no_custom_rc` 写成 `norc=1`，把
`no_preinit` 写成 `preinit=0`。其 late-load 实现本身不会执行 boot-time
preinit/custom-rc。

- fake：使用管理器 late-load，因此天然不进入这两个 boot-time 阶段。
- real：direct-finit 前检查修补后的当前 LKM 是否实际导出 `parm=norc` 和
  `parm=preinit`，分别附加 `norc=1`、`preinit=0`；不支持的 backend 不盲加，
  避免 unknown-param EINVAL。

## 4. 管理器配对与 packages.list

App 和 runner 都在 UAF 前检查管理器 ksud/LKM 同时存在；缺一即
`FAIL=manager_pair_missing` / `FAIL=98260_manager_pair_missing`。双分支禁止
custom-KO 与 manager-pair 混用，也不允许 ko_patch 失败后回退内置模板。

`register_manager_98260()` 已由 packages.list 权限窗口、rename 触发和手工
动态管理器写盘改为同管理器 late-load。`root_stage.sh` 中同类 chmod/mv 也已删除。

## 5. rc17 软重启 panic 的证据与修复

23:25 的 rc17 成功日志（payload `32b44727…`）明确包含：

- uid0、独立 cap 第 2 次成功、`finit_module rc=0`、KSU/SukiSU 闭环；
- 但 victim 汇总为 `total=6 reaped=3 unproven=3`，随后 cap 又新增 victim；
- 同时 `SOFT_REBOOT_GUARD=arm_failed`；
- 软重启后 `sys.resettype=abnormal:AP_S_PANIC`。

所以此次不是“零残留仍 panic”，而是**存在未证明 armed victim 且 guard 未生效**。
修复：

1. lock 目录创建和读回都通过已验证的 root provider，避免外层 uid 2000 因
   `/data/adb` 不可搜索而误报 arm_failed。
2. unproven marker 写入后 fsync 文件及 `/data/local/tmp` 目录，避免软重启后只剩
   同长度 NUL 内容。
3. marker 无效但 plant 仍存活时，LSPosed hotfix fail-closed，不再删除唯一 guard。
4. runner 输出 `98260_SOFT_REBOOT_SAFE=0 unproven=N`，明确禁止管理器软重启。
5. App 成功页同步显示“提权完成 · 禁止软重启”并给出高优先级反馈，不再把
   `DONE` 等同于可安全软重启。

lock 目录只对实现该锁约定的管理器有效；外部 CLI 或不支持它的管理器不能据此
宣称软重启已安全。只有 victim 汇总无未证明项且管理器实际遵守 guard 时，才可
继续做单独真机验证。

## 6. 构建与验证

- 九份 6.12 payload 使用本机 clang 21.1.8 动态 PIE 重建；6.6 不在本轮重编。
- Gradle 属性 `-PmagicrootCredMode=real|fake` 选择新安装的默认分支；UI 的
  `real_cred` 开关仍可显式切换并持久化。
- 两个包共用相同双模式 payload，但默认分支不同，不是仅改文件名。
- 本地生命周期新增 fake 可达性、管理器配对、packages.list 零修改、late-load、
  root 侧 soft-reboot guard 与 marker fsync 回归。
- 真机：real/fake 新链路均未验证；rc17 的软重启 panic 只用于证明旧 guard 失败。

候选包（均为 61,205,489 B，versionCode 12 / versionName 1.0.5，V3 证书不变）：

- real 默认：`/sdcard/cccodroid/MagicRoot-real-cred.apk`，SHA-256
  `cc3cdc6e6b562bb5b2ecc346677e6a869d64e195856496cd2547c048b3647109`
- fake 默认：`/sdcard/cccodroid/MagicRoot-fake-cred.apk`，SHA-256
  `ef4ce60eeb7a1d13ca2884f4ce20a6e9c28ce4f28854519de17c086f94d485a5`

两包 286 项 assets 逐字节一致，6.12.58 payload 均为 `480106fe…d682e`；合并 DEX
hash 分别为 `ff9f4669…63b16` / `f6b6005c…a773`，证明构建默认分支确实不同。

最终 `bash tools/check.sh` 输出 `ALL CHECKS PASSED`：46 项生命周期、11 项 H1C、
65 shell、35 profile hash、327 资产注册/APK 对账、41 dedup 及其余完整本地测试
均通过。该结果不是双分支真机安全证明。
