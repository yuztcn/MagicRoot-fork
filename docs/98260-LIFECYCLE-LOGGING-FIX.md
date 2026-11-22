# 98260 日志、native 终态与 hotfix 修复

日期：2026-11-07

## 范围

本轮只处理审计建议的第 1、2、4、5 项：

1. 每轮完整 native 日志、run ID、boot ID、payload SHA-256。
2. proof/native 终态同步、收尸错误处理、rootd 复用和 pre-arm parked。
4. Zygisk Next `/data/adb/zygisksu` 状态目录与 daemon 状态检查。
5. `--no-real-cred` 与最终 UID/GID proof 的一致契约。

**第 3 项 late-load KO 选择暂不修改。** 当前 `61821brm-kernelsu` 条件及其重复
`elif` 保持原样；相关 `__queue_work` WARNING 仍需另行处理。

新补充的 6.18.21 日志（`fail_log_1794072143401.txt`）是另一条未解决路径：当前轮
H1C 在 `ko_patch` 以 `PATCHED=245 MISSING=6` / rc=82 退出。尾部旧 plant 日志中的
rootd 成功不属于当前轮。本轮不修复这 6 个缺符号。

## 日志归属

### 6.6 / 6.12 native

`98260/run98260.sh` 只在所有复用/parked 检查通过、真正允许启动 native 后重置
`/data/local/tmp/magic/98260.log`，因此 guard-only 运行不会清除上一轮证据，也不会把旧
日志伪装成本轮。

每轮写入：

```text
98260_RUN_ID=<date>-<shell-pid>
98260_BOOT_ID=<boot-id>
98260_PAYLOAD_SHA256=<sha256>
98260_LOG=/data/local/tmp/magic/98260.log
```

`run.log` 仍只附加 native 尾部 80 行，用于现有 UI/进度路径。Compose 的成功、失败和
stale 日志导出会在当前 `run.log`（或 `run.log.exported`）存在对应 `98260_LOG` 标记时，
追加完整 `98260.log`。没有该标记的 guard-only 运行不附旧 native 日志。

### 6.18 H1C

`98260-h1c/run_h1c.sh` 把 live-plant 检查放在诊断文件清理之前。只有允许开始新运行时才
重置：

```text
98260-h1c.log
98260-h1c-ko-patch.log
98260-h1c-plant.log
98260-h1c-root-stage.log
```

H1C 主日志通过 `h1c_log` 同步记录同一个 run/boot ID 和 `cve98260_plant` SHA-256。任一诊断
文件无法重置都会以 `diagnostic_log_reset` 退出且不写本轮 `H1C_BEGIN`。Compose 仅在当前元日志有
`98260_H1C_BEGIN` 时附加这些文件，避免 ko_patch 早退带出历史 rootd 成功。

## native 终态与 parked 契约

native 通过每轮独立的 `PC98260_STATE_FILE=/data/local/tmp/magic/98260-<run-id>.state` 写入。
状态通过同目录临时文件 + 原子 `rename` 更新，不会给外层暴露半行；若首次 `ARMED` 无法
持久化，native 在 `arm_ready` 前拒绝 UAF 并清理 pre-arm child。每轮独立路径也避免旧
`NO_ROOT`/`ARMED` 被下一轮消费。

- `ARMED`：`victim_reg()` 注册 armed victim 时；只有看到此状态，外层才允许写 parked
  marker。
- `NO_ROOT`：最终 sweep/summary 后仍无 root、即将永久 watch，或 `wait_zombie` 的
  超时/错误导致永久 watch；外层立即以 `native_no_root_terminal` 失败，不再空等 socket。

外层 proof 默认兜底等待为 720 秒（`MAGICROOT_98260_PROOF_WAIT_S` 可覆盖）。兜底到期时
明确输出：

```text
98260_NATIVE_STILL_RUNNING=1
FAIL=proof native_not_terminal_after_720s ...
```

它不再把该情况称为 `no_rootd_socket_after_240s`，也不声称 native 已到终态。

slide、task leak 或 selftest 在首次 arm 前退出时，输出 `98260_PRE_ARM_EXIT=1`，不写
parked marker。`parked_mark()` 现在只有写入并 chmod 成功才输出 `98260_PARKED=1`，否则
输出 `98260_PARKED_WRITE_FAILED=1`。跨 boot 旧 marker 删除失败会 fail closed。

## 收尸错误处理

- `wait_zombie()` 的超时（0）和 `waitid` 错误（-1）都进入 `UNPROVEN` + watch；不会
  落入阻塞 `waitpid`。
- `victim_reap()` 对 EINTR 重试；只有 `waitpid` 确实返回目标 PID 才写
  `REPAIRED/reaped_after_proven`。其它结果写 `UNPROVEN/reap_waitpid_failed`，保留在
  unproven marker 和 zygote guard 中。

这些修改不能消除 foreign-owned armed zombie 的已知残余风险，也不能替代真机 panic
验证。

## rootd 复用与 proof

共享 runner 先验证并复用可用 rootd/KSU，再执行 parked/new-plant 拒绝。旧的全局
`pidof` 不再让后面的 `98260_SUCCESS=1 reused=1` 成为不可达代码。无可用 socket 的 live
plant 仍拒绝启动第二个 UAF；H1C 的同类 guard 保留。

`--no-real-cred` 模式不新增 real_cred UAF。proof 要求：

- `id -u` / `id -g` 为 0；
- `Uid:` / `Gid:` 的 effective、saved、fs 字段为 0；
- real 字段只记录，不要求为 0。

完整 real-cred 模式仍要求四个 UID/GID 字段全部为 0。日志分别输出
`98260_PROOF_MODE=no-real-cred` 或 `real-cred`。复用与新 rootd 使用同一验收函数。

## Zygisk Next 状态目录

`lsposed-hotfix.sh` 在 `ksud post-fs-data` 前检查模块是否存在；若
`/data/adb/zygisksu` 缺失，只创建该父目录，不删除 `.magic`、`.abort_msg` 或其它模块状态。
目录不可写时明确输出 `ZYGISK_STATE=error`。

已有 daemon 且 `.magic` 存在时不重复启动。daemon 判定读取 PID/STAT/NAME 和 cmdline，
排除僵尸及 `service-stage` 短时进程；最终判定前重新读取 magic。否则沿用原
daemon/service-stage 路径，并记录 PID 与 magic 状态。模块已安装但最终 daemon/magic 不完整时，
修复结果为 `partial`，不再只凭 LSPosed bridge 报完整成功。LSPosed 的独立修复仍继续执行。

## 验证边界

- 所有改动 Shell 必须通过 `bash -n`。
- `tools/test_98260_uaf_lifecycle.py` 包含静态负路径和真实 shell proof 用例。
- `tools/test_h1c_flow.py` 保留普通用户态 H1C harness，并检查 guard 先于日志清理。
- 12 个有完整源码/target header 的 payload 已用 Termux clang 动态 PIE 配方重建；hash 见
  `BINARY-SOURCES.md`。来源锁定的 6.1、f171/g554 与 H1C native 二进制未改。
- **未执行真机 98260 UAF、KSU 加载、zygote 重启或 soft-reboot。** 静态门禁和普通用户态
  harness 通过不等于真机闭环。

## 构建与门禁结果

- `tools/check.sh`：`ALL CHECKS PASSED`；325 个 APK 资产与磁盘逐字节一致，包含所有
  Java/Flavor/6.1/生命周期/H1C/清理/su_entry 检查。
- Release APK 保持 `com.aoki.magicroot`、versionCode 12、versionName 1.0.5，签名验证通过。
- 输出：`/sdcard/cccodroid/MagicRoot-1.0.5-lifecycle-fix.apk`
- 大小：61,893,588 B
- SHA-256：`11f79d798e7b5dc8d69bf6b8092745840edd8278ac37b316400b9625e33a6dc8`

该 APK 证明源码与资产可构建、静态契约通过；不证明 98260 提权或 hotfix 已在真机成功。

## Zygisk Next 2026-11-08 修复补充

现场模块 1.5.3 安装后缺少 `sepolicy.rule`，`zygiskd` 启动时 `verify1`
失败并自我禁用（`disable` + 改写 `module.prop`），后续启动读取 abort
状态直接退出。初版修复曾按版本和 SHA-256 补回官方 1.5.3 规则，并借此完成
`inject_state=1`、`zygote_states=1`、LSPosed connected 的真机验证。

**后续修订：该真机结果仅属于初版主动补全方案。当前 v12 已移除内置规则资产、
App 释放/传参和 hotfix 复制恢复分支，不再代替模块修改 SELinux 策略。**
当前 `lsposed-hotfix.sh`：

- 用 `ksud zygisk status` 的 `external_providers` 判断 provider，
  只对 `zygisksu` 执行专属修复；KSU 内置 FolkZygisk、YukiZygisk 等
  其他 provider 不触碰；
- 只接受模块目录原本存在的 `sepolicy.rule`；缺失时记录
  `ZYGISK_SEPOLICY=missing reason=module_rule_required` 并拒绝启动
  `zygiskd`，不补全、不恢复、不重新启用缺规则的模块；
- 仅在模块自身规则存在时，检测自我禁用状态并恢复 `module.prop`、删除
  `disable`、备份并清理 abort/magic/injecting；
- 识别 1.5.x “daemon attach init 后退出” 的正常终态，不再重复启动。
