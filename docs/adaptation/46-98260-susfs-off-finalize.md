# 98260 未启用 SuSFS 时 98% 停滞：根因与收尾修复

日期：2026-11-04

## 1. 现象

用户提供的 6.12.58 真机截图显示，98260 链路已经完成：

```text
CHAIN_98260_RC=0
CHAIN_98260_DONE
SuSFS_LKM_LOAD=disabled reason=switch_off
SOFT_REBOOT_REPAIR=disabled reason=use_explicit_zygote_hotfix
```

但界面停在：

```text
98% · 运行中
SuSFS 模块加载（可能较慢）
02:07
正在提权...
```

日志里没有 `DONE`。也就是说，KernelSU 已经加载、`su` 已经可用，卡住的是
成功后的可选 SuSFS 与收尾阶段，不是提权链路本身。

## 2. 根因

### 2.1 UI 把所有 SuSFS 行都当成“模块加载”

旧版 `MainActivity.updateProgressFromLine()` 的判断是：

```java
} else if (line.startsWith("SuSFS_")) {
    if (runProgressValue >= 90) {
        progress = 98;
        stage = "SuSFS 模块加载（可能较慢）";
    }
}
```

`run.sh` 在链路开始时输出 `SuSFS_SWITCH=`，在链路结束时输出
`SuSFS_LKM_LOAD=disabled`。只要进度已经到 90% 以上，后者也会被归为
“模块加载”，即使它明确表示 `disabled reason=switch_off`。于是 UI 把
“马上跳过 SuSFS”错误显示成“正在加载 SuSFS”，并一直保留到 `DONE`。

### 2.2 收尾阶段没有可见标记，且超时可能失效

`CHAIN_98260_DONE` 之后，旧流程直接依次执行：

```text
susfs_load
soft_reboot_repair
cleanup_98260_rootd_listener
cleanup_stale_98260_rootd
DONE
```

SuSFS 关闭时 `susfs_load` 立即返回，`soft_reboot_repair` 也立即返回，
真正的耗时只剩 rootd listener 清理和 socket 清理。但这一段：

- 没有 begin/end 标记，界面只能沿用上一行的“SuSFS 模块加载”；
- `cleanup_98260_rootd_listener` 需要 root helper 扫描 `/proc/<pid>/fd`，
  在系统繁忙或 SELinux 拒绝时可能很慢；
- 若干 `su` 调用只用了 `timeout`，没有 `-k`。Toybox `timeout` 在发送
  SIGTERM 后会一直等待；如果 `su` 或子进程忽略 SIGTERM，脚本就永远不会
  走到 `DONE`。

因此截图中的 98% 有两个叠加原因：**标签错误**让收尾看起来像 SuSFS
加载，**收尾不可见且没有强杀兜底**让这个标签一直停留。

## 3. 影响范围

| 链路 | 是否调用 `susfs_load` | 是否共享旧收尾 | 结论 |
|---|---|---|---|
| 6.12.x `run98260.sh` | 是 | 是 | 受影响，已修复 |
| 6.6.x `run98260.sh` | 是 | 是 | 受影响，已修复 |
| 6.18.21 H1C | 是 | 是 | 受影响，已修复 |
| 6.1.x `run6157_full.sh` | 是 | 是 | 受影响，已修复 |
| 6.1.157 g19a `run61157.sh` | 否 | 只共享 rootd 清理 | 无 SuSFS 误标，但收尾不可见/可能挂起；已补标记与超时 |
| 64560 历史链路 | 尾部调用 `susfs_load` | 使用 `cleanup_stale_98260_rootd` | 不在本次 98260 修改范围；仅同步获得 `timeout -k` 兜底 |

`CHAIN_98260_DONE_ROOTD_ONLY`、preflight 和失败分支没有改动。

## 4. 修复

### 4.1 提取纯 Java 分类器

新增：

```text
main/compose-app/app/src/main/java/com/aoki/magicroot/RunProgress.java
```

它不含 Android 依赖，`MainActivity.updateProgressFromLine()` 只负责把
`RunProgress.Step` 应用到 `UiState`。SuSFS 行现在按真实语义分类：

```text
SuSFS_LKM_TRY=...              -> SuSFS 模块加载（可能较慢）
SuSFS_LKM_LOAD_RC=...          -> SuSFS 模块加载（可能较慢）
SuSFS_LKM_VERIFIED=...         -> SuSFS 模块加载（可能较慢）
SuSFS_LKM_LOADED=1             -> SuSFS 模块加载（可能较慢）
SuSFS_LKM_LOADED=0             -> SuSFS 未加载，继续收尾
SuSFS_LKM_LOAD=already_loaded  -> SuSFS 已加载，收尾清理
SuSFS_LKM_LOAD=disabled/skip   -> SuSFS 未加载，收尾清理
```

同时新增：

```text
98260_FINALIZE_BEGIN           -> 98260：收尾清理（有超时保护）
98260_FINALIZE_END             -> 98260：收尾完成
98260_ROOTD_CLEANUP=...        -> 98260：rootd 收尾清理
```

`DONE` 仍是唯一的 100% 转换。早期 `SuSFS_SWITCH=` 仍被忽略，进度不会
从 8% 跳到 98%。

### 4.2 统一 98260 成功收尾

`run.sh` 新增共享函数：

```sh
finalize_98260() {
    _fz_load_susfs=${1:-1}
    echo "98260_FINALIZE_BEGIN susfs=${SUSFS_ENABLE:-0} load=${_fz_load_susfs} rootd_keep=${MAGICROOT_KEEP_ROOTD:-0}"
    if [ "$_fz_load_susfs" = "1" ]; then
        susfs_load
        soft_reboot_repair
    fi
    cleanup_98260_rootd_listener
    cleanup_stale_98260_rootd
    echo "98260_FINALIZE_END"
}
```

所有 98260 成功分支改为：

```text
CHAIN_98260_DONE
finalize_98260
DONE
```

g19a/61157 分支不加载 SuSFS，因此只打印
`98260_FINALIZE_BEGIN susfs=0 load=0` 并执行原有 listener 清理，不新增
SuSFS 行为。

### 4.3 收尾命令加硬超时

以下调用都从 `timeout` 改为 `timeout -k`：

| 调用 | 超时 |
|---|---|
| rootd listener helper | `-k 5`，默认 15 秒 |
| 旧 rootd socket 删除 | `-k 2`，10 秒 |
| su 可用性探测 | `-k 2`，默认 10 秒 |
| 候选 su 探测 | `-k 2`，5 秒 |
| SuSFS insmod | `-k 10`，默认 180 秒 |
| SuSFS hide 写入 | `-k 3`，默认 15 秒 |

超时只表示“这次没清理成功”，不会 kill PPID=1 的 exploit 父进程。
listener 留在原地是安全的，父进程必须保留到重启。

## 5. 修复后的日志形态

SuSFS 关闭时：

```text
CHAIN_98260_RC=0
CHAIN_98260_DONE
98260_FINALIZE_BEGIN susfs=0 load=1 rootd_keep=0
SuSFS_LKM_LOAD=disabled reason=switch_off
SOFT_REBOOT_REPAIR=disabled reason=use_explicit_zygote_hotfix
98260_ROOTD_CLEANUP=...
RUNSH_...
98260_FINALIZE_END
DONE
```

界面会依次显示“链路完成，收尾中” → “收尾清理（有超时保护）” →
“rootd 收尾清理” → “收尾完成” → 100%。

SuSFS 开启时，`SuSFS_LKM_TRY` 等行仍显示“SuSFS 模块加载（可能较慢）”，
这是真实加载阶段，不应被去掉。

## 6. 验证

已执行：

```bash
python3 -I tools/test_98260_finalize.py
bash -n main/app/assets/run.sh
bash -n main/app/assets/98260/run98260.sh
bash -n main/app/assets/98260/run6157_full.sh
bash -n main/app/assets/98260-h1c/run_h1c.sh
bash -n main/app/assets/61157/run61157.sh
python3 -I tools/audit_6157_chain.py
python3 -I tools/test_h1c_flow.py
bash tools/audit_kernel_flavors.sh
```

`tools/test_98260_finalize.py` 包含：

- 用普通 `javac` 编译生产 `RunProgress.java` 并运行分类器测试；
- 静态检查每个 `CHAIN_98260_DONE` 分支都调用 `finalize_98260`；
- 静态检查两个 rootd 清理函数里的 `su` 调用都带 `timeout -k`；
- 把 `finalize_98260` 抽到临时 shell harness，验证默认路径会调用
  SuSFS 与两个清理函数，`finalize_98260 0` 只跳过 SuSFS、仍执行清理。

APK 构建并签名成功（v3，`com.aoki.magicroot` / 12 / 1.0.5）：

```text
main/app/MagicRoot.apk
87,450,045 bytes
SHA-256 64f1633195748bc2b537fc552b20c4124bd018cee6c72fa46426d64aed664c19
```

包内 `assets/run.sh` 与工作树 SHA-256 一致，DEX 已包含新的
“收尾清理（有超时保护）”和“SuSFS 未加载，收尾清理”文案。

本轮**没有**安装 APK、没有部署资产、没有执行 UAF/rootd/LKM/重启。
6.12.58 的提权与收尾修复仍需下一次真机运行时按第 5 节日志确认。
6.6 / 6.18.21 / 除 g264、g7d 外的 6.1.x 仍属于静态适配，不能表述为
已端到端验证。

## 7. 风险与边界

- 修复不改变 UAF、KSU 加载、su 提供者或 profile 选择。
- 不 kill exploit 父进程；清理失败时保持 listener 存活。
- `-k` 只影响收尾辅助进程，不会向 PPID=1 父进程发信号。
- 不改变 `versionCode 12` / `versionName 1.0.5` / 包名 / 签名配置。
- 64560 历史链路没有新增 finalize 标记，只获得同一套超时兜底。
