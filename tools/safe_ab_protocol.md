# P0 安全模式 A/B 设备验证协议（safe-baseline vs early-abort 4500ms）

本协议定义 P0 实验在**真机**上的执行方式：用同一个实验 APK，交替跑
`safe-baseline`（safe 模式 + `T64560_EARLY_ABORT_MS=0`）和
`p0-early`（safe 模式 + early abort 4500ms），并导出可离线解析的日志。
全程默认**不推送、不执行**；只有操作者手工执行第 5 节命令或给
`run_safe_ab.ps1` 显式加 `-Execute` 才会碰设备。

配套工具（本目录，全部离线）：

```text
release/tools/parse_safe_ab.py        # 日志解析 + JSON/Markdown/CSV + A/B 验收判定
release/tools/run_safe_ab.ps1         # 安全 adb 命令生成器（默认 dry-run，可选执行）
release/tools/safe_ab_protocol.md     # 本文件
release/publish/experiments/p0-ab/    # 新增实验目录（sessions / fixtures / README）
```

---

## 1. 实验臂与变量

| 项 | safe-baseline（B） | p0-early（P） |
|---|---|---|
| APK | 同一个实验 APK | 同一个实验 APK |
| `safe-mode` 标志文件 | 存在 | 存在 |
| `early-abort-ms` 内容 | `0`（显式关闭 early abort） | `4500` |
| `ab-export` 标志文件 | 存在 | 存在 |
| run.sh 环境（safe 模式） | `T64560_SAFE=1`、`MIN_DRAIN_MS=500`、`DRAIN_MAX_MS=8000`、`DRAIN_SLACK=64` | 同上，另 `T64560_EARLY_ABORT_MS=4500`，`STALL=1000`、`MARGIN=4` |
| 目的 | 安全模式自身基线（能产生 SAFE_ABORT） | 验证 early abort 把长 drain 截短 |

- **两臂必须同 APK、同设备、同内核、同 victim/attempts 参数**，唯一差异是
  `early-abort-ms` 文件内容。
- 生产旧链路（`SAFE_MODE=0`）不是本 P0 A/B 的对照组；`parse_safe_ab.py`
  仍可解析这种日志（模式记为 `production`），但默认验收对比只在
  `safe-baseline` 与 `p0-early` 之间进行。
- 每个 run 都必须**冷启动**（见 4.2）：成功后 KernelSU 模块会在当前 boot 里
  Live，下一次 run 会走 `MODULE_ALREADY_LIVE` 快速修复路径，没有 exploit
  attempt，**不是有效样本**。

---

## 2. 前提条件与设备准备

### 2.1 实验 APK（必须由构建方提供）

实验 APK 必须同时包含：

1. `assets/t64560_v36_safe`、`assets/t64560_cred_safe`（P0 safe 二进制）；
2. safe 版 `assets/run.sh`：启动时打印
   `SAFE_MODE=... EARLY_ABORT_MS=... AB_EXPORT=...`，按 `safe-mode` 标志选择
   safe 二进制并注入 `T64560_SAFE/MIN_DRAIN_MS/DRAIN_MAX_MS/DRAIN_SLACK`；
3. `MainActivity.ASSETS` 包含 `t64560_v36_safe` / `t64560_cred_safe`，否则
   「部署资产」不会把 safe 二进制放到设备上；
4. `ab-export` 支持：run.sh 在 `DONE` 后把 `/data/local/tmp/magic/run.log`
   复制到 `/sdcard/Download/MagicRoot-ab/run-<epoch>-<pid>.log`。

安装前离线核对 APK（任选其一）：

```powershell
# 记录 SHA256 和版本，写入 session 的 manifest
Get-FileHash <实验APK> -Algorithm SHA256
# 可选：确认 APK 资产存在（zip 列表）
python -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); print([n for n in z.namelist() if 'safe' in n])" <实验APK>
```

安装/替换：

```text
adb install -r <实验APK>
adb shell pm path com.aoki.magicroot
```

> 若 `pm path` 返回多路径或旧包残留，先手动卸载旧包再安装，避免读到旧资产。
> 关闭应用商店自动更新，避免 A/B 中途 APK 被替换。

### 2.2 设备状态

- 同一台设备、同一内核（`adb shell uname -r` 与 6.12 profile 一致），
  USB 调试授权已允许；
- 电量 ≥ 50% 或接电源，关闭自动锁屏/省电限制，保持屏幕常亮；
- Stellar / Shizuku 可用并已授权（App 内「1. 授权」按钮状态正常）；
- 冷启动后 SELinux 应为 `Enforcing`；
- `/data/local/tmp/magic` 可写、`/sdcard/Download` 可写。

只读检查命令（均不含 shell 元字符）：

```text
adb devices
adb shell getprop sys.boot_completed
adb shell getprop ro.build.version.release
adb shell uname -r
adb shell getenforce
adb shell pm path com.aoki.magicroot
adb shell grep kernelsu /proc/modules
```

- 最后一条 **无输出/返回非零** 表示冷启动后 KernelSU 未加载，可以开跑；
  若有 `kernelsu ... Live`，本次 boot 必须放弃并重启。
- `getenforce` 在开跑前应为 `Enforcing`；若已是 `Permissive`，说明该 boot
  不干净，重启后再来。

### 2.3 App 内设置（每个 APK 安装后确认一次）

1. 打开 MagicRoot，完成「1. 授权 Stellar / Shizuku」；
2. victim 档位：SELinux **32**、fsuid **32**、cred **24**
   （UI 首次安装默认 cred=16，必须点到 24；三档会持久化，换 APK 后重查）；
3. 「可选：跳过 fsuid/fsgid」= 关；
4. 「可选：su_compat + su 搜索入口」= 关；
5. 打开日志面板，确认能显示新日志（部署/运行按钮可点）。

---

## 3. 设备上的标志文件语义

工作目录固定为 `/data/local/tmp/magic`（App 部署资产时创建）。

| 文件 | 写入方式 | run.sh 语义 |
|---|---|---|
| `safe-mode` | 存在即生效，内容任意 | `SAFE_MODE=1`：选 `t64560_v36_safe` / `t64560_cred_safe`，注入 safe 参数；缺失时走生产二进制 |
| `early-abort-ms` | 纯数字文本（`0` / `4500` / …） | 仅 safe 模式读取；缺文件默认 4500；`0` = 显式禁用 early abort；非数字回退 4500；上限 60000 |
| `ab-export` | 存在即生效，内容任意 | run.sh 正常结束前把 `run.log` 复制到 `/sdcard/Download/MagicRoot-ab/` |

约定：

- **只用 `adb push` 写标志文件**，禁止 `adb shell 'echo 1 > ...'` 之类的
  重定向/管道写法（本协议与 `run_safe_ab.ps1` 都不生成这种命令）；
- 标志文件在运行成功后随工作目录一起被清理（App 清理
  `/data/local/tmp/magic`），所以**每次 run 前都要重新推一次**；
- 失败/中断时工作目录保留，但下一次点「3. 开始提权」会先 `rm run.log`，
  因此**必须在下次运行前导出日志**；
- 本 A/B 两臂都保留 `safe-mode`、`ab-export`，只切换 `early-abort-ms`
  内容（B=`0`，P=`4500`）。

本地暂存 + 推送示例（PowerShell，先创建三个小文件再 push）：

```powershell
$stage = Join-Path $env:TEMP 'magicroot-ab-flags'
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Set-Content -Path (Join-Path $stage 'safe-mode')      -Value '1'    -NoNewline -Encoding ascii
Set-Content -Path (Join-Path $stage 'ab-export')      -Value '1'    -NoNewline -Encoding ascii
# B 臂: '0'    P 臂: '4500'
Set-Content -Path (Join-Path $stage 'early-abort-ms') -Value '0'    -NoNewline -Encoding ascii

adb push (Join-Path $stage 'safe-mode')      /data/local/tmp/magic/safe-mode
adb push (Join-Path $stage 'early-abort-ms') /data/local/tmp/magic/early-abort-ms
adb push (Join-Path $stage 'ab-export')      /data/local/tmp/magic/ab-export

# 校验（应列出三个文件，early-abort-ms 内容为 0 或 4500）
adb shell ls -l /data/local/tmp/magic/safe-mode /data/local/tmp/magic/early-abort-ms /data/local/tmp/magic/ab-export
adb shell cat /data/local/tmp/magic/early-abort-ms
```

> `run_safe_ab.ps1 -Mode Prepare` 会自动完成上述暂存/推送/校验，并打印命令；
> 默认 dry-run，只有加 `-Execute` 才真正执行。

---

## 4. 单个 run 的标准流程（B/P 交替）

### 4.0 场次与命名

建议每次 P0 场次 ≥ 3 个配对（推荐 3~5 对），交替执行：

```text
B01 → P01 → B02 → P02 → B03 → P03 ...
```

同一个 session 根目录：

```text
release/publish/experiments/p0-ab/sessions/p0-ab-YYYYMMDD/
  manifest.md                      # 场次信息：设备/内核/APK sha256/顺序
  B01-safe-baseline/
    run.log                        # 导出的日志
    run.meta.json                  # 解析器读取的 sidecar（见 4.6）
  P01-p0-early-4500/
    run.log
    run.meta.json
  ...
```

`fixtures/` 下是离线自测用的**合成日志**，不是真机结果，分析时不要混入
`sessions/`。

### 4.1 顺序（每个 run 重复 4.2~4.6）

1. 冷启动设备（人工重启；见 4.2）；
2. 打开 App，完成授权检查，确认 victim 档位 32/32/24；
3. 点「2. 部署资产」，等到日志出现「部署完成」；
   确认 safe 二进制已就位：`adb shell ls -l /data/local/tmp/magic/t64560_v36_safe /data/local/tmp/magic/t64560_cred_safe`
4. 推标志文件（B 或 P 的 `early-abort-ms` 内容不同），校验内容；同时清空旧的
   `/sdcard/Download/MagicRoot-ab/`（`run_safe_ab.ps1 -Mode Prepare` 会自动
   执行 `rm -rf /sdcard/Download/MagicRoot-ab`；手工流程请先确认上一次 run
   已 Pull，再删旧导出目录，避免把旧日志混进本次场次）；
5. 点「3. 开始提权」；记录开始时间；等待 DONE **或** FAIL **或** 重启/卡死；
6. 导出日志 + 记录 boot id（见 4.5/4.6）；在 `manifest.md` 记一行；
7. 下一个 run 从 4.1.1 重新开始（必须再次冷启动）。

### 4.2 冷启动（每个 run 前必须做）

- 用**物理按键/电源菜单**重启，或在主机侧手工执行 `adb reboot`；
  **禁止**把 `reboot` 写进 `adb shell` 命令字符串（本协议工具从不生成）。
- 等待启动完成：

```text
adb wait-for-device
adb shell getprop sys.boot_completed
```

  返回 `1` 后再等 20~30 秒让系统稳定。
- 记录本次 boot：

```text
adb shell cat /proc/sys/kernel/random/boot_id
```

  把结果写进本次 run 的 `boot_id_before`。
- 开跑前确认干净：

```text
adb shell getenforce
adb shell grep kernelsu /proc/modules
```

  `getenforce` 必须为 `Enforcing`；`grep` 应无匹配。

### 4.3 部署 + 写标志

按 4.1.3/4.1.4。**顺序不能反**：标志文件必须在「部署资产」之后推
（工作目录由部署创建；部署只增不删，但标志最终会被上次成功清理带走）。
部署后若 App 报 `safe 二进制缺失`，不要运行，回到 4.1.3 重新部署。

### 4.4 运行与观察

- 点「3. 开始提权」后记录开始时间（用于 manifest）。
- 正常结束标志（run.log 尾部）：
  - 成功：`DONE`；
  - 失败：`FAIL=<code>`（如 `FAIL=permissive`、`FAIL=cred_phase`）；
  - 早停/预算：`SAFE_LEAK_LIMIT leaked=...`、`SAFE_BUDGET_EXCEEDED elapsed=...`。
- 超时：若 20 分钟仍无 DONE/FAIL，按失败处理（截图 + 导出日志），
  不要反复点按钮。
- **设备重启/黑屏/掉 USB = 立即停止本场次**：见第 7 节。

### 4.5 日志导出（关键：成功后工作目录会被 App 清理）

正常成功路径：

```text
adb shell ls -l /sdcard/Download/MagicRoot-ab
adb pull /sdcard/Download/MagicRoot-ab/run-<epoch>-<pid>.log release/publish/experiments/p0-ab/sessions/<session>/<run-dir>/run.log
```

- 若 `/sdcard/Download/MagicRoot-ab` 里没有新文件或 `ab-export` 未生效：
  立即补拉 `adb pull /data/local/tmp/magic/run.log ...`（App 可能已清理，
  拉不到就标记本次 run 无效，查 `ab-export` 配置后重跑）。
- 失败/中断路径（工作目录还在）：先拉 run.log，再拉 ab-export（如有）：

```text
adb shell ls -l /data/local/tmp/magic/run.log
adb pull /data/local/tmp/magic/run.log <run-dir>/run.log
```

- 已知竞态：`ab-export` 在 `echo DONE` 之后立刻 `cp`，导出文件末尾可能
  少 1~2 行（如 DONE）。只要 attempt/abort/landing 数据完整即可；若关键
  收尾行缺失，在 manifest 备注，解析器会把该 run 标为 `incomplete`。

### 4.6 记录 sidecar（解析器会自动读取，推荐必填）

在每个 `run-dir/` 下写 `run.meta.json`：

```json
{
  "label": "B01",
  "arm": "safe-baseline",
  "boot_id_before": "从 /proc/sys/kernel/random/boot_id 读取",
  "boot_id_after": "run 结束/重启后读取",
  "reboot_detected": false,
  "wall_time_seconds": 300.0,
  "notes": "可选：异常、AB 导出缺尾行等"
}
```

- `arm` 只能是 `safe-baseline` / `p0-early`（大小写不敏感别名见解析器）；
- `boot_id_before != boot_id_after` 或 `reboot_detected=true` 时，解析器把该
  run 标为 reboot 并给出警告；这类 run **不计入验收**；
- `wall_time_seconds` 可从 App 面板/手工计时得到；日志自带时间戳时解析器
  优先用日志时间（`time_source=log-*`）。

---

## 5. `run_safe_ab.ps1` 用法（可选辅助）

默认 **dry-run**：只打印将要执行的 adb 命令，不连接设备。

```powershell
# 预览 B 臂准备命令（不执行）
powershell -File release/tools/run_safe_ab.ps1 -Mode Prepare -Arm safe-baseline `
  -Session release/publish/experiments/p0-ab/sessions/p0-ab-20261025

# 真正推送标志文件 + 记录 boot_id（需要连设备）
powershell -File release/tools/run_safe_ab.ps1 -Mode Prepare -Arm p0-early `
  -Session release/publish/experiments/p0-ab/sessions/p0-ab-20261025 -Execute

# 只读状态检查（flags / 冷启动状态 / run.log 尾部）
powershell -File release/tools/run_safe_ab.ps1 -Mode Status -Execute

# run 结束后导出日志 + 写 sidecar
powershell -File release/tools/run_safe_ab.ps1 -Mode Pull -Arm p0-early `
  -Session release/publish/experiments/p0-ab/sessions/p0-ab-20261025 -Label P01 -Execute
```

可选参数：`-Adb <adb.exe 路径>`、`-Serial <设备序列号>`、
`-EarlyAbortMs 4500`（p0-early 默认；safe-baseline 固定写 0）。

脚本安全约束（实现内校验，违反即拒绝生成命令）：

- 不使用管道 `|`、分号 `;`、`&&`、`||`、重定向 `>`/`<`、`$(...)`/反引号；
- 不生成 `reboot` / `shutdown` / `fastboot` 等词；
- 标志文件一律 `adb push`；
- 默认 dry-run，只有 `-Execute` 才执行。

`-Mode Prepare` 还会清空设备上的 `/sdcard/Download/MagicRoot-ab/`（旧的
ab-export 文件），因此必须先对上一次 run 执行 `-Mode Pull` 或手工拉取日志。

---

## 6. 分析命令与验收指标

### 6.1 解析命令

```powershell
# 全量 session：JSON + Markdown 摘要
python release/tools/parse_safe_ab.py release/publish/experiments/p0-ab/sessions/p0-ab-20261025

# 落盘报告（推荐）
python release/tools/parse_safe_ab.py release/publish/experiments/p0-ab/sessions/p0-ab-20261025 `
  --format markdown `
  --out-json   release/publish/experiments/p0-ab/sessions/p0-ab-20261025/ab-report.json `
  --out-markdown release/publish/experiments/p0-ab/sessions/p0-ab-20261025/ab-report.md `
  --out-csv    release/publish/experiments/p0-ab/sessions/p0-ab-20261025/ab-report.csv

# 只输出 JSON（给脚本/CI）
python release/tools/parse_safe_ab.py <run.log 或目录> --json
```

Windows PowerShell 5.1 控制台若出现中文乱码，先执行
`chcp 65001` 或直接看 `--out-markdown` 生成的文件（文件固定 UTF-8）。

### 6.2 验收指标（P0 通过条件）

| # | 指标 | 判定 | 解析器字段 |
|---|---|---|---|
| 1 | early abort 的 drain 中位数 | P0 池化 `drain median ≤ 5500 ms` | `comparison.metrics.median_drain_ms`（`--median-limit-ms` 可调） |
| 2 | SAFE_ABORT 次数不差 | P0 平均 `abort_events/run ≤ baseline + 1`（容差可调） | `comparison.metrics.abort_events_per_run`（`--abort-tolerance`） |
| 3 | landing attempts 不差 | 每个 phase 的 P0 平均首次 landing attempt ≤ baseline + 1 | `comparison.metrics.landing_attempts.<phase>`（`--landing-tolerance`） |
| 4 | 无重启 | P0 中 `reboot_detected=true` 的 run 数 = 0 | `comparison.metrics.reboots`、`runs[].reboot_detected` |
| 5 | 有效样本 | 无 `MODULE_ALREADY_LIVE` 快路径、无 `FAIL=missing_safe_bin`、无 `FAIL=profile_not_ready` | `comparison.metrics.valid_sample`、`runs[].reuse_fast_path`、`runs[].fail_codes` |

辅助观察（不单独卡关，写入报告）：

- DONE 成功率（P0 不应低于 baseline）；
- `SAFE_LEAK_LIMIT` / `SAFE_BUDGET_EXCEEDED` 次数（P0 不应增加）；
- `leaked` 起止/最大值、每次 run 的总时长；
- early abort 原因分布（`abort_reasons`：`drain_timeout` 等）。

所有阈值都可通过命令行覆盖，并在报告 JSON 的 `comparison.thresholds` 里留痕；
如果 `overall_pass=false`，逐行看 `comparison.metrics.*.pass` 和 `runs[].warnings`。

### 6.3 解析器字段定义（摘要）

| 字段 | 含义 |
|---|---|
| `arm` | `safe-baseline` / `p0-early` / `production` / `unknown`（由 `SAFE_MODE`+`EARLY_ABORT_MS` 推断，sidecar `arm` 可覆盖） |
| `phases` | `permissive` / `fsuid` / `cred_phase1` / `cred_phase2`（由 `== N. ... ==` 段标题、`p1/p2` 前缀、`== phaseN start` 推断） |
| `attempts` | phase 内最大 attempt 序号（缺 attempt 号时退化为行数） |
| `abort_events` | 带 `drained=0(...)` / `short_spray` / `slab_regrown` 的 SAFE_ABORT 事件 |
| `early_aborts` | 行内含 `SAFE_ABORT` 且含 `early` 的行（early 单行 marker 与 abort 摘要行分开计，不重复） |
| `drain` | `drained=N(ms)` 的 drain 循环时长：mean/median/p90/min/max（p90 为 nearest-rank） |
| `abort_drain` | 仅 abort 事件的 drain 时长统计 |
| `leaked_start/end/max` | 按日志顺序的 `leaked=` 首/末/最大值（cred 旧格式回退 `leak=`；`SAFE_LEAK_LIMIT leaked=` 参与 max） |
| `landing_attempts` | v36：`STEP_OK`/`LANDED`/`landed=1`；cred：`LEAK pN attempt=`；`first_landing_attempt` 取最小值 |
| `wall_time_seconds` | 日志时间戳或 sidecar 计算的总时长；`time_source` 标明来源；都没有时为 `null` |
| `reuse_fast_path` | 出现 `MODULE_ALREADY_LIVE` / `MODULE_LIVE_FAST_REPAIR_OK`，该 run 不能用于 exploit 对比 |

---

## 7. 重启、失败与中止处理

### 7.1 设备意外重启（P0 验收 "无重启" 的判定）

- 触发条件（任一）：运行中设备重启/黑屏重启、USB 掉线后重新枚举、
  `boot_id_after != boot_id_before`、App 显示异常、日志突然截断且设备 uptime
  归零（`adb shell cat /proc/uptime` 很小）。
- 处理：
  1. **立即停止本场次**，不要继续下一个 run；
  2. 尽量在重启后第一时间拉取 `/data/local/tmp/magic/run.log`（`/data/local/tmp`
     在 /data 分区，重启后仍可能保留）；
  3. 该 run 目录写 `run.meta.json`：`reboot_detected=true`，
     `boot_id_before/after` 均填，`notes` 记录现象与时间；
  4. 在 `manifest.md` 标记 `REBOOT`，该 run 排除出验收；
  5. 检查崩溃面（主机侧命令，不用 adb shell 管道）：
     `adb logcat -d -b crash -t 300`
  6. 冷启动确认干净后，再从配对序列继续；同编号重跑（如 P02 重跑后仍叫 P02，
     manifest 记录两次）。
- 解析器会把这类 run 标为 `status=reboot` 并在 `comparison.metrics.reboots` 里
  计入；若 P0 臂 ≥1 次重启，总体验收不通过。

### 7.2 其他失败

| 情况 | 处理 |
|---|---|
| `FAIL=missing_safe_bin` | 部署不完整或标志文件早于部署；重新部署 + 重推标志 + 重跑（该 run 无效） |
| `FAIL=profile_not_ready` / 内核不支持 | 设备/内核不符合前置条件，停止，不是 P0 结论 |
| `FAIL=permissive` / `FAIL=cred_phase` / `FAIL=module_wait` | 属于碰撞失败，记录并作为该臂的失败样本保留（不要丢弃）；若连续失败 2 次以上，停止检查环境 |
| `SAFE_LEAK_LIMIT` / `SAFE_BUDGET_EXCEEDED` | 保留日志；次数用于辅助指标，不应明显劣于 baseline |
| App 崩溃/被系统杀死 | 拉 logcat crash，标记 run 无效，重跑 |
| 工作目录被误清理 | 本次 run 无效，重新部署重跑 |

### 7.3 日志丢失的降级处理

- 成功路径只依赖 `/sdcard/Download/MagicRoot-ab/` 的导出文件；
- 若导出缺失且工作目录已清理：从 App 日志面板截图/复制尾部（不完整），
  标记 run 无效并重跑；同时先做一次 smoke run 验证 `ab-export` 工作正常。

---

## 8. 场次执行清单（可复制到 manifest.md）

```markdown
# P0 A/B session <日期>

- 设备: <型号/序列号>
- 内核: <uname -r>
- 实验 APK: <路径> sha256=<...> versionCode=<...>
- 工具版本: parse_safe_ab.py v1.0.0
- 顺序: B01 P01 B02 P02 B03 P03
- 每 run 前提: 冷启动 + getenforce=Enforcing + grep kernelsu 无匹配
- victim 档位: SELinux=32 fsuid=32 cred=24；skip_fsuid=off；su_compat=off

| # | 臂 | 开始 | 结束 | boot_id before/after | 结果(DONE/FAIL/REBOOT) | 日志路径 | 备注 |
|---|----|------|------|----------------------|------------------------|----------|------|
| B01 | safe-baseline |  |  |  /  |  |  | early-abort-ms=0 |
| P01 | p0-early |  |  |  /  |  |  | early-abort-ms=4500 |
```

---

## 9. 安全约束与禁止操作（本 P0 强制）

1. **禁止在 `adb shell` 命令字符串里使用**：管道 `|`、分号 `;`、`&&`/`||`、
   重定向 `>`/`<`、命令替换 `` ` ``/`$(...)`、以及 `reboot` / `shutdown` /
   `fastboot` / `bootloader` 等会被 Android shell 解释的词。需要写文件时用
   `adb push`；需要读文件时用 `adb shell cat/ls`；需要重启时由操作者手工重启
   或主机侧单独执行 `adb reboot`（不进入 `adb shell`）。
2. 本 P0 只新增实验文件，**不修改** `release/source` 生产链路、备份目录和
   `release/publish` 已有发布物；`release/publish/experiments/` 只新增目录。
3. 不 `adb push` 到 `/system`、`/vendor`、`/data/adb`；不执行提权成功后的
   写模块/改系统操作（P0 只做安全模式 A/B 本身）。
4. 设备工具默认 dry-run；`-Execute` 才执行，且只执行准备/状态/拉取日志类命令。
5. 不要在实验设备上同时做其他刷机/模块安装；A/B 期间保持设备与 APK 不变。

---

## 10. 已知假设与未决风险

1. **实验 APK 尚未在本协议中钉死哈希**：A/B 开始前必须由构建方给出
   safe 资产版 APK 的 SHA256/versionCode 并写入 manifest；若中途换 APK，
   本场次作废。
2. **风险：safe-mode 标志 + 未部署 safe 二进制** → run.sh 直接
   `FAIL=missing_safe_bin`。用 4.1.3 的 `ls -l` 检查避免。
3. **风险：ab-export 竞态**：`cp run.log` 在 `echo DONE` 后立即执行，导出文件
   末尾可能缺 DONE 等 1~2 行；不影响 attempt/abort/landing 指标，但会让
   `status=incomplete`。首次 run 建议先验证导出文件确实出现。
4. **风险：UI 默认 cred victim=16**：不改成 24 会与 P0 计划的参数不一致，
   造成两臂都不可比。换 APK 后必须复查。
5. **冷启动判定依赖操作规范**：`grep kernelsu /proc/modules` 有输出时必须
   重启；若误跑，日志会出现 `MODULE_ALREADY_LIVE`，解析器将 run 标为
   `reuse_fast_path` 且 `valid_sample` 验收不通过。
6. **boot_id / sidecar 依赖人工记录**：没有 sidecar 时解析器无法自动判断
   重启（日志本身通常不含 boot id）；不写 sidecar 的 run 只能从日志尾部
   截断/异常人工判断，建议强制执行 4.6。
7. **KASLR/KO 缓存影响耗时而非成功率**：每次冷启动 KASLR 与 ko patch 时间
   不同；两臂交替执行以抵消漂移，但仍建议 ≥3 对样本。
8. **safe 二进制的实际日志格式以构建产物为准**：解析器兼容
   `SAFE_BUILD`/`SAFE_ARGV`、`p1/p2` 前缀、standalone `SAFE_ABORT early ...`
   （含/不含 attempt 号、含 `phase=N` 字段）等变体；若构建产物新增字段，
   更新 `parse_safe_ab.py` 的相应正则并重跑 fixtures 自测。
9. **P0 只验证 early abort 本身**：safe 模式的 min-drain/参数仍是实验值；
   `SAFE_ABORT` 语义变化、KernelSU 后续版本差异不在本 A/B 结论范围内。
