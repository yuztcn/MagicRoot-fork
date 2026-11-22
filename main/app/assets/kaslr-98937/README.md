# CVE-2026-98937 KASLR slide oracle (optional MagicRoot template)

Read-only perf callchain leak -> arm64 2 MiB-aligned slide -> unique slide.
No root, no kernel write.  It is an optional external KASLR source for the
existing MagicRoot chains; the default KASLR paths are unchanged.

## Files

| file | 用途 |
|---|---|
| `poc98937` | CVE-2026-98937 PoC（ARM64, API24），输出 `[C] first kernel callchain addresses` |
| `slide98937` | 从泄漏的 callchain 地址求唯一 slide；同时输出 `PREPARE`/`SELINUX_ARG`（供 64560 链交叉校验） |
| `run98937.sh` | oracle 驱动：跑 PoC、解析 callchain、按 `targets.conf` 选目标常量、输出 `KASLR_*` |
| `targets.conf` | 每内核的 `_stext`/`_etext`/link base + `prepare_creds`/`selinux_state` 链接地址（g142 已填） |

g142（HONOR MLY-AN00，6.12.58 g142ddad31e60）常量来自精确内核 ELF
（SHA-256 f445f775…b17c56）：`_stext=0xffffffc080010000`、
`_etext=0xffffffc0812b0000`、`_text=0xffffffc080000000`、
`prepare_creds=0xffffffc0801935b8`、`selinux_state=0xffffffc0827e7a60`。

## 启用（默认 auto）

模块和目标常量存在时，`run.sh` / `run98260.sh` 会**优先尝试本 oracle**，失败自动回退
原有 KASLR 源（internal/raw/legacy 或 trace-grab）。显式控制：

```sh
# 关闭（或 0 / none）
MAGICROOT_KASLR_SOURCE=off
# 强制（失败也不回退，适合诊断）
MAGICROOT_KASLR_SOURCE=98937
# 标记文件：即使不传环境变量也启用（适合手动/脚本测试）
mkdir -p /data/local/tmp/magic/kaslr-98937
touch /data/local/tmp/magic/kaslr-98937/enable
```

## 输出（示例，g142 某次 boot）

```
KASLR_SLIDE=0x1a2fa00000
KASLR_RUNTIME_TEXT=0xffffffdaafa00000
KASLR_SOURCE=98937
KASLR_ANCHORS=3
KASLR_VOTES=8
KASLR_BYTES=19529728
PREPARE=0xffffffdaafb935b8
SELINUX_ARG=0xffffffdab21e7a59
```

- `KASLR_ANCHORS` 是唯一内核 text 帧数（通常 3）；`KASLR_VOTES` 是参与的一致地址数。
- 64560 链的 g142 profile 默认要求 `ANCHORS>=5`（原始 trace 源的启发式）。98937 源在
  `run.sh` 中用 `KASLR_98937_ANCHOR_OVERRIDE` 将该下限改为 3，并保留
  **PREPARE/SELINUX_ARG 交叉校验**（用 profile 链接 + slide 重算并逐字节比对）；
  这一步会打印日志，不是静默放宽。
- 98260 链直接使用 `--slide`，没有 anchors 门限。

## 接入点

- `assets/98260/run98260.sh`：在 slide 选择逻辑最前面尝试 98937；成功则
  `98260_SLIDE_SOURCE=98937`、`SLIDE_ARG="--slide …"`；失败回退原有
  internal/raw/legacy 源。
- `assets/run.sh`（64560）：在 KASLR cache 之前尝试 98937，生成兼容
  `kaslr.txt` 的字段并写 cache；随后原有的 `KASLR_CROSS_CHECK` 仍会校验。
- `MainActivity`：`ASSETS` / `ASSETS_98260` 已加入本目录四个文件，并对
  `kaslr-98937/` 做 `chmod 755`。**需要重新构建 APK 才会随包部署**；不重建时
  可手动把本目录 push/复制到 `/data/local/tmp/magic/kaslr-98937`。

## 运行上下文

- PoC 用 perf_event_open；在 `u:r:shell:s0`（uid 2000，Shizuku/Stellar）下
  case A 会被拒绝，case C 是真正的权限绕过；在 root/ksu 域里可能报
  `UNRESTRICTED`，但 callchain 仍会泄漏，slide 仍可用。
- slide 每次 boot 变化；本模块只写本次 boot 的 `kaslr-98937.txt`，不缓存跨 boot。
- 只读，无内核写，无 root 依赖。


## 2026-11-21 targets 扩充

`targets.conf` 现覆盖 22 个本地构建（5.15 之外）：6.1.157 g264/g8d6/gaaa/g19a、
6.1.128 g2e1f/g8a496、6.6.58 g648、6.6.89 6689、6.6.118 g893/f171/g554、
6.12.23 g856、6.12.38 g4b36/gfde、6.12.58 g142/g42fcf/g3a7ac、6.12.69 g242e、
6.18.21 gfee/g928/ge186/gf957/g7fcbff。98260/64560 与 99491 共用此表；
无精确常量的构建由各自链的原 KASLR 源回退。
