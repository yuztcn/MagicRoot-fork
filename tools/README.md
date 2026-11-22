# MagicRoot 工具目录说明 (`tools/`)

## 0. 当前活跃工具（1.0.6 主线）

从仓库根目录运行：

```sh
bash tools/check.sh
```

| 工具 / 数据文件 | 用途 |
|---|---|
| `tools/check.sh` | 一键静态门禁（62 个脚本语法 + LF 检查、资产双向对账、Java 单测、Flavor/6.1/98260/H1C/Termux 回归测试） |
| `tools/kernel_profiles.json` | 28 个内核 profile 路由与资产映射单一数据源 |
| `tools/asset_dedup_map.json` | APK 构建期 37 项重复资产去重映射表（配合 `KernelLogHelper.resolveCanonicalAsset`） |
| `tools/strip_baseline.py` | 构建期剔除 baseline profile、v1 签名以及经 SHA-256 校验一致的重复资产 |
| `tools/audit_kernel_flavors.sh` | 校验所有 profile × 5 种 Flavor 的模板与符号表匹配 |
| `tools/audit_6157_chain.py` | 校验全部 6.1.x 载荷、CGA vermagic、M6 资产与分派顺序 |
| `tools/test_61128_adaptation.py` | 6.1.128 适配回归测试 |
| `tools/test_98260_finalize.py` | `RunProgressTest` + `run.sh` 收尾状态机回归测试 |
| `tools/test_h1c_flow.py` | 6.18.21 H1C 引擎状态机单元测试 |
| `tools/test_termux_su_entry.py` | Termux `su_optional.sh` 补丁回归测试 |
| `tools/tests/RunProgressTest.java` | 运行进度分类器纯 Java 单元测试 |
| `tools/tests/KernelLogHelperTest.java` | 内核版本/vermagic 解析、路由表与去重映射纯 Java 单元测试 |
| `tools/package-source.ps1` / `package-source.py` | 源码包打包与必需路径校验 |

> 目录中其余 `doc_*`、`patch_*`、`fix_*`、`update_*` 脚本为历次版本迭代的迁移与记录脚本，保留以维持 `docs/adaptation/` 审计可追溯性。

---

# Release verification tools (historical 1.0.x notes)

Run from the workspace root after building and packaging.

## 1. Offline release verification

```sh
python release/verify_release.py
```

Checks:

- main APK assets:
  - `t64560_v36` (MAXVICTIM=32) and `t64560_cred` (MAXVICTIM=32) hashes;
  - no Enhanced `T64560_SAFE` / `SAFE_ABORT` markers;
  - victim limits 32/32/24 and min-drain parameters;
  - page-persistence markers.
- route APK:
  - `assets/pty_run` hash;
  - no `assets/su`;
  - `closure.sh` no BOM/CRLF;
  - plan-B dex markers and no plan-A `TEMP_SU` markers.
- archive:
  - no keystore, local absolute paths, or signing-password fallback;
  - `SHA256SUMS.txt` matches the three published files.
- shell assets:
  - no BOM/CRLF;
  - `sh -n` if a shell is available.

If no `sh` exists on the host, the script prints a warning. Use
`--require-shell` in CI where a shell is guaranteed.

## 2. Shell syntax

```sh
python release/tools/shell_syntax_check.py
# optional:
python release/tools/shell_syntax_check.py --adb C:\path\to\adb.exe
python release/tools/shell_syntax_check.py --require-shell
```

If no local `sh` exists, the tool can run `adb exec-out sh -n` against a
connected device without pushing files.

## 3. Page persistence after process death

This requires an installed release APK and a connected device. It does not
install or modify the app; it only taps the About tab, force-stops the app,
relaunches it, and checks the restored page.

```sh
python release/tools/page_persistence_test.py
```

Expected:

```text
PASS: page 1 restored after process death
```

If the test reports the About tab not found, make sure the app is in the
foreground and the accessibility/UIAutomator dump is available.

## 4. Route118 PTY device smoke test

Before running the full route payload, verify `/dev/ptmx` and the PTY relay:

```sh
adb shell "cd /data/local/tmp/cve64560_118 && ./pty_run /system/bin/echo PTY_SMOKE"
```

Expected:

```text
PTY_SMOKE
```

Then test a shell on the PTY:

```sh
adb shell "cd /data/local/tmp/cve64560_118 && ./pty_run /system/bin/sh -c 'echo PTY_OK; id'"
```

If these fail, do not continue to the payload/closure stage.

## 5. Backup integrity

The release process must not modify the versioned backup directories. The
backup APK hashes were recorded during this change and are not expected to
change:

```text
MagicRoot-1.0.0-original       CBF9BA27...
MagicRoot-1.0.1-release        7F35A34B...
MagicRoot-1.0.1-multi-release  EBB1DDAD...
MagicRoot-1.0.2-release        366738A1...
MagicRoot-1.0.2B-release       9EB6A15C...
MagicRoot-Backup               CBF9BA27...
```
