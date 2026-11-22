# Honor SuSFS LKM 适配研究（2026-10-29）

## 结论

Honor 6.12.58 / 6.6.118 的正确路线不是移植 OnePlus 16 的 6.18.21 guard，也不是直接使用
SUSFS release r18.5 的 KMI `.ko`，而是：

1. 用 `inforcqb/susfs4ksu-lkm` 的 **最新源码**（至少包含 20016397 的 syscall-table
   expected-hook 校验）按 KMI 重新构建：
   - Honor 6.12.58 → `android16-6.12`
   - Honor 6.6.118 → `android15-6.6`
2. 使用 `susfs_insmod` 在设备端按 Honor release 修正 vermagic，并解析 kallsyms。
3. 只在 KernelSU 已加载且 `su` 可用后加载 guard。
4. 不接受 6.18 的 `susfs_guard_lkm.ko` 跨 KMI 复用，也不接受 r18.5 release
   中缺少 `susfs_or_entry_expected_hook` 的 6.12/6.6 旧件。

## 上游证据

- OnePlus16-Jailbreak HEAD：`20016397c916311db8cccabe25938adef634726b`
  （2026-10-28，`fix(lkm): validate syscall table entries and the or_entry hook`）
- Vendored source：`lkm/susfs4ksu-lkm`
  - `MODIFICATIONS.md` 记录 6.18 BTI/kCFI wrapper 修改
  - `susfs_fp_hook.c` 有 `fp_entry_is_kernel_original()`、`kernel_text_address()`
  - `susfs_or_entry.c` 有 `susfs_or_entry_expected_hook` 校验
  - guard 真机产物：3,456,440 B，sha256
    `4c944d3f84b386bb03c0aadb4527c4ec74c12fe511c5511884073160c3a88304`
- 上游 `inforcqb-self/susfs4ksu-lkm` CI：
  - `build-lkm-ddk` matrix 包含 `android15-6.6`、`android16-6.12`
  - DDK 镜像：
    - `ghcr.io/ylarod/ddk-min:android15-6.6-20260828`
    - `ghcr.io/ylarod/ddk-min:android16-6.12-20260828`
  - 每个 KMI 单独 artifact：`susfs_guard_lkm.ko-android16-6.12`
- 但 **release r18.5** 的 6.12/6.6 资产仍是旧尺寸：
  - `3,258,016` / `2,630,816`
  - 与本项目之前移除的旧 guard 完全一致，缺少 expected-hook 加固。
  因此不能把 release 件当作“最新正确 guard”。

## Honor 真机配置

MLY-AN00 / 6.12.58 拉取 `/proc/config.gz` 后确认：

```text
CONFIG_ARM64_BTI=y
# CONFIG_ARM64_BTI_KERNEL is not set
CONFIG_CFI_CLANG=y
CONFIG_CFI_ICALL_NORMALIZE_INTEGERS=y
# CONFIG_CFI_PERMISSIVE is not set
CONFIG_MODVERSIONS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
# CONFIG_MODULE_SIG_FORCE is not set
```

关键含义：

- **内核态 BTI 未开启**：OnePlus 的 `bti c`/kprobe 问题不是 Honor 的主要风险；
- **kCFI 开启**：所有通过运行时指针调用内核函数的 wrapper 必须 `__nocfi`；
- **BTF 开启**：`btf_layout` 可在运行时校验结构偏移；
- **MODVERSIONS 开启，但 DDK Module.symvers 没有 CRC 条目**：
  build workflow 明确说明 load-time CRC check 是 inert 的；
- **MODULE_SIG_FORCE 关闭**：未签名 LKM 可由 loader 加载。

`/proc/kallsyms` 中存在：

```text
sys_call_table
compat_sys_call_table
static_calls_table
lsm_active_cnt
modules_op
kallsyms_op
proc_pid_maps_op
proc_pid_smaps_op
```

`security_hook_heads` 不存在，符合 6.12 改用 `static_calls_table` 的预期。

## 本项目当前代码发现

`run98260.sh` 的 Next 内置 guard 分支判断：

```sh
[ "${SUSFS_ENABLE:-0}" = "1" ]
```

但真实链路只设置了：

```text
SUSFS_SWITCH=1
```

所以该分支从未执行，设备上也没有生成 `98260-susfs-ksud.log`；
真实运行结束后 `/proc/modules` 只有 `kernelsu`，没有 `susfs`。

这不是“guard 加载失败”，而是 **代码变量名不一致导致根本没有尝试**。

## 适配建议

### 构建

使用 OnePlus vendored source（含 20016397）或同源更新版本，按 KMI 构建：

```bash
# 6.12
KDIR=/opt/ddk/src/android16-6.12 \
OUT=/out/susfs_guard_lkm-android16-6.12.ko \
bash lkm/build-susfs.sh

# 6.6
KDIR=/opt/ddk/src/android15-6.6 \
OUT=/out/susfs_guard_lkm-android15-6.6.ko \
bash lkm/build-susfs.sh
```

实际需在对应 DDK 容器内运行；build 脚本只负责 `make -C $KDIR M=...`。

### 设备端加载

```sh
susfs_insmod /data/local/tmp/susfs_guard_lkm-android16-6.12.ko expose_proc=1
```

加载器会：

1. 从 `/proc/kallsyms` 把未定义符号写成 SHN_ABS；
2. 检查 `/dev/kmsg` 的 vermagic 错误；
3. 按内核要求把 `.modinfo` 的 `vermagic=` 改成 Honor release；
4. 重新 `init_module`。

因此 **GKI 6.12.76 的 guard 可以在 6.12.58 上尝试**，但不能用 6.18 或 6.6 的件。

### 安全门

- 拒绝缺少 `susfs_or_entry_expected_hook` 的件；
- 加载后检查 `/proc/susfs_path` 和 `/sys/module/susfs_guard_lkm`；
- 任何 `Oops - BTI`、`CFI failure`、`refusing to chain` 都立即回滚/重启；
- 不要在 root 链路成功前预加载。

## 当前阻塞

本机没有 Docker/WSL/KMI KDIR，无法本地重建；
GitHub Actions artifact 需要认证，release r18.5 又是旧件。

下一步需要其一：

1. 由上游 CI 下载最新 `susfs_guard_lkm.ko-android16-6.12` / `-android15-6.6`；
2. 在带 Docker 的机器上按上面的 DDK 命令构建；
3. 提供可用的 GitHub token 下载 Actions artifact。


## 2026-10-29 提供 artifact 审计

收到的五个文件全部未通过：

| 文件 | 大小 | sha256 | expected-hook |
| --- | ---: | --- | --- |
| `susfs_guard_lkm.ko-android16-6.12` | 3,258,016 | `1f50330a...` | 缺失 |
| `susfs_guard_lkm.ko-android15-6.6` | 2,630,816 | `7c2a2747...` | 缺失 |
| `next-android16-6.12_susfs_guard_lkm.ko` | 508,928 | `4599d9e1...` | 缺失 |
| `next-android15-6.6_susfs_guard_lkm.ko` | 447,336 | `d05c38da...` | 缺失 |

两个 zip 的 6.12/6.6 大小和 hash 与**旧 release r18.5** 完全一致；
Next 两个 KO 有 `susfs_fp_hook`，但同样没有
`susfs_or_entry_expected_hook`。

因此全部拒绝，不进入设备加载。

新增静态检查器：

```bash
python tools/check_susfs_guard.py <guard.ko> --kmi android16-6.12
```

检查：

- ELF；
- `.modinfo` vermagic 与 KMI；
- `susfs_or_entry_expected_hook`；
- `susfs_fp_hook`。

这只是静态门禁，不能替代真机启动/加载验证。

## 设备状态

真实链路完成后 USB ADB 掉线；Windows 仍能看到 `Honor Magic9` WPD 设备，
但 `adb devices` 为空。需要重新插拔/在手机上重新授权 USB 调试后才能继续实机测试。


## 2026-10-29 自建尝试记录

已实际检查本机：

- 无 Docker / Podman / WSL Linux；
- 无 MSYS2/LLVM/KMI KDIR；
- 当前会话非管理员；
- 设备在真实链路后重启，ADB 恢复但只有 uid=2000，/system/bin/su 不存在；
- 设备虽有 /system/bin/chroot，但没有 root，无法建立 chroot 构建环境。

因此本机无法执行 DDK 容器构建，也未产出新的 .ko。

已补可复现脚本：

`ash
VARIANT=android16-6.12 KDIR=/opt/ddk/src/android16-6.12   sh tools/build-susfs-honor.sh
`

脚本只负责在正确 DDK 环境中完成 kbuild 并调用
	ools/check_susfs_guard.py 门禁；它不会替代 DDK 镜像/KDIR。

构建前置条件：

1. 对应 DDK 镜像（android16-6.12 / android15-6.6）；
2. 已 modules_prepare 的 KDIR；
3. 含 20016397 校验的 guard 源码；
4. 构建后必须通过 expected-hook 检查。

在没有这些条件时，继续硬加载旧 r18.5 件属于已知会再次触发 openat2 野指针风险的行为，已拒绝。
