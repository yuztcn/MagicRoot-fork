# 6.1 CGA 三项 KernelSU 功能恢复（g264 / gaaa）

日期：2026-11-11

## 1. 范围

本次恢复以下三项在精简 CGA 模块中被裁掉或没有初始化的功能：

- `su_compat`：传统 SU 命令支持；
- `kernel_umount`：按 UID 处理模块挂载的内核级卸载；
- `selinux_hide`：隐藏 KernelSU 对 SELinux 的修改。

**只替换 g264 与 gaaa 的运行资产。** 其他 6.1 profile 保持原样：

- `g8a496/g2e1f` 的现有 225 符号清单没有新增的
  `tracepoint_probe_register_prio`，工作区又没有对应外部 `vmlinux`，因此
  不伪造地址、不生成恢复版；
- 其余旧 CGA profile 没有本轮完整重链输入，继续使用原有模块；
- `g19a` 的 `61157/kernelsu-magicpad.ko` 是另一套完整上游模块，不包含本次
  CGA 裁剪标记，未被替换；
- g7d 的 M6 路线不变。

## 2. 输入与来源

用户提供的原始 CGA 包包含 39 个预编译对象、4 个修改源文件和链接后处理
脚本。包内 4 个源文件与仓库修改前的 `binary-sources/6157-g264/cga/` 一致。

```text
CGA package
  uploads/20261110174203-CGA-W00-KernelSU-复刻包_(2)_(1).zip
  SHA-256 170c60e1aff18679497e7a0d7e50d0719aadb2c6b94cdcf13082fa8fd759c911

KernelSU
  v3.3.1 / 32680 / UAPI 5
  commit 0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d

Android 6.1 source archive (6.1.166 headers)
  src.android14-6.1.tar.zst
  SHA-256 a0e0d938890dc1ecd6c8676f4342ba295c578296b526ba6a18aeae3135216205

Android 6.1 generated headers (kdir-min)
  kdir.android14-6.1.tar.zst
  SHA-256 b253b7f001b86697d9f39e7576a3c198577f55d72fa4d09681aac759ebb58808

Zig 0.13.0 / Clang 18.1.6
  zig-linux-aarch64-0.13.0.tar.xz
  SHA-256 041ac42323837eb5624068acd8b00cd5777dac4cf91179e8dad7a7e90dd0c556
```

同时提供的 `g19a` boot 的 SHA-256 为
`428e36ff27c4389854837f3fbdcb632beb0471f8a2bea6833b2e087495479ac9`。
它确认了该镜像的 Kprobes/Kretprobes/syscall tracepoints 配置，但**没有把
g19a 的地址用于 g264 或 gaaa**。g264 地址来自旧 base 与现有 g264 符号表；
gaaa 地址来自现有 `build/gaaa-adapt/vmlinux.elf`。

## 3. 原样构建对照

先用原始 CGA 源文件原样重建 `init.o`、`hookmgr.o`、`supercall.o`，再与原包
对象比较。对照项包括：

- 所有函数的大小；
- 所有未定义符号；
- 所有重定位类型和目标。

三项均为空差异：`func_size_diff={}`、`und_diff=[]`、
`relocation_diff=Counter()`。原始对象重链得到 `ABS=225 / 桩=220`，恢复版
得到 `ABS=226 / 桩=221`，缺失符号均为 0。

对照过程发现原 README 的参数列表与实际对象不完全一致：

- 需要 `-fomit-frame-pointer`，否则函数序言和大小不同；
- 原对象含 SIMD `q0` 清零指令，实际构建不能使用
  `-mgeneral-regs-only`。

这里只声称**代码生成与重定位语义一致**，不声称整个 ELF 的字符串排列、
符号表布局和文件字节与旧对象完全相同。

## 4. 实现

### su_compat / kernel_umount

`hookmgr.c` 恢复五个 syscall hook、kretprobe 和 sys_enter tracepoint 的注册，
并在全部成功后调用：

```c
ksu_setuid_hook_init();
ksu_sucompat_init();
```

`arm64_syscall_hook.c` 新增 `ksu_syscall_dispatcher_ready()`：
`ksu_syscall_table_hook()` 写入后必须读回预期函数指针；dispatcher 未真正
安装、kretprobe/tracepoint 失败或任一 hook 注册失败时，撤销部分注册并保留
原有 supercall/`su_lkm` 路径，不声明这两个功能可用。

`supercall.c` 保留现有 MANAGER-INSTALL/root grant kprobe；当官方
`setresuid` dispatcher 已接管时跳过重复的 manager 安装，避免同一 UID 切换
被处理两次。

### selinux_hide

`init.c` 恢复 `ksu_selinux_hide_init()`，保留当前 CGA 已有的 sepolicy 注入、
Enforcing 和 `rmmod` 修复。`apply_kernelsu_rules()` 在修改策略前创建的
`backup_sepolicy` 继续作为隐藏功能的原始策略备份。

### 运行时计数

`run6157_full.sh` 不再把全部 profile 固定为 225/220：

```text
g264 / gaaa:  ABS=226, live stubs=221
其他旧 profile: ABS=225, live stubs=220
```

`rebase_cga_module.py` 的默认值仍锁定旧 base；只有显式设置
`CGA_BASE_SHA256`、`CGA_EXPECTED_ABS`、`CGA_EXPECTED_STUBS` 才接受恢复版。
旧 base 保存在 `binary-sources/61157-g264/legacy-cga/`，只用于历史验证，
不进入 APK。

## 5. 可复现构建

构建入口：

```text
binary-sources/6157-g264/build-feature-restore.sh
```

示例参数形式（路径按本机调整）：

```bash
CGA_PACKAGE=/path/to/extracted-CGA-package \
KERNEL_SRC=/path/to/android14-6.1-source \
KDIR=/path/to/android14-6.1-kdir \
KERNELSU_SRC=/path/to/KernelSU-v3.3.1 \
CGA_CC='qemu-aarch64 /path/to/zig.bin clang' \
GAAA_VMLINUX=/path/to/gaaa/vmlinux.elf \
bash binary-sources/6157-g264/build-feature-restore.sh /path/to/new-empty-output
```

脚本要求空输出目录，不执行设备命令、不自动覆盖 APK 资产。已在一个新的
输出目录完整重跑，g264 与 gaaa 输出均和安装到 `main/app/assets` 的文件
**逐字节一致**。

最终资产：

```text
size    422384 B (each)

g264/ksm-g264-base.ko
  SHA-256 b44cc79de9196c65a0f2ffe1a6e5b23dff7713c68f8752c3fe861c627d78399a
  vermagic 6.1.157-android14-11-g2646292297b1
  _printk 0xffffffc0086bc710

g264/ksm-gaaa-base.ko
  SHA-256 64ebb525f3f98c73a0cc648f27552b0e5792ee18aaf87c6b1fdade15a90bc377
  vermagic 6.1.157-android14-11-gaaa383620ebf
  _printk 0xffffffc008582dbc

61157/g264/ksm-g264-base.ko
  与主 g264 base 字节一致，供 legacy g264 路线使用

binary-sources/61157-g264/cga-feature-restore.json
  SHA-256 8864b383c8be0ced39018b6c30eb983bb7e19b2187645c520a78a6c08005e510
```

## 6. 验证状态

已完成静态/主机侧验证：

- 原样对象语义对照通过；
- 恢复版重链 `ABS=226 / 桩=221 / 缺失=0`；
- gaaa 确定性 `verify` 通过，变化字节 1144；
- `ko_slide_patch` 在 QEMU 下以 slide=0 处理两份模块，均输出
  `abs_symbols=226 stub_quads=221`，输出与输入逐字节一致；
- `tools/test_cga_feature_restore.py` 验证真实初始化调用、dispatcher 读回、
  tracepoint 注册和 setresuid 防重复 guard；
- 旧 6.1.128 CGA 测试继续使用旧 base 并通过；
- `tools/audit_6157_chain.py` 与完整性清单检查通过。

**尚未在真机 insmod。** 因此当前不能声称三项功能已在设备上完成端到端
验证。真机验收至少应检查：

```text
CGA-FEATURES: su_compat and kernel_umount registered
dispatcher installed and verified
selinux_hide / backup sepolicy success
ksud feature list / feature set 的实际读回
传统 /system/bin/su、su_lkm、按 UID 模块卸载和 SELinux 状态
```

若出现 `CGA-FEATURES: syscall features unavailable`，应保留现有
supercall/`su_lkm` 路径并收集 `98260-features.log` 与内核日志，不应把管理器
仍显示“不支持”误判为 UAF 或提权失败。

## 7. APK 构建记录（2026-11-11）

本机（Android arm64）发布构建与 `build.ps1` 等价，但有两个宿主差异：

1. AGP 从 Maven 下载的 AAPT2 是 TLS 对齐 32 的 arm64 产物，Bionic 要求 64，
   无法启动。改用工具链自带的原生 AAPT2：

   ```bash
   -Pandroid.aapt2FromMavenOverride=$PREFIX/bin/aapt2
   ```

2. `zipalign` 只有 x86-64 版本，无法运行。使用仓库新增的
   `tools/zipalign.py`（对齐后逐条目校验内容哈希不变）：

   ```bash
   python3 -I tools/zipalign.py -f -p 4 MagicRoot-stripped.apk MagicRoot-aligned.apk
   apksigner sign --ks <release.keystore> --ks-pass ... --out main/app/MagicRoot.apk MagicRoot-aligned.apk
   ```

构建结果：

```text
main/app/MagicRoot.apk
size    61,209,584 B
sha256  c264000fdfef2410ac4f80f9c9e28340ff3a3d017dd3fc6e8581cb482835159f
V3 signer ef572a91ebf470dc6606af3639e8aa8d28b4bd0768d31b5efbbb2933d92c8296
versionCode 12 / versionName 1.0.5 / targetSdk 37 / arm64-v8a
```

APK 内两份恢复版模块哈希与上表一致；`g8a496/g2e1f` 保持原字节；
`61157/g264/ksm-g264-base.ko` 按去重表移除，由 canonical 条目提供。
