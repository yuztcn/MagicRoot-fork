# PATCH-NOTES.md — PATCHED/ 目录说明（静态适配产物，非可刷写镜像）

> 目标构建：**Honor AAK（AAK-AN00，MagicOS 10.0.0.175(SP1)，Android 15 基线）**
> kernel release：`6.6.118-android15-8-gf17133276a57-abogki518694926-4k`
> boot(1).img sha256：`3dacd60da1d8faa7e2548d22dbdd4fcc254d8892aa35d106c2aa6b632fcbff4e`
> 适配日期：2026-10-28；全部离线生成，**未连接、未写入任何真机，未执行 flash**。

## ⚠️ 先读：这个目录里什么能碰、什么不能碰

| 产物 | 性质 | 能不能用 |
|---|---|---|
| `boot-repack-identical.img` | 无损重打包**证据**（与原 boot(1).img 逐字节相同） | **禁止刷入**。刷它没有意义（内容没变），而且一旦设备有 AVB 校验状态变化会直接 boot 失败 |
| `pc98260_target_66118.h` | C 头文件（per-build 常量） | ✅ 用于编译 98260 载荷 |
| `profile-66118.json` | profile（地址为十六进制字符串） | ✅ 给 App/工具链导入 |
| `syms_66118.txt` | KernelSU LKM 符号表（225 行，0 缺失） | ✅ 给设备端 `ko_patch` 使用 |
| `build/exploit-android-key-ptr-66118` | 静态编译的 98260 载荷（NDK r28c，未上机） | ⚠️ 仅限自有设备研究；必须按 REPORT.md §8 的灰盒顺序先做只读验证 |
| `build/pc98260-su-66118` | su 客户端 | 与官方发布资产逐字节相同（可复现性证据） |
| `build/*.c / build/pc98260_target.h` | 编译输入（从 toolkit 复制 + 本构建 header） | 供复现编译 |

**本任务没有、也不应该产出“已打好补丁的 boot 镜像”**：本镜像 AVB = SHA256_RSA4096，
OEM 私钥不在手上，任何内容改动都无法重签，锁 bootloader 会拒绝启动。
MagicRoot 的 6.12 方案同样不刷 boot —— boot.img 只在离线阶段被用来提取 kallsyms/BTF/profile，
提权在运行期内存中完成（UAF→rootd→KSU LKM 临时加载）。详见 `../REPORT.md` §6。

## 1. 文件 sha256

| 文件 | sha256 |
|---|---|
| `boot-repack-identical.img` | `3dacd60da1d8faa7e2548d22dbdd4fcc254d8892aa35d106c2aa6b632fcbff4e`（= 原镜像） |
| `build/exploit-android-key-ptr-66118` | `2d9a3042d24b976b3affd70837d6b405d21e161ac00cd612418b28ee92230fbc` |
| `build/pc98260-su-66118` | `696240ec583616d3677e693d1e5d3783b7f590b682ace8d7ca830bc757516ca5` |
| `pc98260_target_66118.h` | 见 `SHA256SUMS.txt` |
| `profile-66118.json` | 见 `SHA256SUMS.txt` |
| `syms_66118.txt` | 见 `SHA256SUMS.txt` |

## 2. 如何复现编译（与项目 1.0.5 工具链一致）

前置：`work/toolchain/ndk/android-ndk-r28c`（已在仓库内）。

```powershell
$boot = "C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\adapt-66118\boot"
$bd   = "$boot\PATCHED\build"
$env:TMP = "$bd\tmp"; $env:TEMP = "$bd\tmp"; $env:TMPDIR = "$bd\tmp"   # 必须可写的 TMP
$cc = "C:\Users\HourG\Documents\deepseek-harness\MagicRoot98260\work\toolchain\ndk\android-ndk-r28c\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android35-clang.cmd"
Push-Location $bd
& $cc -std=gnu11 -O2 -w -pthread -static -I. -o exploit-android-key-ptr-66118 uaf_plant_61258.c stubs.c rootd.c
& $cc -std=gnu11 -O2 -w -static -o pc98260-su-66118 su98260.c
Pop-Location
```

复现判据：
- `pc98260-su-66118` 与项目官方 `assets/98260/pc98260-su` **逐字节相同**（`696240ec…`，本次已验证）；
- `exploit-android-key-ptr-66118` 因换 target header 而 hash 不同（官方 6.12.58 版为 `fe67a61d…`），
  但编译参数/流程/大小（2,213,008 B）完全一致。

> 说明：`build/stubs.c` 把 `pc98260_try_ksu_install()` 置空（先验收 rootd 的临时桩，与项目 1.0.5 一致）；
> 真正的 KSU 接管走 `syms_66118.txt + ko_patch + ksud insmod` 的独立步骤（见 §3）。

## 3. KSU LKM 侧（提权之后，不是 boot patch）

目标 vermagic（`ko_patch` 的最后一个参数）：

```text
6.6.118-android15-8-gf17133276a57-abogki518694926-4k SMP preempt mod_unload modversions aarch64
```

设备端步骤（全部在内存/`/data/local/tmp` 内，不碰系统分区、不刷 boot）：

1. 取 6.6 家族 LKM 模板（本项目里可用的是 KMRoot APK 内 `payload/kernelsu.ko`，
   vermagic `6.6.127-4k-g46a034eca005-dirty`，225 个未定义符号在本内核 kallsyms 中 0 缺失）；
2. `ko_patch kernelsu.ko ksu-patched.ko syms_66118.txt <slide> "6.6.118-android15-8-gf17133276a57-abogki518694926-4k"`
   → 期待输出 `PATCHED=225 MISSING=0`；
3. `ksud insmod ksu-patched.ko`（或对应 flavor 的 loader）；失败时看
   `dmesg | grep -iE 'kernelsu|vermagic|unknown symbol|disagrees|Key was rejected'`。
4. manager 必须与 LKM 同源（KMRoot 内为 KernelSU 官方 `me.weishu.kernelsu`）。

> `syms_66118.txt` 的地址是**链接期地址**，`ko_patch` 会加运行期 slide；slide 由 98260 链运行期测得。
> 该文件只对 **本构建**（`gf17133276a57/518694926`）有效，换 build 必须用 §2 的 `gen_profile.py` 重生成。

## 4. 设备端验证顺序（只读 → 灰盒 → 单次；本任务未执行）

先决条件：自有设备、已备份、清楚 `PANIC_ON_OOPS=y`（常量错一次就是 panic + 长按电源）。
按 `../REPORT.md` §8 执行：`uname -r` 精确匹配 → `/proc/slabinfo`、`/proc/iomem`、`/proc/cmdline` 只读采集 →
`--check --quick` → slide 只读探测 → 干净重启后一 boot 一样本跑 plant。出现 `miss` 只重启，**绝不 kill plant**。

## 5. 回滚 / 恢复

本方案不改 boot、不改系统分区；崩溃/异常的正确处置是 **重启设备**（不要 kill 进程），
不留持久修改。若使用 KSU late-load 失败，删除 `/data/local/tmp` 下的临时 KO/ksud 即可，
不影响系统完整性。
