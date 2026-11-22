# SukiSU Nova（com.sukisu.nova）支持与符号表补全

日期：2026-11-16

## 1. 失败日志结论

2026-11-16 08:10 的两次 98260 运行（boot `ce0536e7-…`）失败原因不是
UAF/real-cred 本身，而是管理器身份与符号表不匹配：

```text
98260_MANAGER_PRESENT=1 package=com.sukisu.nova
98260_KSU_PATCH_RC=0 missing=23 flavor=fina profile=g142 template=ko-fina.ko
98260_SYMS_RUNTIME=unavailable reason=no_root_kallsyms waited=6s
98260_KSU=failed reason=ko_patch
98260_CHAIN_END=ROOT_OK_KSU_FAIL code=82
```

- `com.sukisu.nova` 是 **SukiSU Nova v3.0.0**（versionCode 30000），不是
  FinaSU。App 的“其它已安装管理器”路径只记录了包名，却沿用上一次选择的
  `flavor=fina`；runner 因此用 Nova 自己的 LKM（`ko-fina.ko`，vermagic
  `6.12.76-4k`）去配 `syms_g142_fina.txt`。
- Nova/FinaSU 1.6.3 内嵌的 6.12 LKM 字节相同（SHA-256
  `31603945662b440f4e51e07ed82aa1c88ec301ddf2012fff7b30fc925e18d16a`），
  它比现有符号表多引用 8 个符号。
- real-cred 路线在 `finit_module` 前没有 rootd，`kptr_restrict=2` 下
  uid 2000 也读不到 `/proc/kallsyms`，运行时补符号在该路线结构性不可用。
  因此必须在表里静态补齐。

### FinaSU 1.6.3 的 KO 检查

用 FinaSU 1.6.3 APK 的 ksud 提取：

```text
ksud debug extract-binary android16-6.12_kernelsu.ko fina-612.ko
```

得到的 6.12 LKM 与 Nova v3.0.0 的完全一致（同一 SHA-256），对旧的
`syms_g142_fina.txt` 同样 `MISSING=8`。所以“换回 FinaSU”并不能绕开这个
缺口。

App 现有的 raw-deflate carver 不识别 FinaSU 1.6.3 的容器，提取失败时会
回退到内置 `ksu-template-fina.ko`；该内置模板对旧表是 `MISSING=0`，但它
不是 1.6.3 的新 LKM。

2026-11-16 已实现自动提取：`extractManagerLkm` 在内置模板回退之前，对
`fina`/`nova` 执行管理器自己的

```text
ksud debug extract-binary android<kmi>_kernelsu.ko <absolute-path>
```

校验 ELF magic、KMI vermagic 和文件大小后，直接落到
`ko-<flavor>.ko`。因此 FinaSU 1.6.3 的 6.12.76 LKM 会自动与补齐后的
`syms_<profile>_fina.txt` 配对，不再退到旧内置模板。

第二次运行（08:10:59）不是新失败：第一次运行留下 armed victim，guard 按
设计拒绝同 boot 再 plant：

```text
98260_unproven_victims_reboot_required count=1
```

## 2. 缺失符号

对 Nova 的 6.12 LKM 逐项跑 `ko_patch`，所有 6.12/6.6/6.18 profile 的共同
缺口是同样 8 项：

```text
init_user_ns
cap_capable
inode_owner_or_capable
audit_log_start
audit_log_format
audit_log_n_untrustedstring
audit_log_end
security_validate_transition
```

地址来源必须是**该 kernel build 的精确镜像/kallsyms**，不能用相邻版本或
型号猜。本轮使用的来源：

| profile | kernel build | 来源 |
| --- | --- | --- |
| g142 | 6.12.58 g142ddad31e60 | `g142-kernel.elf` / `build/kallsyms/g142.txt` |
| 61258 | 6.12.58 g3a7ac1674240 | MLY-AN00 11.0.0.106 boot.img，`ExportKernelKallsyms` |
| 61258c | 6.12.58 g42fcf008ff5c | `61258c-vmlinux.iUt2Ye/vmlinux.elf` |
| g856 | 6.12.23 gcd85666d7884 | `g856-vmlinux.uSlbgi/vmlinux.elf` |
| 6138 | 6.12.38 gfde7767f6ef6 | Magic8 BKQ-AN00 10.0.0.170 boot.img |
| g554 | 6.6.118 g554929766a0d | `g554-vmlinux.QXXiUr/vmlinux.elf` |
| f171 | 6.6.118 gf17133276a57 | `f171-vmlinux.UF8yV8/vmlinux.elf` |
| 6689 | 6.6.89 g082e5a98dac1 | `6689-vmlinux.PjZ6Ks/vmlinux.elf` |
| 6658 | 6.6.58 g6484937db664 | PPG-AN00 9.0.0.112 boot.img |
| ga812 | 6.6.118 ga812a1946391 | `build/kallsyms/ga812.txt` |
| g893 | 6.6.118 g893e848657cc | `boot_ota_1794139884130.img`，`ExportKernelKallsyms` |
| 61821 / 117 | 6.18.21 | 现有完整表已包含这 8 项（MISSING=0） |

每个 profile 还先做了 donor 校验：表内已有符号与精确镜像重叠 266/266，
地址差异 0，才把 8 项写入。写入后该 profile 的每张 flavor 表都是
“五张表并集 + 8 项”（274 行），`ko_patch` 对 Nova LKM 为
`MISSING=0`。

## 3. Nova flavor

App 与脚本现在把 `com.sukisu.nova` 识别为独立 flavor：

```text
flavor      nova
package     com.sukisu.nova
label       SukiSU Nova
uapi        6
syms        syms_<profile>_nova.txt（仅精确来源的 profile）
LKM         始终从已安装管理器 APK 提取；无内置 nova 模板
```

- Nova 的 `libmtcytvztgb.so`（随机名）由现有“最大 arm64 .so”探测提取，
  `lib/arm64-v8a/libksud.so` 不存在时仍能拿到 ksud/LKM。
- 不把 Nova 归为 FinaSU：`flavorForPackage()` 现在把
  `com.sukisu.nova` 映射到 `nova`，选择该管理器会切换 backend。
- 无 nova 表的 profile 走 `ksu_select_ko()` 的 fail-closed：缺表时
  `FLAVOR_SYMS_MISSING=1`，不会借用其他内核的地址。

已提供 nova 表的 profile：

```text
61258 61258c g856 6138 g142
g554 f171 6658 6689 ga812 g893
```

暂未提供（本机没有精确镜像，donor 重叠校验不通过）：

```text
61258b / aph112（6.12.58 g459a4285ccf8）
6138y（6.12.38 g7ae8ec909e03）
6123（6.12.23 g45ea5e4bce8a）
61821brm（6.18.21 ge186062ea75f）
```

这些 build 上选 Nova 会在 `ko_patch` 阶段因缺符号失败，不会加载错误模块。
6.1.x 走运行时 kallsyms 路线，本轮未把 Nova 的 6.1 LKM 做静态补全。

## 4. 验证

```text
ko_patch <nova-6.12.76.ko> <out> syms_g142_nova.txt <slide> <kernel>
PATCHED=249 MISSING=0

ko_patch <nova-6.12.76.ko> <out> syms_<profile>_nova.txt ...
每个已支持 profile 均 MISSING=0
```

`bash tools/check.sh` 的资产注册对账、SHA256SUMS、dedup、
`audit_kernel_flavors.sh`、`test_61128_adaptation.py`、`test_init_cred_patch.py`、
`test_runtime_syms.py` 均通过；APK 需要重新构建后才会通过包内资产逐字节
校验。

## 5. 真机注意事项

- 2026-11-16 08:12 的第三次运行在 Nova 表补齐前执行：real-cred 与
  CAP_SYS_MODULE 已成功，但 KSU patch 仍失败；留下
  `/data/local/tmp/.magicroot-unproven`（当前 boot `cefc53a1-…`，3 个
  unproven victim）和 PPID=1 的 exploit 父进程。
- **必须重启**后才能再次运行；不要 kill PPID=1 的父进程，不要在同 boot
  再触发 UAF。当前 SELinux 仍为 Permissive，重启后恢复 Enforcing。
- 新 APK 安装并重新部署后，预期日志：
  `98260_KSU_PATCH_RC=0 missing=0 flavor=nova` →
  `98260_REAL_CRED_KO_READY` → `98260_REAL_CRED_INPROC_OK=1`。
- 管理器注册/`su` 仍需真机复验；本文件不把未跑过的路径写成已验证。
