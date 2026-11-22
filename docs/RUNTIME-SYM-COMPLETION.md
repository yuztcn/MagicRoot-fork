# 运行时符号补全（manager LKM 新符号）

日期：2026-11-11

## 1. 触发问题

官方 KernelSU 管理器在 2026-11-11 20:28:53 自动更新到
`v3.3.1-47-gdbb73665`（versionCode 32727）。20:31 的运行日志显示：

```text
98260_KSU_PATCH_RC=0 missing=11 flavor=kernelsu profile=g142 template=ko-kernelsu.ko
98260_KSU=failed reason=ko_patch
```

`98260-ksu.log`：

```text
TRACK_THRONE=patched track=0x6518 adrp=0x6558 ldr=0x655c rd=x0
PATCHED=225 MISSING=11 REPAIRED=0 VERMAGIC=6.12.58-...-g142ddad31e60-... SMP ...
```

新版管理器内嵌 LKM 比旧表多引用 11 个符号：
`__arm64_sys_unshare`、`sort`、`bsearch`、`bpf_get_btf_vmlinux`、
`btf_find_by_name_kind`、`btf_type_by_id`、`btf_name_by_offset`、
`btf_type_skip_modifiers`、`copy_from_kernel_nofault`、`strndup_user`、
`shmem_file_setup`。real-cred 路线不允许退回 32680 旧模板配对 32727
ksud，因此链路在 patch 阶段按设计 fail-closed，模块从未加载，管理器
自然无法注册/授权。

### 1.1 real-cred 实测：运行时补符号不可用

新 APK 安装后 2026-11-11 21:22 的运行仍失败：

```text
98260_KSU_PATCH_RC=0 missing=11 flavor=kernelsu profile=g142 template=ko-kernelsu.ko
98260_SYMS_RUNTIME_BEGIN wait=180s
98260_SYMS_RUNTIME=unavailable reason=no_root_kallsyms waited=180s
```

原因是结构性的：

- 设备 `kptr_restrict=2`，即使 SELinux 已 Permissive，uid 2000 读
  `/proc/kallsyms` 也全是 0；
- real-cred 的 rootd 只有在子进程 `finit_module` 之后才启动，而子进程要等
  runner 写出 `ksu-patched.ready` 才 finit。缺符号时 runner 永远等不到
  rootd，形成死锁。

因此运行时补符号不能作为 real-cred 的兜底；它只在 rootd 已经存在的路径
（fake-cred / 复用场景）可用。等待上限已从 180 秒改为 6 秒，避免无意义
停顿；缺符号时仍 fail-closed。

## 2. 实现

### 2.1 ko_patch

`binary-sources/64560/native/ko_patch.c`（以及同步的
`main/app/native/ko_patch.c`）新增：

1. 对仍处于 `UND` 的符号输出 `MISSING_SYM=<name>`，供运行器判断和诊断。
2. 可选第 7 个参数：`/proc/kallsyms` 转储。表内没有的符号按**完全同名**
   在转储中查找；找到后把该符号标为 `SHN_ABS`，值直接使用转储中的
   **运行时地址**（kallsyms 已经是 runtime，不能再加减 slide）。
3. 地址为 `0`（kptr_restrict 隐藏）视为未找到，绝不写入 ABS=0。
4. 每次回退输出 `KALLSYMS_FALLBACK=<name>=0x<addr>`，仍缺的继续
   `MISSING_SYM` 并计入 `MISSING=`。

六参数调用完全兼容原有测试与离线流程。

### 2.2 run98260.sh

真实 real-cred 路线在首次 patch 后：

```text
MISSING=0 → 原流程
MISSING>0 且日志有 MISSING_SYM= → runtime_symbols_retry
```

`runtime_symbols_retry()`：

1. 以 2 秒间隔等待 rootd 客户端（默认上限 180 秒，可用
   `MAGICROOT_98260_SYM_WAIT_S` 覆盖）。plant 已由 run98260 启动，root
   完成与 ready 文件无关。
2. 通过 rootd 执行临时脚本：保存 `kptr_restrict` 原值 → 置 0 →
   `cat /proc/kallsyms` 到工作目录 → 恢复原值。脚本位于
   `/data/local/tmp/magic/98260/kallsyms_dump.sh`，随工作目录清理。
3. 首行地址仍为 0（仍被隐藏）或没有 root 时，报告
   `98260_SYMS_RUNTIME=unavailable reason=no_root_kallsyms` 并保持失败。
4. 取得可读转储后，用第 7 参数重新执行 ko_patch，更新
   `PATCH_RC/PATCH_LINE/KSU_MISSING`，输出
   `98260_KSU_PATCH_RETRY=<rc> missing=<n> resolver=runtime_kallsyms`。
5. 若 plant 已 park（`missed page; holding zombie`）或进程退出，立即
   放弃等待，避免把失败拖满超时。

仍缺符号时走原来的 `98260_KSU=failed reason=ko_patch`，不伪造成功。

## 3. 验证

`tools/test_runtime_syms.py`（已接入 `tools/check.sh`）验证：

- 缺失符号名被报告；
- 带 kallsyms 转储时 `MISSING=0`，ABS 值等于 `link + slide` 的运行时地址；
- 零地址转储被拒绝，符号保持缺失；
- shell 函数在模拟 rootd 下成功重试；
- 无 root/空转储时 fail-closed。

对真实失败样本离线复验：`official-32727-original.ko` +
`98260-g142/syms_g142_kernelsu.txt`，第一次 `PATCHED=225 MISSING=11`；
带精确 g142 kallsyms 转储后 `PATCHED=236 MISSING=0`，11 个回退地址与
`build/kallsyms/g142.txt` 一致。

```text
ko_patch SHA-256
fe3f983200083767baa822d76d46d32f6aa42bb3e4419762306b894b1f6dc10c
```

## 4. 静态补全（主修复）

`tools/sync_manager_symbols.py` 把官方表缺失的 11 项从同内核的
bakasu/fina/sukisu 表补入。接受条件：

- 供体表与目标表的**全部重叠符号地址一致**（重叠至少 40 项，实际为
  219 或 226 项）；
- 所有提供该符号的供体地址必须相同；
- 不从型号或相邻内核版本猜地址。

已应用于 14 个 kernelsu 表；61821/61821brm 原本就有，6.1 不走该 LKM。

### 4.1 管理器变体实测

从官方管理器 APK 的 `libksud.so` 中提取到三个相关 KMI 变体：

```text
6.12.76-4k                        d16ce91c…（与设备上的 ko-kernelsu.ko 一致）
6.6.127-4k-g46a034eca005-dirty    35101a12…
6.18.32-4k-g47cc22554442-dirty    0666791d…
```

用它们分别 patch 对应 profile 的 kernelsu 表：

```text
6.12 变体：61258 61258b 61258c 6138 6138y 6123 g856 g142 aph112 → 236/236，MISSING=0
6.6  变体：g554 f171 6658 6689 ga812                             → 236/236，MISSING=0
6.18 变体：61821 61821brm                                         → 236/236，MISSING=0
```

### 4.2 精确 kallsyms 复核

对本地有精确镜像/导出的 10 个 profile，逐项核对整张表（237 项）：

```text
61258 61258c 6138 g856 g142 g554 f171 6658 6689 ga812
重叠 237/237，地址差异 0；新增 11 项全部与镜像一致
```

`61258b`、`aph112`、`6123`、`6138y` 本地无精确镜像，只完成供体重叠
校验（219/226 项零差异），文档标记为“未用镜像复核”。内置模板矩阵
仍为 80/80 `MISSING=0`。

## 5. 边界

- 静态补全覆盖当前管理器 32727 的 11 个新符号；未来管理器再新增符号时，
  仍需按精确 kallsyms（或同内核供体）更新各表。
- 运行时补符号只在 rootd 已存在时可用（fake-cred/复用）；real-cred 的
  rootd 在 finit 之后才启动，不能用来解缺符号死锁。
- `CRED_MODE=fake` 与用户自定义 KO 路径未接入运行时重试，缺符号时按
  原逻辑失败。
- 本机只做静态/离线验证与 APK 构建，未重新执行真机 UAF、insmod 或
  soft-reboot。下次真机运行应看到 `98260_KSU_PATCH_RC=0 missing=0`，
  不再出现 `98260_SYMS_RUNTIME` 等待。
