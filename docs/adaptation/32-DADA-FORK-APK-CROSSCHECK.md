> **2026-10-29 修正（boot image 已核验）**  
> g554 的真实 `prepare_creds=0xffffffc080238438`，call site 是 `0xffffffc080238458`。  
> 本文下方曾按 BRM 改成 `0x80038458`，那是 BRM `ge186` 的地址，不适用于 g554。  
> 已回退；详见 `34-66118-BOOT-VERIFY.md`。

# dada-cve / GhostLock APK 对照报告

日期：2026-10-29

## 1. 仓库与上游

- Fork：`nisu123f/dada-cve-AN00`
- 上游：`wushidia/dada-cve`
- Fork 默认分支：`main`
- Fork 最新提交：
  - `1393990` Fix off-by-4 trace call-site constants for Honor AAK-AN00
  - `4715308` Port CVE-2026-98260 payload to Honor AAK-AN00
  - `3f9191c` Sync app payload with the standalone source（上游）
- 上游最新提交：
  - `3f9191c` Sync app payload with the standalone source

Fork 相对上游只有 3 个文件变化：

```text
kernel/cve-2026-98260.c
app/third_party/cve-2026-98260/cve-2026-98260-uid0.c
app/app/src/main/assets/cve98260/cve-2026-98260-uid0
```

最新提交 `1393990` 明确说明：

> source only; payload asset is not rebuilt in this commit.

因此 fork 的**源码是修正版，资产二进制不一定同步**。

## 2. Fork 的移植内容

目标：

```text
Honor AAK-AN00 / MagicOS 11 / Android 17
Kernel 6.6.118-android15-8-g554929766a0d-abogki544555896-4k
```

关键常量：

```text
CRED_SITE_LOW21      0x38458    prepare_creds+0x20  (BL+4)
TIMER_SITE_LOW21     0x1afcec   do_timer_create+0x94 (BL+4)
STATIC_TIMER_SITE    0xffffffc0803afcec
TASK_ALLOC_LOW21     0x1cb240   copy_process+0x144   (BL+4)
TASK_ALLOC_BYTES     0x12c0
SELINUX_STATE        0xffffffc0823ba418
PANIC_ON_WARN        0xffffffc08216ae0c
ROOT_USER            0xffffffc08218f228
INIT_USER_NS         0xffffffc08218ef98
INIT_UCOUNTS         0xffffffc082190cf8
INIT_GROUPS         0xffffffc082190788
```

提交 `4715308` 一开始用了 **BL 指令地址 +4 两次**：

```text
do_timer_create+0x98 / 0x1afcf0
prepare_creds+0x24  / 0x3845c
copy_process+0x148  / 0x1cb244
```

导致 tracepoint 的 `_RET_IP_` 匹配为 0；`1393990` 改回 **BL+4 返回值**：

```text
+0x94 / 0x1afcec
+0x20 / 0x38458
+0x144 / 0x1cb240
```

这是本次最重要的方法论修正：**kmem trace 的 call_site 是 `BL` 的下一条指令地址，而不是 `BL` 本身**。

## 3. 与本地 6.6.118 对照

本地有两个 6.6 profile：

```text
98260-f171  kernel ...gf17133276a57...
98260-g554  kernel ...g554929766a0d...
```

按内核 release 一致即可通用的原则，本地 g554 与 fork AAK g554 应使用同一组链接地址。逐项对比：

| 项 | 本地 PTP g554 | Fork AAK-AN00 g554 |
|---|---|---|
| do_timer_create site | `0xffffffc0803afcec` | 同 |
| copy_process site | `0xffffffc0801cb240` | 同 |
| prepare_creds site | `0xffffffc080238458`（boot 实测） | `0xffffffc080038458`（BRM ge186） |
| task_struct bytes | `0x12c0` | 同 |
| selinux_state | `0xffffffc0823ba418` | 同 |

boot 实测本地 g554 是 `0xffffffc080238458`；BRM 的 `0x80038458` 属于 ge186，不适用于 g554。

本地 g554 的 `syms_66118.txt`：

```text
prepare_creds 0xffffffc080238438
```

与修正后的 header `+0x20 -> 0xffffffc080038458` 自洽。syms 已同步为 `0xffffffc080038438`。

因此：

- **同 kernel release 应通用**，不需要按 AAK/PTP 拆 profile；
- 原冲突已在本地按参考修正为 `0x38458`；同 kernel release 不按机型拆分；
- timer/task/selinux 原本就一致；cred 已按参考修正，后续仍需 g554 真机 trace 验证；
- 修正已写入本地 header、syms 和 payload；未验证前不要再用旧 `0x238458` 资产。

### off-by-4 对照

本地 g554 header：

```text
do_timer_create+0x94   -> 0x1afcec
prepare_creds+0x20     -> 0x038458
copy_process+0x144     -> 0x1cb240
```

这与 fork 修正后的 `BL+4` 语义一致；本地没有重复加 4。

## 4. 上传 APK 拆解

```text
base(2).apk
size   22,393,412
sha256 5de0a9a53487d22204efbf6746a622ff8554a0492a89d838118cb6afae75a2e3
package com.ghostlock.app
versionCode 5 / versionName 1.3
label GhostLock
```

主要资产：

```text
assets/cve98260/cve-2026-98260-uid0      460,344 B
assets/cve98260/cve-2026-98260-android   33,528 B
assets/cve64560/cve-2026-64560-fanout    94,096 B
assets/cve64560/cve-2026-64560-rotate    94,288 B
assets/cve64560/cve-2026-64560-su        8,888 B
lib/arm64-v8a/libextract.so              2,463,080 B
lib/arm64-v8a/libghostlock.so              426,840 B
assets/kernel_profiles/                  多套 5.x/6.x profile
```

`cve-2026-98260-uid0` 字符串：

```text
[+] target: CVE-2026-98260 uid-0 (Honor AAK-AN00, 6.6.118)
```

说明 APK 的 payload 是 **AAK-AN00 g554 移植版**，不是 MLY 6.12。

但 APK 的 `kernel_profiles/index.conf` 中 **没有 g554929766a0d profile**；只有：

```text
6.6-template.conf (各字段 null)
6.6.118-... 其他 commit build
```

所以 GhostLock 不能在 g554 上自动选 profile；`6.6-template.conf` 只是结构模板，字段全是 `null`，需要手动导入/生成 offset。

APK 的 `-android` payload 是上游 AIO-ring 变体；fork 源码注释明确说该变体在 6.6.118 上 stage1 找不到 timer 对象，仅保留参考。真正可用的是 `-uid0`。

APK 是完整的 Shizuku/root 管理器，不是我们 `rootd + KernelSU late-load` 链，不能直接替换本地资产。

## 5. 可落地结论

1. 本地 g554 boot 实测 `prepare_creds=0x238458`（BL+4）；已恢复原 payload/syms，BRM ge186 单独 profile。
2. 吸收 fork 的 **BL+4 语义**；本地 header 已经是正确形式。
3. **不按机型拆 profile**；同 kernel release 通用。
4. 仍需 g554 真机 `--check`/trace matches 验证；boot 地址已确认。
5. GhostLock APK 的 AAK g554 payload 只作参考样本；没有 g554 profile，且后端不是我们的 rootd 链。
6. 本地 g554 仍未在 6.6 真机验证；不要因为 fork 源码提交就替换常量。

## 6. 验证边界

- 本地没有 g554 真机；
- 没有执行 fork payload 或 APK payload；
- 没有重建 6.6.118 测试包；
- 常量差异来自源码、本地 header/syms 和 APK 二进制字符串，仍需 g554 `--check` 与 trace 验证。
