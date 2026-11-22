# 6.6.118 boot.img 静态适配摘要

输入：`boot(1).img`（100,663,296 B，sha256 `3dacd60d...ff4e`）。
内核：`6.6.118-android15-8-gf17133276a57-abogki518694926-4k`，KMI android15-8，4K。
OEM：Honor AAK（vbmeta `AAK-LGRP1-CHN 10.0.0.175(SP1)`，指纹 qti/sun/sun:15），不是 ColorOS/OPPO。
boot header v4，kernel 37,128,704 B，ramdisk=0，分区 vbmeta @0x236E000，AVB footer @0x5FFFFC0，SHA256_RSA4096。

## 结论

- CVE-2026-98260 UAF 前提在该内核静态成立：
  `begin_new_exec` 内 `release_task(+0x3ec) -> exec_mmap down_read_killable(+0x508) -> posix_cpu_timers_exit(+0x6ac) -> exit_itimers(+0x6bc)`。
- `k_itimer=264 B`，与 ColorOS 17 6.6.x APK 的 slab 几何假设一致。
- 但 ColorOS APK 目标 build 是 `...-g9bc34d5b0c79-abogki537459655-4k`，与本 boot `...-gf17133276a57-abogki518694926-4k` 不同构建；APK 内嵌符号/常量不可照抄。
- 已完成本构建的静态适配：完整符号表、call-site 常量、BTF 几何、`pc98260_target_66118.h`、`profile-66118.json`、`syms_66118.txt`，以及 NDK 编译的 `exploit-android-key-ptr-66118`（未上机）。
- 不改 boot 分区：OEM AVB 私钥不可得；任何改动 boot 均无法通过 AVB。方案仍是 UAF 提权 + KSU LKM 临时加载。
- 6.12 KSU 模板不能直接用于 6.6（缺 noprof 等符号）；需要 6.6 KMI 的 LKM 并用 kallsyms/ko_patch 处理。

## 产物

见 `binary-sources/66118/`：
- `pc98260_target_66118.h`
- `profile-66118.json`
- `syms_66118.txt`（225 符号，0 缺失）
- `build/exploit-android-key-ptr-66118`、`build/pc98260-su-66118`
- `build/*.c` 源码与可复现脚本
- `PATCH-NOTES.md`

完整取证与报告：`work/adapt-66118/boot/REPORT.md`、`BOOT-HEADER.md`、`EXTRACT/`。
风险：`PANIC_ON_OOPS=y`、KASAN/KFENCE/UBSAN/CFI 全开；`GEO_TASK_OBJSIZE`、`GEOM_MEMSTART_PFN` 需设备只读复核；未上机验证，禁止直接刷写。
