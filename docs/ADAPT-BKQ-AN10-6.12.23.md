# BKQ-AN10 / 6.12.23 适配说明（实验）

## 目标镜像

- 设备：BKQ-AN10
- 固件：10.0.0.110(SP5C00E109R101P7)_Firmware_MagicOS 10.0_0501AHNY
- boot.img：Android boot image v4，4K pages，kernel_size=39815680
- 内核：`6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k`
- 编译：`#1 SMP PREEMPT Mon Sep 22 10:54:53 UTC 2025`
- Image SHA256（解压后）：`065a777a85600c06cb6424d409ea8e3b04a7440a9a475442b6ca48f921267a41`

## 推导结果

从 boot.img 解压 Image，并用 vmlinux-to-elf 提取 126,140 个 kallsyms；从 Image 提取 BTF（6.98 MB）确认结构偏移。

### 98260

- `LINK_SELINUX_STATE = 0xffffffc082656570`
- `LINK_INIT_USER_NS  = 0xffffffc0823f1360`
- `LINK_ROOT_USER     = 0xffffffc0823f15d8`
- `LINK_INIT_GROUPS   = 0xffffffc0823f2aa0`
- `LINK_INIT_UCOUNTS  = 0xffffffc0823f2f70`
- `LINK_ALLOC_TIMER   = 0xffffffc080cbb390`（do_timer_create 内）
- `LINK_ALLOC_CRED    = 0xffffffc080cec86c`（prepare_creds 内）
- task_struct：cred=0x900 / real_cred=0x8f8 / comm=0x910
- cred：size=0xb8，uid=0x8，cap_effective=0x40，security=0x80
- k_itimer：size=0x100，it/node=0x78
- `GEOM_MEMSTART_ADDR = 0xffffffc0817e4638`，`GEOM_MEMSTART_PFN=0x80000`

已生成 `98260-6123/exploit-android-key-ptr`（SHA256 `3a0a03e2...`）及 App 资产。

### 64560

- KASLR anchors（6.12.23 函数入口）：
  - worker_thread `0xffffffc080b350b0`
  - rcu_gp_fqs_loop `0xffffffc080ee7564`
  - rcu_gp_kthread `0xffffffc080ee6888`
  - folio_wait_bit_common `0xffffffc0801dff08`
  - ufshcd_issue_dev_cmd `0xffffffc080eaef00`
  - icc_set_bw `0xffffffc080b06330`
- `PREPARE_CREDS = 0xffffffc080cec840`
- `SELINUX_STATE = 0xffffffc082656570`
- 5 个 flavor 的 `syms_6123*.txt` 已从各 LKM 的 undefined symbol 与 6.12.23 kallsyms 生成，缺失 0。
- `kaslr_slide_6123` 已编译并打包。

## 验证边界

已完成：

- 内核版本识别
- Image/kallsyms/BTF 提取
- 98260 target header 编译
- 64560 KASLR 与 syms 生成
- App/legacy APK 打包
- audit：`PASS_WITH_WARNINGS`，fail=0

**尚未完成**：

- 没有 BKQ-AN10 运行该 6.12.23 内核的实机；未做真实 UAF/KSU 运行验证。
- 98260 的 `GEO_TASK_OBJSIZE` 会在运行时由 `/proc/slabinfo` 校正；其余 slab 几何沿用 6.12.58 值，需实机确认。
- 64560 的 KASLR anchor 基于同一 blocked_reason 观测函数集合，需实机抓取 `bl_text.txt` 确认 votes/anchors 达到阈值。
- KSU LKM 模板为 6.12 KMI 模板，需验证 6.12.23 vermagic/sym 重定位后的模块加载。

## 风险提示

在 BKQ-AN10 6.12.23 上首次运行前，先只跑 KASLR_ONLY 和 98260 `--check`，并保留 pstore/完整 run.log。不要直接反复尝试 UAF。

## 1.0.5 资产部署问题与修复

`prev-run` 中的 `FAIL=kernel_unsupported actual=6.12.23...` 说明运行时
`kernel_profiles.sh` 没有 6.12.23 profile，并非 UAF 阶段失败。

原因：

1. 新增 `98260-6123` 资产后，部署代码只识别 `98260` 与 `98260-6138`；
   `98260-6123/foo` 被错误映射到 `98260/6123/foo`，目录不存在。
2. legacy 部署仍保留同尺寸跳过，APK 更新后可能继续使用旧
   `run.sh`/`kernel_profiles.sh`。
3. 若测试的是加入 6123 profile 之前的 APK，则必然出现
   `kernel_unsupported`。

修复：

- 按资产前缀自动创建并映射三个 98260 目录；
- legacy 移除同尺寸跳过，改为始终覆盖；
- `run.sh` 的 `kernel_unsupported` 增加 `DEPLOYED_PROFILE_6123` /
  `DEPLOYED_RUN60_6123` 诊断。
