# YLP-W00 / 6.12.38 适配说明（实验）

## 目标镜像

- 设备：YLP-W00
- 固件：10.0.0.137(SP8C00E140R102P1)_Firmware_MagicOS 10.0_0501AHWD
- boot.img：Android boot image v4，4K pages
- kernel_size=39881216
- 内核：`6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k`
- 编译：`#1 SMP PREEMPT Sun Dec 21 12:01:05 UTC 2025`
- 解压 Image SHA256：`92b882b87cd5efc5087985d64e1875f3881f9ec837f97df344ba2e8006a0a414`

## 98260

新 profile 目录：`98260-6138y`

- `LINK_SELINUX_STATE = 0xffffffc0826663c8`
- `LINK_INIT_USER_NS  = 0xffffffc082401568`
- `LINK_ROOT_USER     = 0xffffffc0824017e0`
- `LINK_INIT_GROUPS   = 0xffffffc082402ca8`
- `LINK_INIT_UCOUNTS  = 0xffffffc082403178`
- `LINK_ALLOC_TIMER   = 0xffffffc080d99ef0`
- `LINK_ALLOC_CRED    = 0xffffffc080b89dc4`
- `GEOM_MEMSTART_ADDR = 0xffffffc0817fa5b8`
- BTF：task/cred/k_itimer 偏移与 6.12.58 相同
- `exploit-android-key-ptr` SHA256：`174aaa3cdedcf2e11b7e609b00ceb7ed5d0725618ea531e0c1a46ac180343c77`

## 64560

- `PROFILE_ID=6138y`
- `KASLR_BIN=kaslr_slide_6138y`
- `PREPARE=0xffffffc080b89d98`
- `SELINUX=0xffffffc0826663c8`
- KASLR anchors：
  - worker_thread `0xffffffc080ad8138`
  - rcu_gp_fqs_loop `0xffffffc080cccdc0`
  - rcu_gp_kthread `0xffffffc080ccc1d8`
  - folio_wait_bit_common `0xffffffc0801830b8`
  - ufshcd_issue_dev_cmd `0xffffffc080ef0e48`
  - icc_set_bw `0xffffffc080a95e60`
- `syms_6138y*.txt` × 5 flavor，LKM undefined symbol 缺失 0

## 资产部署与 root-owned 目录

参考 `docs/DEVICE-VERIFY.md` §55：root/root 755 的旧工作目录会让 uid 2000 无法覆盖，旧资产仍被误报为部署成功。

1.0.5 的加固：

- `ensureWorkDirWritable()`：不可写时先 `mv`，失败再 `rm -rf`，然后重建 771；
- 新增 `ensureStageDirWritable()`：`98260-*` 子目录若 root-owned 不可写，单独轮换 `.old.<ts>`;
- 部署前删除 root-owned 旧目标与 `.new` 临时文件；
- Compose 与 legacy 都使用同一套检查；
- legacy 不再同尺寸跳过；
- 部署目录自动按 `98260*` 前缀创建，不再只识别固定两个目录。

## 验证边界

已完成：

- 内核版本/链接/BTF 推导
- 98260 target header 与资产
- 64560 KASLR/syms/profile
- APK/legacy 打包
- audit：`PASS_WITH_WARNINGS`，fail=0

尚未完成：

- 没有 YLP-W00 实机验证；
- 64560 KASLR 需实机 `bl_text.txt` 达到 votes≥3、anchors≥5；
- KSU LKM 的 6.12.38 YLP vermagic/sym 重定位需实机加载确认；
- 98260 的 slab 几何仍需 `/proc/slabinfo` 校正。

首次运行前建议先只验证部署和 KASLR：

```text
ASSET_SYNC=ok
KASLR_CROSS_CHECK=ok ...
KASLR_ACCEPTED slide=... votes=... anchors=...
```
