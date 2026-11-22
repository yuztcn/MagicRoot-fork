# BOOT-HEADER.md — boot(1).img 静态解包报告（header / 布局 / AVB）

> 目标文件：`work/adapt-66118/boot/boot(1).img`
> sha256：`3dacd60da1d8faa7e2548d22dbdd4fcc254d8892aa35d106c2aa6b632fcbff4e`
> 大小：100,663,296 字节 = 0x6000000 = 96 MiB（A/B `boot` 分区镜像）
> 工具：自写 Python 按 AOSP `bootimg.h` v4 + AVB 规范解析（`parse_boot.py`、`repack_boot.py`），本机无 Android SDK；
> Python 3.14.6，pyelftools 0.33、capstone 5.0.7。所有操作只读原文件，副本只写本目录。

## 1. 结论速览

| 项 | 值 |
|---|---|
| magic | `ANDROID!`（0x00000000） |
| header_version | **4** |
| header_size | 1584（0x630） |
| page_size（规范固定） | 4096 |
| kernel_size | 0x2368A00 = **37,128,704** 字节（原始 arm64 `Image`，非压缩） |
| ramdisk_size | **0**（GKI 形态：ramdisk 在 `init_boot`/`vendor_boot`，本文件不含） |
| boot v4 signature_size | **0** |
| os_version | **0**（未写；实际 Android 版本来自 vbmeta property，见 §3） |
| cmdline | 空（纯 GKI；bootconfig/cmdline 在 `vendor_boot`，未提供） |
| kernel 偏移 | 0x1000（第一页为 header） |
| kernel 结束 | 0x1000 + 0x2368A00 = 0x2369A00 |
| 内容按页对齐结束 | 0x236A000 |
| boot signature 区 | 0x236A000 – 0x236E000（16 KiB，2 × AVB0 meta 2240 B + 零填充） |
| 分区 vbmeta（AVB hash footer） | 0x236E000 – 0x236E9C0（2496 B，SHA256_RSA4096） |
| 零填充 | 0x236E9C0 – 0x5FFFFC0 |
| AVB footer | 0x5FFFFC0 – 0x6000000（最后 64 字节） |
| 原镜像（footer 记录） | original_image_size = vbmeta_offset = 0x236E000 = 37,150,720 |
| AVB 算法 | SHA256_RSA4096（`algorithm_type=2`），rollback_index=0，flags=0 |

**无损重打包验证**：按上述字段重新拼装得到的镜像与原文件 **逐字节一致**
（`repack_boot.py` → `PATCHED/boot-repack-identical.img`，sha256 同为 `3dacd60d…ff4e`）。
这证明对 header/布局的理解是准确的，也给出了将来任何重打包所需的精确参数。

## 2. boot v4 header 字段表（按 AOSP `boot_img_hdr_v4`）

结构（小端）：
```c
struct boot_img_hdr_v4 {
    uint8_t  magic[8];              // "ANDROID!"
    uint32_t kernel_size;
    uint32_t ramdisk_size;
    uint32_t os_version;
    uint32_t header_size;
    uint32_t reserved[4];
    uint32_t header_version;
    char     cmdline[1536];
    uint32_t signature_size;        // 仅 v4
};
```

| 偏移 | 长度 | 字段 | 原始字节 | 解释值 |
|---|---|---|---|---|
| 0x0000 | 8 | magic | `41 4e 44 52 4f 49 44 21` | `ANDROID!` |
| 0x0008 | 4 | kernel_size | `00 8a 36 02` | 37,128,704 (0x2368A00) |
| 0x000C | 4 | ramdisk_size | `00 00 00 00` | 0 |
| 0x0010 | 4 | os_version | `00 00 00 00` | 0 |
| 0x0014 | 4 | header_size | `30 06 00 00` | 1584 |
| 0x0018 | 16 | reserved[4] | 全 0 | — |
| 0x0028 | 4 | header_version | `04 00 00 00` | 4 |
| 0x002C | 1536 | cmdline | 全 0 | 空 |
| 0x062C | 4 | signature_size | `00 00 00 00` | 0 |
| 0x0630 | — | header 结束（1584 B），余下到 0x1000 为 0 | — | — |

页对齐规则（AOSP）：header 占 1 页（4096 B）；kernel 从 0x1000 开始；ramdisk 紧接 kernel 按页对齐
（此处 ramdisk_size=0 → 偏移 0x236A000）；v4 signature 紧随 ramdisk 按页对齐（size=0）。
本镜像在 signature 之后还有 OEM 追加的 16 KiB boot-signature 与该分区的 vbmeta——这段不属于
mkbootimg header 描述范围，由 AVB/厂商流水线追加。

## 3. 内容识别（boot 镜像内部可见的构建元数据）

### 3.1 16 KiB boot signature 区（0x236A000 起，2 个 AVB0 meta）

| # | 文件偏移 | 大小 | AVB 算法 | 公钥 sha256 前 16 | hash 描述符 image_size | 关键 property |
|---|---|---|---|---|---|---|
| 1 | 0x236A000 | 2240 (0x8C0) | SHA256_RSA4096 | a765081aa62a077d… | 37,134,336 (0x236A000，= mkbootimg 产物全长) | `ARCH=arm64`、`BRANCH=`、`KERNEL_RELEASE=6.6.118-android15-8-gf17133276a57-abogki518694926-4k` |
| 2 | 0x236A8C0 | 2240 (0x8C0) | SHA256_RSA4096 | c6cf3af371ec34ce… | 37,128,704 (= kernel_size，即裸 Image) | 同上 |

- blob#1 的 `blob_sha256 = c880d625e78a369e7f9644a6309da55ccce4bf9e75bc94e4833c9c6cd25e0c16`
- blob#2 的 `blob_sha256 = 5f1819f7824d34dcd51b2323cfb6f71e7f376bf3cf3141213fc4bf05140aa15a`
- 这是 GKI/高通流水线追加的「boot signature」双签名：一份覆盖 mkbootimg 产物，一份覆盖裸 kernel
  Image，供 bootloader 校验内核来源（KERNEL_RELEASE 属性里即是本内核 UTS release）。

### 3.2 分区 vbmeta（AVB hash footer，0x236E000，2496 B）

- 头部：`AVB0`，major=1/minor=0，auth=576、aux=1664（合计 2496），algorithm=SHA256_RSA4096。
- 公钥：`pubkey_sha256 = c6e46281f43f33a3dacc51b7acf44c2c5a3ff19e1b74223f4dd5c4a859edce84`（OEM 4096-bit RSA，私钥不在本项目内）。
- hash 描述符：`image_size = 37,150,720 (0x236E000)`、`hash_algorithm = sha256`、`partition_name = boot`；
  描述符内嵌 32 字节 `e8ce5dbf…6f9c79` —— **正好等于本镜像内 kernel Image 的 sha256**，
  另含 32 字节 `7282d6c0…7903e` 摘要字段（avbtool 1.3.0 的 hash 描述符尾部字段顺序未在本机复刻，
  原始 body 已完整保存到 `EXTRACT/avb-layout.json`，可交给 avbtool 复核）。
- property 描述符（vbmeta 内置的构建元数据，**识别设备/版本的主要证据**）：

| property | 值 |
|---|---|
| `com.oem.base_version` | **`AAK-LGRP1-CHN 10.0.0.175(SP1)`** |
| `com.android.build.boot.os_version` | `15` |
| `com.android.build.boot.fingerprint` | `qti/sun/sun:15/AQ3A.250214.001/eng.root.00000000.000000:user/release-keys` |
| `com.android.build.boot.security_patch` | `2026-08-01` |

- vbmeta 原始 sha256：`dd9e4efd610f1added3b54903d4979f81dc1693bcab4c030fe4ca19ff23a6315`
- AVB footer（最后 64 字节，大端）：magic `AVBf`、version 1.0、original_image_size=0x236E000、
  vbmeta_offset=0x236E000、vbmeta_size=2496、reserved 全 0。

### 3.3 由 vbmeta 元数据得出的设备判断

- `qti/sun/sun:15` → 高通（qti）+ `sun` 平台（SM8750 家族，Snapdragon 8 Elite）+ Android 15 基线；
- `AAK-LGRP1-CHN 10.0.0.175(SP1)` → 厂商 base version，`AAK` 与 Honor 设备代号体系
  （对比本项目 6.12 参照：Magic8 Pro = `BKQ-LGRP1-CHN 11.0.0.110(SP4)`）一致；
  公开资料把 `AAK-AN00` 指为 Honor WIN RT 机型（外部旁证，非本镜像自证；
  <https://github.com/hui191/cve-2026-43499-aak-an00>）；
- kernel 内嵌 config 有 26 个 `CONFIG_HONOR_*`（见 REPORT.md §2），无任何 OPLUS/OPPO/OnePlus/MTK 化配置
  → 这是 **Honor（MagicOS）OEM 内核**，不是 ColorOS/OPPO 的 boot；
- `com.android.build.boot.fingerprint` 的 `eng.root` / `00000000` 字段是 Honor（基于高通 LAA 基线）
  boot 镜像流水线的固定写法；参照 Magic8 Pro 6.12.58 镜像同样如此（`qti/canoe/canoe:16/…/eng.root:user/release-keys`），
  不能据此认定这是“工程样机内核”（参见 REPORT.md §5 的对比结论）。

## 4. 与 Honor 6.12.58 参照 boot.img 的结构对比

| 项 | 本镜像 (6.6.118) | Magic8 Pro 6.12.58 (`targets/Magic8Pro-BKQ-AN90/…/boot.img`) |
|---|---|---|
| header_version / header_size | 4 / 1584 | 4 / 1584 |
| kernel_size | 37,128,704 | 41,441,792 |
| ramdisk_size | 0 | 0 |
| os_version（header） | 0 | 0 |
| cmdline | 空 | 空 |
| v4 signature_size | 0 | 0 |
| kernel 偏移 | 0x1000 | 0x1000 |
| 内容结束（页对齐） | 0x236A000 | 0x2787000 |
| boot signature 区 | 16 KiB / 2×2240 B AVB0 | 16 KiB / 2×2240 B AVB0（同布局） |
| 分区 vbmeta | 2496 B @ 0x236E000 | 2496 B @ 0x278B000 |
| AVB 算法 | SHA256_RSA4096 | SHA256_RSA4096 |
| footer 位置 | 0x5FFFFC0（96 MiB 末尾） | 0x5FFFFC0（96 MiB 末尾） |
| base_version | AAK-LGRP1-CHN 10.0.0.175(SP1) | BKQ-LGRP1-CHN 11.0.0.110(SP4) |

→ 两者出自**同一条 Honor GKI boot 打包流水线**，布局完全同构；差异仅在 kernel 大小、版本串与
  OEM 签名（公钥不同：本镜像 `c6e46281…` vs 参照 `1b20341e…`，即不同批次/设备的 AVB key）。

## 5. 复现命令（全部离线、只读）

```powershell
# 1) header + 提取 kernel/ramdisk/signature
python work/adapt-66118/boot/parse_boot.py

# 2) 内核字符串/BTF/config 侦察
python work/adapt-66118/boot/kernel_recon.py
python work/adapt-66118/boot/deep_recon.py

# 3) AVB footer + vbmeta + 16 KiB 签名区 + 无损重打包
python work/adapt-66118/boot/repack_boot.py
```

工具输出原样文件：
- `EXTRACT/boot-header.json`、`EXTRACT/boot-header-4096.bin`（header 页原始字节）
- `EXTRACT/avb-layout.json`（footer / 2 个 boot signature blob / 分区 vbmeta 全字段 + 原始 descriptor body）
- `EXTRACT/repack-evidence.txt`、`EXTRACT/repack-stdout.txt`
- `EXTRACT/gap-16k.bin`（0x236A000–0x236E000 原始 16 KiB，sha256 `331b7561…e436`）

## 6. 已知限制

1. 本文件只有 `boot` 分区内容：**没有 `init_boot`/`vendor_boot`/`vbmeta`(分区)**，因此
   bootconfig/cmdline、SELinux 初始状态、`androidboot.*` 参数、dm-verity 状态都无法从本文件得到；
   这些在下一步（设备端只读采集，或补充 vendor_boot 镜像）才能确认。
2. AVB hash 描述符尾部字段顺序按 avbtool 1.3.0 生成规则未在本机完整复刻（本机没有 avbtool）；
   但 footer/vbmeta 头部/RSA-4096/公钥/属性/大小均已确定，且无损重打包已逐字节验证。
3. header 的 `os_version=0` 不代表 Android 版本为 0：实际版本证据是 vbmeta property
   `com.android.build.boot.os_version=15`。两个值不一致是该 OEM 打包流水线的正常表现。

