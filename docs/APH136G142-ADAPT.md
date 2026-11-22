# APH136 / g142 双链路与 6.12.x 98260 审计（2026-11-08）

## 1. 输入与目标

参考实现：honor_ubl 3.1.1 的 `G14264650Adapter.kt`、
`G14298260Adapter.kt` 和 `adaptation/aph136g142/`。

目标完整 release：

```text
6.12.58-android16-6-g142ddad31e60-abogki576095858-4k
```

参考报告中的输入证据：

```text
boot SHA-256    697a6356f2157665fff4926f5f4efbac08c3efcd0d20a8b08c8609ac084c5051
Image SHA-256   f445f7756756ad5c8a58b63c48b12efd69f2e829903e3f009ad2ad6bdfb17c56
BTF             6,926,113 bytes
kallsyms        129,139 recovered symbols
```

收到的参考包 SHA-256：

```text
97b1377bad0059e23b1244aac40cb3b3cd524f7c9d80b5937afdb599092aada1  honor_ubl-3.1.1-g142-kernel-adapter.zip
b75a12047c240669ca2987198d116238779706d513744a058245da7a4f0b1486  honor_ubl-3.1.1-g142-source-and-binaries.zip
8b02fe4d995ff97a5adffbc5c549ee1def036410dcb95b13b7fd1a8b09523b53  honor_ubl-3.1.1-g142-integration-source.zip
abc241c0889287e3638937007d6d7bae357ff3a7190e6bd0445307dcbc6b3292  honor_ubl-3.1.1-g142-integration.apk.1
```

MagicRoot 继续使用既有 profile id `g142`，不增加型号、BTF hash、ROM/config
hash 门禁。参考适配器的 `/data/local/tmp/hnubl-g142-*` 工作目录、`bfexec`
和 `root-command.sh` 控制通道属于 honor_ubl，本仓库不引入这些平行控制面。

## 2. 64560 接入

新增：

```text
main/app/assets/kaslr_slide_aph136g142
  SHA-256 925ecd35fda6ba70a6dafa137ae2bffcfe009f164376e2cc98888a0edf1bb5d6
binary-sources/64560/kaslr_slide_aph136g142.c
  SHA-256 ab7a3ff6b0382017e4a3296fe402132b2dae9132f04381346ff3239ebea340ef
```

该 helper 是参考包中的静态 aarch64 Android 35 可执行文件（NDK r29），源码与
现有 APH 六锚点算法同构，只使用 g142 自己的链接地址：

```text
worker_thread           0xffffffc080207bc8
rcu_gp_fqs_loop         0xffffffc08018dbfc
rcu_gp_kthread          0xffffffc08018d6f4
folio_wait_bit_common   0xffffffc0802e798c
ufshcd_issue_dev_cmd    0xffffffc080e55658
icc_set_bw              0xffffffc08037a2b8
prepare_creds           0xffffffc0801935b8
selinux_state           0xffffffc0827e7a60
```

`kernel_profiles.sh` 的 `select_kernel_profile()` 现在对完整 g142 release 返回：

- `PROFILE_ID=g142`；
- 上述专用 KASLR helper；
- 既有 `t64560_v36` / `t64560_cred`；
- 当前 Flavor 对应的 `98260-g142/syms_g142_*.txt` 与 6.12 LKM；
- `PREPARE` / `SELINUX_ARG` 二次交叉检查链接地址。

Compose 控制器把 helper 和五张符号表纳入部署，并只在 g142 上部署；
`requireCriticalAssets()` 对 64560 强制检查这些文件。`run.sh` 的权限恢复也包含
新 helper。参考包的 226 项 KernelSU 符号表已同步到
`syms_g142_kernelsu.txt`；相较旧表只补入 `init_cred`，当前内置官方模板的
225 个未定义符号仍全部解析。

## 3. 98260 校正

既有 `select_chain_98260_profile()`、`run98260.sh` 和 Java 部署筛选已经按完整
release 选择 `98260-g142`，本轮保留该路由和当前 native 生命周期/trace 修复，
不回退到参考包的旧静态 UAF 二进制。

`binary-sources/98260-6.12/pc98260_target_g142.h` 修正：

```text
LINK_ALLOC_TASK  0xffffffc0801f0d64 -> 0xffffffc0801f06e0
BNE_LINK         0xffffffc0806c82bc -> 0xffffffc0806c8c58
```

活动的 `LINK_ALLOC_TIMER=0xffffffc08051a918`、
`LINK_ALLOC_CRED=0xffffffc0801935e4` 与参考反汇编一致。当前
`uaf_plant_61258.c` 没有引用 `LINK_ALLOC_TASK` 或 `BNE_*`；这些修正属于准确的
目标资料和未来适配前提，不应描述成已改变本轮 UAF 执行路径。

修正后按既有 Termux clang 21.1.8 动态 PIE 配方重建，产物与当前资产逐字节相同：

```text
e5d4a5095bb59964a7edfd0e37aa813f341fdbf62f59c9aa0ea96c821e28141a  98260-g142/exploit-android-key-ptr
8838ab17e38252492df3761b74126855bde8a77ed5ab02255b67ebef81376ab1  98260-g142/pc98260-su
```

`su98260.c`、`rootd.c`、`stubs.c` 与参考包逐字节一致。新增
`98260-g142/SHA256SUMS.txt`，记录 payload、su、target 和五张符号表；98260 的
关键部署验收也强制检查这些文件。

## 4. 其他 6.12.x 98260 审计

覆盖以下 9 个 profile（aph112 与 61258b 同 release、按既有 APH 分支隔离）：

```text
61258 / 61258b / 61258c / aph112 / 6138 / 6138y / 6123 / g856 / g142
```

结果：

- 所有 target.sh、共享 runner、Java staging 的 release 均一致；未知构建失败关闭。
- 9 个 payload 全部可由当前目标头和共享 C 源码逐字节重建。
- 9 profile × 5 Flavor 共 45 组内置模板静态 `ko_patch` 全部
  `MISSING=0`，目标 vermagic 与各自完整 release 一致。
- 所有已存在的资产目录 `SHA256SUMS.txt` 均与实际文件一致；一键门禁现在验证
  所有此类 manifest，而不是只检查基线目录。
- `tools/audit_kernel_flavors.sh` 补上此前漏掉的 g856/g142/ga812，并在文件
  缺失或路由器报告 unsupported 时真正返回失败；新增 g142 双链路路由断言。

构建工具修正：

- `build-98260-6.12.ps1` 的 hash 表更新到当前资产；Windows NDK 与 on-device
  Termux 产物不再被错误地视为可逐字节互换。只有显式 `-VerifyRecordedHash`
  才把记录 hash 作为硬门禁。
- `build-98260-direct.ps1` 补齐全部 6.12 目标定义、真实 hash 输出和安装目录。
  旧脚本会把 6123/6138y 等错误安装到基线 `98260/`，现已修正；它仍是 legacy
  static NDK 配方，不冒充当前动态 PIE 发布产物。

这些结果证明静态路由、符号覆盖和源码/资产一致性，不证明真实 UAF/rootd/LKM
在所有 6.12.x 设备上成功。

## 5. 验证边界

参考适配报告本身明确没有连接 APH/g142 设备；本轮也没有在 g142 设备上执行
UAF、rootd、LKM 或 zygote 操作。`GEOM_MEMSTART_PFN=0x80000` 仍是参考报告标记的
静态推断，必须在目标设备复核。首次实机应先运行只读预检与 KASLR 交叉检查；
切换提权链前重启，不在同一 boot 自动重试失败的 98260。

## 6. 本轮构建与门禁

- Release 构建成功，包名/版本保持 `com.aoki.magicroot` / 12 / 1.0.5。
- 最终 APK 移除 baseline、按既有映射去重、重新对齐并使用发布 key V3 签名；
  证书 SHA-256 为 `ef572a91ebf470dc6606af3639e8aa8d28b4bd0768d31b5efbbb2933d92c8296`。
- `main/app/MagicRoot.apk`：62,794,944 B，SHA-256
  `d1e1164b54ebe0704c9037bb953912878b99a72e5c256d7a53ed52cb35e90431`。
- 最终签名 APK 运行 `tools/check.sh` 全过：65 个 Shell、35 个 manifest 项、
  328 个资产逐字节一致、31 个 profile、39 个去重映射，以及 Java/生命周期/
  H1C/清理回归。`verify_98260_assets.py`、`verify_apk.py` 和源码包必需项检查通过。
- 未安装 APK，未执行真实提权、模块加载、hotfix 或重启。

