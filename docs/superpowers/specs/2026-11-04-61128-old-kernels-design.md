# 6.1.128 g8a496 / g2e1f 98260 适配设计

日期：2026-11-04

## 1. 目标与边界

为用户提供的荣耀旧版 boot 对照包中尚未支持的两个内核增加一次性临时 root
适配：

```text
6.1.128-android14-11-g8a4968670f1c  profile=g8a496
6.1.128-android14-11-g2e1f0741dafb  profile=g2e1f
```

成功标准是：两个精确 `uname -r` 分别部署自己的 payload 和 CGA 模块，进入
现有 `run6157_full.sh` 的 rootd → CGA LKM → su 交接，静态资产可确定重建，
部署不会借用其他内核地址，并产出签名 APK 与源码包。

本设计不新增设备型号、BTF 哈希、ROM 构建哈希或配置哈希门禁。只使用内核
release 选择已有类型的精确 profile。43499/Pad3 不引入；M6 Shell 1.9 的 g84
B2 路线不引入；现有 g7d M6、g264、6.6、6.12、6.18 链路保持不变。

仅支持本人或明确授权设备；重启失效，不修改分区、不持久化。本次实现和构建
不执行 UAF、rootd 提权、LKM 装载或重启。

## 2. 范围核对

附件：`荣耀boot对照_20261103_旧版本.zip`。其 `gf171`、`gfde77`、`g42fc`
以及未变化的 6.12/6.18 构建在仓库已有对应路线，不重做、不替换。

两份目标 boot 的 SHA-256：

```text
g8a496  bebc28d515c2bdb2a11acba609dc3efee33e49730596e8e96d80c228fdbeb3a8
g2e1f   d5a085ec75f6864ddc9f9de4659959b02fed33b26ab1e7634cb673f4771bdba6
```

`vmlinux-to-elf` 从两个 boot 各恢复 105877 个 kallsyms。版本字符串直接来自
镜像，不根据机型或文件名推断。原始 boot 只作为外部分析输入，不导入源码仓库、
APK 或源码包。

## 3. 布局与链接常量

两个构建均经反汇编证实属于 g264 的 `0x838/0x108` 家族：

- `prepare_creds` 从当前 task 的 `0x838` 读取 cred；real_cred 为 `0x830`。
- `init_posix_timers` 调用 `kmem_cache_create` 时对象大小为 `0x108`。
- 不使用 g84/g40b1 的 `0x840/0x118` 字段偏移补丁。
- 以下地址均来自各自恢复的 kallsyms 与函数指令，不从兄弟构建猜测。

| 常量 | g8a496 | g2e1f |
|---|---:|---:|
| `do_timer_create` | `0xffffffc008380ddc` | `0xffffffc008380fe4` |
| `timer_link`（分配调用返回点 `+0x94`） | `0xffffffc008380e70` | `0xffffffc008381078` |
| `prepare_creds` | `0xffffffc008095fdc` | `0xffffffc008095c78` |
| `cred_link`（分配调用返回点 `+0x20`） | `0xffffffc008095ffc` | `0xffffffc008095c98` |
| `selinux_minus7` | `0xffffffc00a6da9e9` | `0xffffffc00a6da9e9` |
| `sig_enforce` | `0xffffffc00a43dba0` | `0xffffffc00a43dba0` |
| `user_ns` | `0xffffffc00a0b0708` | `0xffffffc00a0b0708` |
| `root_user` | `0xffffffc00a0b0998` | `0xffffffc00a0b0998` |
| `groups` | `0xffffffc00a0b1cb8` | `0xffffffc00a0b1cb8` |
| `ucounts` | `0xffffffc00a0b2228` | `0xffffffc00a0b2228` |

`neg_timer_link` 按现有成功载荷规则取 64 位无符号 `-timer_link`。数据符号
相同不代表 payload 相同；两个构建的代码链接地址不同，必须分别生成和校验。

## 4. 生成架构

### 4.1 98260 payload

扩展现有 `binary-sources/61157-g264/rebase_success_payload.py` 与
`success-profiles.json`，新增 g8a496/g2e1f 两个直接记录实证常量的 profile。
以哈希锁定的 g264 静态成功载荷为唯一基座：

```text
cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
```

继续使用现有 MOVZ/MOVN/MOVK、imm12 和 `.rodata` 定点改写，不退回缺少
`blind_reclaim_stream` 的 34 KiB 动态版本。生成器检查基座原值、目标指令、
目标布局和输出哈希；`verify` 能逐字节重建全部旧 profile 和两个新 profile。

新目录：

```text
main/app/assets/98260-g8a496/
  exploit-android-key-ptr
  pc98260-su
  target.sh

main/app/assets/98260-g2e1f/
  exploit-android-key-ptr
  pc98260-su
  target.sh
```

`pc98260-su` 复用现有不含内核地址、哈希一致的 6.1 客户端。`target.sh`
记录各自精确内核 release，不写型号白名单。

### 4.2 CGA 模块

新增可重跑的静态重定位工具，以现有 `g264/ksm-g264-base.ko` 为布局基座，
以 `ksu6157-g264/ksu-syms.txt` 为基线符号来源，以各目标 vmlinux 恢复的
kallsyms 为目标地址来源，生成：

```text
main/app/assets/g264/ksm-g8a496-base.ko
main/app/assets/g264/ksm-g2e1f-base.ko
```

工具必须：

1. 按符号名重定位 `SHN_ABS` 内核地址；保留明确的 cache flush 别名规则。
2. 按已证明的调用目标映射 `.text.ksustub` 中的绝对地址，无法唯一映射即失败。
3. 保留 KCFI 类型值、模块内部符号、非内核常量与指令，不做盲目数值替换。
4. 写入对应目标 vermagic，并验证字符串长度和 ELF 完整性。
5. 校验所有模块未定义/重定位目标有地址，且活跃 section、符号表和跳板中
   无 g264 旧内核地址残留；不把未引用的文件尾数据当作运行时代码。
6. 证明新模块没有引入 `0x840/0x118` 家族的字段指令改写。

产物继续使用现有 `g264/ko_slide_patch` 在设备端叠加本次启动的 KASLR slide。
不把 PC 分析的 slide 或 boot 地址写入运行时持久配置。

## 5. 运行与部署接入

在 `run6157_full.sh` 中为两个 release 分别增加：payload 目录、CGA base/输出名、
`G264_BLIND=1`。它们只进入现有 CGA 分支，不能进入 g264 专属 legacy loader、
g7d M6、61157 g19a 或其他 KMI 分支。缺资产时沿用 fail-closed 行为。

在 Compose `MainActivity.java` 同步修改：

- `ASSETS_98260` 与共享 CGA 资产清单；
- `shouldStageLegacyAsset` 的 release 与精确文件筛选；
- `payloadDirFor6157`、`cgaBaseFor6157`；
- `requireCriticalAssets` 所需 payload、su 和 CGA base；
- 相关 chmod/部署路径（若现有通配规则未覆盖）。

部署仍以 ZIP 批处理和末尾统一权限规范化为主。两个 profile 只部署自己的
payload/CGA 和共享工具，不全量部署其他 6.1 内核资产。

## 6. 验证与失败处理

实现后至少执行：

1. 新 CGA 工具对两个目标的重复生成与字节一致性检查。
2. `rebase_success_payload.py verify`，覆盖全部 profile。
3. 扩展后的 `tools/audit_6157_chain.py`：哈希、静态 ELF、盲回收标记、
   vermagic、符号覆盖、旧地址清零、资产筛选和 runner 分支顺序。
4. 现有 profile 的生成结果与实施前哈希保持不变。
5. `bash -n` 和 `/system/bin/sh -n` 检查改动的 Shell。
6. 构建 release APK，检查签名、目标资产存在性及 APK 哈希。
7. 更新 `BINARY-SOURCES.md`、`SOURCE-MANIFEST.txt`、6.1 支持文档、
   `CLAUDE.md`、`进度.md` 和源码包 required 清单，生成 source zip。

任何未解析符号、歧义跳板、旧地址残留、布局不匹配或资产缺失都必须停止生成/
部署，不以“构建成功”替代正确性检查。没有对应真机时，最终状态明确标为
“静态适配，未做端到端真机验证”。后续真机测试须另行确认授权设备与风险，
一次开机不重复触发 98260。

## 7. 不做的事项

- 不接入 M6 Shell 1.9、B2 单 timer 或设备端 kallsyms patcher 新链路。
- 不修改 `main/app/src/` 旧控制器，不改变单页 UI、版本号、包名或签名策略。
- 不替换已验证或已静态适配的其他内核资产。
- 不提交 boot 镜像、APK、签名密钥、设备日志或用户数据。
- 不根据本次静态完成状态宣称 root、KernelSU 或 LSPosed 已真机闭环。
