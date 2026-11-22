# 6.18.21（ge186062ea75f / 115）98260 全链路适配分析

对比对象：

```text
已验证基线   6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
失败目标     6.18.21-android17-5-ge186062ea75f-abogki564062290-4k（115）
参考实现     https://github.com/superboyyy/HOneClick（0ede556，native/cve98260 + assets/syms-115.txt）
```

结论：115 不是“某一条命令失败”，而是**五个独立缺陷叠加**。其中第 1 条会让
每一次 g186 运行都必然留下 parked UAF，第 2、3 条让即便只剩 H1C 引擎也难
命中页面或拿到 ksu 域凭据；第 4、5 条决定“命中了也收不了尾 / UI 看不出进展”。

## 1. `run98260.sh` 在 H1C 分派之前无条件跑旧 BRM 引擎（决定性）

`98260/run98260.sh` 在 219–223 行就把 `61821|61821brm` 标成 `H1C_ONLY=1`，
但旧引擎的整段逻辑仍然在 H1C 分派（693 行）**之前**执行：

```text
260 行   [ -x "$SU" ]（pc98260-su）不存在即 exit 73
300 行   PREFLIGHT 落到 legacy --check
449–503  parked_check / 复用 rootd / KSU 已加载判断 / 僵尸 plant 判断
512–591  setsid 启动 $B/exploit-android-key-ptr，等 240 s socket，verify_su
597–629  SUSFS preload
693 行   if [ "$H1C_ONLY" = "1" ]; then 才开始 H1C
```

`98260-61821-brm/` 里恰好部署着 `exploit-android-key-ptr`，所以 g186 上会出现
**两套 UAF 同时存在**：旧 payload 按 6.12 的 `k_itimer=256B / node=0x78 /
task->cred=0x900` 布局去 reclaim，而 115 实际是 `384B / 0xe0 / 0x908`。
真机日志（`20261102154444-fail_log_1793632613438.txt`、
`20261103074035-prev-run-1793691304011.txt`）里 H1C 之前就有旧 plant 的启动
痕迹，随后 H1C 报`page miss`/`plant_already_running`。

修复：

- 260 行的 `pc98260-su` 资产检查移入 `H1C_ONLY != 1` 分支；
- 449–629 行整段包进 `if [ "$H1C_ONLY" != "1" ]; then ... fi # legacy BRM chain only`；
- 旧引擎里的“KernelSU 已加载则复用 su”快路径对 H1C 也补了一份，避免同一次
  开机第二次运行时重复 plant。

`tools/test_h1c_flow.py::test_legacy_brm_launch_is_guarded_from_h1c` 做源码结构
回归，确保 `$BIN $REAL_CRED_ARG`、SUSFS preload、`pidof exploit-android-key-ptr`
不会被移出该块。

## 2. `ksu-template-115.ko` 未打 bootstrap 凭据补丁

上游给 109 模板打了 `patch_ksu_bootstrap_creds_v331.py`
（`e33b7c5d…` → `86ed32a0…`）：把首次凭据分配从 `prepare_creds()` 改成
`prepare_kernel_cred(&init_task)`，让 `ksu_cred` 复制的是**带安全标签的
init 凭据**，而不是从 UAF 子进程继承来的“无 security 指针”凭据。

115（`f8dd188f…`）一直没打。当模块通过 `cve98260_module` 从 UAF 子进程
`finit_module` 时，`prepare_creds()` 拿到的 cred 没有 SELinux blob，
后续 `u:r:ksu:s0` 域迁移失败 → `root_id`/`direct su` 校验过不去。

修复：

- `patches/patch_ksu_bootstrap_creds_v331.py` 的 `SUPPORTED_INPUTS` 同时接受
  109 与 115 两个输入 hash（115 的 `.rodata` addend 为 `0x50BF`，与 109 相同；
  先前记录的 `0x50AF` 是错误值）；
- 对 115 输出 `97022c36f9888469146b71a5917bc0fe95c28f2c4816ce8c601e3fe5a2fcdae0`
  （438,096 B），同步到 3 个去重路径；
- `syms_61821_brm.txt` 补 `prepare_kernel_cred 0xffffffc0804f184c`（来自
  `assets/syms-115.txt`），否则 `ko_patch` 报 `MISSING=1`。

`ko_patch` 验证：`PATCHED=227 MISSING=0 REPAIRED=14`。

## 3. 复合页 PFN 匹配错误（`uaf_plant.c`）

6.12.58 与 115 的 slab 几何不同：

```text
             k_itimer  node   task->cred  cred_size  每 slab
6.12.58      256 B     0x78   0x900       168 B      32 obj / 2 页
6.18.21-115  384 B     0xe0   0x908       184 B      21 obj / 2 页（order-1）
```

`pfn_in_line()` 原来只做 `got == pfn`（精确命中页头）。当
`skb_page_frag_refill()` 把刚释放的 order-1 slab 合并成 order-2/3 复合页时，
`mm_page_alloc:` 记录的是**复合页头 PFN**（`base & ~((1<<order)-1)`）并带
`order=<N>`；只要 `base` 不落在块首，原判断就永远不中，日志表现为
`writes=480 hit=0 → page miss; parking unsafe process`。

修复：解析 `order=`，按 `pfn >= got && pfn < got + 2^order` 匹配整个复合页范围。
`cve98260_plant` 已按此源码重建（见 `BINARY-SOURCES.md`）。

## 4. 载入后阶段与收尾缺口

- `run_h1c.sh` 曾用 `cp -f "$H/root_stage.sh" "$D/root_stage.sh"` **覆盖** App
  部署的完整 `root_stage.sh`，丢掉管理器发现、签名注册
  （`kernel dynamic-manager set-apk` / `debug set-manager`）、原子安装 ksud。
  现在优先使用部署版，回退版写到 `root_stage_h1c.sh`；身份文件接受
  `root_id` 或 `marks/ROOT_ID`。
- 部署版 `root_stage.sh` 用 `tmp + mv -f` 原子替换 `/data/adb/ksud`；
  内置 H1C 版本原来直接 `cp`，中断会留下截断的 ksud，已改为原子写法。
- `run98260.sh` 的 H1C 分支在 763 行 `exit "$H1C_RC"`，因此从未走到
  `/data/adb/ksu/soft_reboot.lock` 布防和 `98260_KSU=loaded` 收尾；H1C 的
  成功标记统一由 `run_h1c.sh` 的 `98260_H1C_DONE=1` 表达，UI 已按此识别。

## 5. UI 进度分类缺 H1C 标记

`RunProgress.java` 原来没有任何 `98260_H1C_*` 规则，整个 H1C 过程 UI 停在
“初始化链路”。已补：引擎、preflight、slide、ko patch、plant、rootd wait/ready、
module load/live、root stage、direct su、DONE、already_loaded。

## 修改清单

```text
main/app/assets/98260/run98260.sh              legacy 段仅 BRM；H1C 复用快路径
main/app/assets/98260-h1c/run_h1c.sh           root_stage 选择 + 原子写 + root_id 兼容
main/app/assets/98260-h1c/root_stage.sh        ksud 原子替换
main/app/assets/98260-h1c/cve98260_plant       重建（复合页 PFN 修复）
main/app/assets/98260-h1c/ksu-template-115.ko  凭据补丁
main/app/assets/98260-61821-brm/ksu-template.ko
main/app/assets/98260-61821-brm/ksu-template-61821-kernelsu.ko
main/app/assets/98260-61821-brm/syms_61821_brm.txt  + prepare_kernel_cred
main/compose-app/.../RunProgress.java          H1C 进度标记
tools/tests/RunProgressTest.java               对应断言
tools/test_h1c_flow.py                         legacy 隔离 + 部署版 root_stage
tools/asset_dedup_map.json                     新 hash/size
BINARY-SOURCES.md, docs/98260-H1C-ENGINE.md    来源与说明
```

## 验证状态

- 静态/本机：`bash -n` 全部通过；`ko_patch` 对 115 模板
  `PATCHED=227 MISSING=0 REPAIRED=14`；重建 plant 的 `--preflight` 与上游二进制
  输出一致（仅 tracefs 权限差异）；`RunProgressTest`、`test_h1c_flow.py` 全绿。
- 真机：**未验证**。UAF/模块加载/管理器注册属设备行为，需在 6.18.21 设备上
  重新部署 APK 后实跑；失败仍按“一次开机只跑一次、失败即重启”的约束处理。

## 剩余风险

- 重建的 `cve98260_plant` 由静态改为动态 PIE（本机无静态 bionic libc）。
  逻辑与上游一致，但属于二进制替换，需真机确认启动与驻留行为。
- 115 的凭据补丁是二进制定点替换，`ko_patch` 的 14 个 `SHN_XINDEX` 修复仍依赖
  现有实现。
- 复合页修复放宽了“命中”，但页面内容校验（`filemap` 行数、ring 归属）仍是
  失败即停，不会因为放宽匹配而误判成功。
