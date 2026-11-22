# 6.18.21 / 6.12.x / 6.6.x 内核自适应配置

## 来源

该功能参考 HOneClick：

- `KernelProfileGenerator.java`
- `native/cve98260/uaf_plant.c`
- `exploit-profiles.json`

参考仓库缓存于：

```text
work/upstream-honeclick-20261102/
```

## 用途

当前 APK 不再只依赖预编译的 6.18 profile。用户可以导入当前设备自己的
`boot.img`，在设备本地生成：

```text
/data/user/0/com.aoki.magicroot/files/profiles/<id>/profile.json
/data/user/0/com.aoki.magicroot/files/profiles/<id>/syms.txt
```

生成内容只来自用户选择的 boot.img，不联网、不下载第三方配置。

## 支持范围

- 仅接受内核版本以 `6.18.` 开头的 AArch64 内核
- 解析 kallsyms、BTF、`do_timer_create` / `prepare_creds` 链接
- 检查 `begin_new_exec` 内的漏洞调用顺序
- 校验 `cred` 字段偏移
- 生成 profile 后再由 H1C 引擎的 `--preflight` 二次校验

不添加设备型号、BTF 哈希、ROM 构建哈希等硬编码限制。内核适配只以
boot.img 中实际解析到的内核为准。

## 6.12.x / 6.6.x：纯 kallsyms 导出路径（2026-11-06 新增）

6.12.x / 6.6.x 是标准 GKI 内核，不会像 6.1.x 厂商内核那样把
`commit_creds` 等关键符号从 kallsyms 隐藏（参见
`binary-sources/66118/PATCH-NOTES.md` 的「0 缺失」记录），因此不需要
6.18 那套 BTF 结构体偏移解析和 `begin_new_exec` 漏洞调用顺序校验，
只做本地离线的 kallsyms 名称/地址表恢复即可。

`KernelProfileGenerator.java` 新增：

```java
public static String peekKernelRelease(byte[] image)
public static KallsymsResult generateKallsyms(byte[] image)
```

`MainActivity.importAdaptiveBoot()` 导入 boot.img 后先用
`peekKernelRelease` 判断内核版本号：

- `6.12.` / `6.6.` 开头 → 走 `generateKallsyms`，只写出
  `syms.txt`（`name 0xADDR` 格式）和一份极简 `profile.json`
  （仅 `id`/`kernel`/`audit_kallsyms`/`vulnerable:false`，不含
  `timer_link`/`cred_link` 等 H1C 专用字段）。
- 其余（即 `6.18.`）→ 保持原有完整 `generate()` 流程不变。

`generateKallsyms` 会用
`commit_creds`/`prepare_creds`/`_printk`/`init_user_ns`/`init_groups`/`init_ucounts`
六个符号做存在性校验（`requireSymbol`），缺任何一个就直接失败，不输出
半成品符号表。对 6.1.x 厂商内核或非 `6.12./6.6./6.18.` 版本调用
`generateKallsyms` 会显式抛异常拒绝，不会尝试「尽力而为」。

**已验证**：用两份真实设备 `boot_ota` 镜像（内核
`6.12.23-android16-5-gcd85666d7884-abogki452537391-4k` 与
`6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k`）跑
`generateKallsyms`，分别提取出 126268 / 110155 个符号，与仓库已有的
参考符号表 `main/app/assets/syms_g856.txt`、
`main/app/assets/98260-6689/syms_6689_kernelsu.txt` 逐一核对所需的
225 个符号，**地址 100% 精确匹配**（225/225，0 缺失、0 不符）。

**未完成（不要当成已验证的端到端能力）**：目前只实现了「生成」，
`run.sh` / `run98260.sh` 的顶层分派 **没有**接入这份新生成的
syms.txt —— 遇到仓库尚未内置 profile 目录的全新 6.12.x/6.6.x 内核，
`run98260.sh` 仍会落入 `FAIL=kernel_unsupported`。把生成结果真正接到
真机链路消费（新建 profile 目录、`kernel_profiles.sh` 选择逻辑、
`shouldStage98260Asset` 筛选）是单独的后续工作，尚未开始，不要在
文档或对外说明里把这条路径描述成「6.12/6.6 新内核即插即用」。

深入调查后确认：接入新内核真正缺的不是符号表（本节已解决），而是
`exploit-android-key-ptr` 这个逐内核单独编译的二进制——它把
`do_timer_create`/`prepare_creds` 内部的分配调用点偏移量编译期写死，
这些偏移量**不跨内核分支稳定**（6.12.x 是 `+0xac`/`+0x2c`，6.6.x 是
`+0x94`/`+0x20`，6.18.x 是 `+0xb8`/`+0x2c`）。针对这个问题，现在有一个
独立的、**仅供维护者离线使用**的反汇编辅助工具，自动产出这两个偏移量
的草稿供人工核对，但仍然需要人工复核 + 重新编译 + 真机验证，详见
[[docs/98260-612-NEW-KERNEL-PORTING.md]]。这个工具不在 APK 里，不影响
`run.sh`/`run98260.sh` 的设备端分派。

## 运行链路

1. 高级选项 → `导入 boot.img 生成自适应配置`
2. App 生成 `profile.json` 与 `syms.txt`
3. 运行前把生成的符号表写入 `/data/local/tmp/magic/syms_adaptive.txt`
4. `run98260.sh` 通过环境变量把动态常量传给 H1C：
   - timer/view link
   - cred/selinux/user_ns/root_user/groups/ucounts
   - `k_itimer` size/node
   - task cred 偏移、cred size、slab objects/pages
5. `run_h1c.sh` 的 `H1C_DYNAMIC=1` 分支使用这些值，不再使用
   `61821` / `61821brm` / `61821h1c117` 固定常量（117 已有精确内置 profile，
   gfee2325de189 不再依赖导入）
6. KernelSU 模板仍使用当前管理器 Flavor 对应的 61821 模板，符号表用
   用户 boot.img 生成的新表

## 6.18 引擎选择

6.18.21 强制使用 H1C 引擎：

```text
MAGICROOT_98260_ENGINE=h1c
```

旧 BRM 引擎在 6.18 上会出现 `page_freed=0` 的 reclaim miss，因此即使
用户保存过 `brm`，6.18.21 也会自动覆盖为 H1C。

## 注意

- 生成配置只对**完全相同的内核 release**生效；内核更新后需要重新导入。
- 仍需要执行一次 H1C 的 `--preflight`；预检失败会停在 UAF 之前。
- 不安装任何第三方 manager APK。
