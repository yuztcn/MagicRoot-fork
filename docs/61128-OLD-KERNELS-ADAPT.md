# 6.1.128 g8a496 / g2e1f 98260 适配

日期：2026-11-04

状态：**静态适配**。没有对应真机，未执行 UAF、rootd、KSU 模块装载或重启。

## 1. 输入与目标

输入为 `荣耀boot对照_20261103_旧版本.zip` 中两份尚未支持的旧版 boot。

| profile | uname -r | boot SHA-256 |
| --- | --- | --- |
| `g8a496` | `6.1.128-android14-11-g8a4968670f1c` | `bebc28d515c2bdb2a11acba609dc3efee33e49730596e8e96d80c228fdbeb3a8` |
| `g2e1f` | `6.1.128-android14-11-g2e1f0741dafb` | `d5a085ec75f6864ddc9f9de4659959b02fed33b26ab1e7634cb673f4771bdba6` |

两份内核的版本字符串均直接来自镜像。`vmlinux-to-elf` 以
`0xffffffc008000000` 为链接基址恢复各自 105877 个 kallsyms。boot/vmlinux
只作为外部分析输入，不进入仓库、APK 或源码包。

## 2. 布局证据

两个构建都是 g264 的 `0x838/0x108` 家族，而不是 g84/g40b1 的
`0x840/0x118`：

- `prepare_creds` 从 `SP_EL0 + 0x838` 读取当前 task 的 cred，随后按
  `0xb0` 字节复制；因此 real_cred 为 `0x830`。
- `init_posix_timers` 调用 `kmem_cache_create` 时的对象大小立即数为
  `0x108`。
- 没有加入型号、BTF、ROM 或配置哈希门禁。

## 3. 每构建链接常量

| 常量 | g8a496 | g2e1f |
| --- | --- | --- |
| `timer_link` | `0xffffffc008380e70` | `0xffffffc008381078` |
| `cred_link` | `0xffffffc008095ffc` | `0xffffffc008095c98` |
| `selinux_minus7` | `0xffffffc00a6da9e9` | `0xffffffc00a6da9e9` |
| `sig_enforce` | `0xffffffc00a43dba0` | `0xffffffc00a43dba0` |
| `user_ns` | `0xffffffc00a0b0708` | `0xffffffc00a0b0708` |
| `root_user` | `0xffffffc00a0b0998` | `0xffffffc00a0b0998` |
| `groups` | `0xffffffc00a0b1cb8` | `0xffffffc00a0b1cb8` |
| `ucounts` | `0xffffffc00a0b2228` | `0xffffffc00a0b2228` |

`timer_link` 是 `do_timer_create+0x94` 的 `kmem_cache_alloc` 返回点；
`cred_link` 是 `prepare_creds+0x20` 的对应返回点。两者都从各自函数的
反汇编直接确认。即使数据符号相同，两个 payload 也必须独立生成。

## 4. Payload

两个 payload 从已验证的 1.0.36 静态盲回收 g264 载荷确定性派生：

```text
base cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
```

生成器与清单：

```text
binary-sources/61157-g264/rebase_success_payload.py
binary-sources/61157-g264/success-profiles.json
```

| profile | payload SHA-256 |
| --- | --- |
| `g8a496` | `1db586a3f787a35d7f8872537470783397f2fbd9680a9877dd26beb2ca410f35` |
| `g2e1f` | `e681569bcf6b51fa36e59622e6361b19653eeca2079c8b081f0b9a9ae2d47d27` |

`98260-{g8a496,g2e1f}/pc98260-su` 与现有 6.1 通用客户端逐字节一致。
`target.sh` 分别锁定完整 `uname -r`，型号门控为空。

## 5. CGA 模块

新增标准库静态 ELF 重写器：

```text
binary-sources/61157-g264/rebase_cga_module.py
binary-sources/61157-g264/cga-profiles.json
base main/app/assets/g264/ksm-g264-base.ko
     6381ad16a904af8d7d2a702e04994ed22c3fd01c6e00229ec584634034a56c09
```

生成规则：

1. 将 225 个高地址 `SHN_ABS` 内核符号按名字改写到目标 kallsyms。
2. 将 `.text.ksustub` 中 220 个活跳板（204 个唯一目标）按旧地址反查
   符号名，再写目标地址；未知或歧义映射直接失败。
3. 只等长替换 `.modinfo` 的 vermagic release。
4. 允许变化的字节仅限上述符号值、跳板 qword 和 vermagic；其他任何
   字节差异都会让 `verify` 失败。
5. 保留 KCFI 值、模块内部符号和其他指令。

| profile | CGA SHA-256 | 改变字节 |
| --- | --- | --- |
| `g8a496` | `450b242ba93e085de4545184882230980addefb336bd6922885b285863c19dfa` | 1280 |
| `g2e1f` | `5b8f95453fa73e3c23aa0ffd071a2f354eb089358f4e13c2461fc87524075549` | 1276 |

设备端仍由现有 `g264/ko_slide_patch` 叠加当次启动的 KASLR slide。

复现：

```sh
python3 -I binary-sources/61157-g264/rebase_cga_module.py verify \
  --base main/app/assets/g264/ksm-g264-base.ko \
  --profiles binary-sources/61157-g264/cga-profiles.json \
  --output-root main/app/assets/g264
```

## 6. 路由与部署

- 顶层 `run.sh` 的 6.1 分派、`run6157_full.sh` 的 payload/CGA/
  `G264_BLIND=1` 选择都按精确 release 增加两项。
- Compose `MainActivity.java` 的现有 6.1 `ASSETS` 列表、文件级筛选、
  `payloadDirFor6157`、`cgaBaseFor6157`、关键资产与 chmod 已同步。
- 两个新 profile 不能进入 g7d M6、g264 legacy handoff、61157 g19a 或
  6.12/6.6 模板路径；未知 release 仍 fail closed。
- 未新增设备型号或硬性限制项。

## 7. 验证与限制

已执行：

```text
python3 -I tools/test_61128_adaptation.py all
python3 -I tools/audit_6157_chain.py
bash -n main/app/assets/run.sh
bash -n main/app/assets/98260/run6157_full.sh
/system/bin/sh -n main/app/assets/run.sh
/system/bin/sh -n main/app/assets/98260/run6157_full.sh
```

测试覆盖旧 profile 哈希、新 payload 常量与确定性、CGA 225/220 映射、
缺符号/未知跳板/额外字节负向拒绝、部署筛选及 g7d/g264 隔离。
静态审计最终为 `failures=0`。

未验证：两个目标都没有物理设备。不得把静态 `MISSING=0`、payload
重建或 CGA 审计描述成已提权或 KernelSU 已工作。真机测试需另行确认授权
设备，并遵守一次开机只触发一次 98260、保留 PPID=1 UAF 父进程、不在
临时 root 生效时执行 `ksud soft-reboot` 的约束。
