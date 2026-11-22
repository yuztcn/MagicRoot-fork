# 6.1.157 gaaa383620ebf 98260 静态适配

日期：2026-11-07

状态：**仅静态适配**。未在对应设备上执行 UAF、rootd、CGA LKM 装载、su 或重启；不得据此声称端到端验证通过。

## 输入与链路

输入为用户提供的 `boot_ota_1794058115581.img`：

```text
uname -r    6.1.157-android14-11-gaaa383620ebf
boot size   100663296 bytes
boot SHA-256 a41aa37fc83e39334a1805bcd3f510c860d76e6dd02e44db762012f6caf9e524
```

该 profile 使用现有 `98260/run6157_full.sh` 的每构建 CGA 路线。没有引入 43499/Pad3 路线，没有新增型号、BTF、ROM 或配置哈希门禁，也没有借用 g264 的代码地址或 CGA 符号。

## 布局与链接常量

从 boot 中恢复 106799 个 kallsyms，并直接反汇编目标函数：

- `prepare_creds` 在 `+0x20` 返回 `kmem_cache_alloc` 调用点；随后从 `SP_EL0 + 0x838` 读取当前 cred，并按 `0xb0` 字节复制。因此 `task_cred=0x838`、`real_cred=0x830`。
- `do_timer_create+0x90` 调用 `kmem_cache_alloc`，所以返回点为 `+0x94`。
- `init_posix_timers` 给 `kmem_cache_create` 的对象大小为 `0x108`。

| 常量 | gaaa |
| --- | --- |
| `timer_link` | `0xffffffc0083c0a00` |
| `cred_link` | `0xffffffc00808de68` |
| `selinux_minus7` | `0xffffffc00a6fde39` |
| `sig_enforce` | `0xffffffc00a45dc60` |
| `user_ns` | `0xffffffc00a0d0748` |
| `root_user` | `0xffffffc00a0d09d8` |
| `groups` | `0xffffffc00a0d1cf8` |
| `ucounts` | `0xffffffc00a0d2268` |

## 确定性产物

Payload 从已锁定的 g264 成功型静态盲回收载荷派生，base SHA-256 保持：

```text
cc0b9693dcdba564585c39dfe3eb386860f1cede4251d0d7aca63d1e51762843
```

2026-11-11 起，gaaa 使用恢复版 g264 base，按名字重写 226 个 `SHN_ABS` 符号、221 个活跳板并等长更新 vermagic；新增符号为 `tracepoint_probe_register_prio`。缺符号、未知跳板和白名单外字节变化均拒绝输出。原 225/220 派生记录见 `cga-profiles.json`，恢复版单独使用 `cga-feature-restore.json`。

```text
98260-gaaa/exploit-android-key-ptr
  67cedbc21f3bd6c761291183dac054c5711407485fbff8c24a7d577409ee1fae

g264/ksm-gaaa-base.ko
  64ebb525f3f98c73a0cc648f27552b0e5792ee18aaf87c6b1fdade15a90bc377
```

`98260-gaaa/pc98260-su` 与其他 6.1 CGA profile 的通用客户端逐字节一致；APK 去重映射指向 `98260-6157/pc98260-su`。`target.sh` 锁定完整 release，型号门禁为空。

复现与审计：

```sh
python3 -I binary-sources/61157-g264/rebase_success_payload.py verify \
  --base main/app/assets/98260-g264/exploit-android-key-ptr \
  --profiles binary-sources/61157-g264/success-profiles.json \
  --output-root main/app/assets

CGA_BASE_SHA256=b44cc79de9196c65a0f2ffe1a6e5b23dff7713c68f8752c3fe861c627d78399a \
CGA_EXPECTED_ABS=226 CGA_EXPECTED_STUBS=221 \
python3 -I binary-sources/61157-g264/rebase_cga_module.py verify \
  --base main/app/assets/g264/ksm-g264-base.ko \
  --profiles binary-sources/61157-g264/cga-feature-restore.json \
  --output-root main/app/assets/g264 --only gaaa

python3 -I tools/test_61128_adaptation.py all
python3 -I tools/audit_6157_chain.py
bash tools/check.sh
```

外部 boot/kernel/vmlinux 仅为分析输入，不进入 APK、Git 或源码包。

## 注册范围

已同步：顶层 6.1 分派、runner 的 payload/CGA/blind-reclaim 选择、Compose `ASSETS` 与精确部署筛选、`payloadDirFor6157`/`cgaBaseFor6157`、chmod、`KernelLogHelper`、`tools/kernel_profiles.json`、APK 去重表、源码包必需文件及关于页列表。

真机验证仍须另行在明确授权且匹配该 release 的设备上进行；静态 `MISSING=0`、确定性重建和门禁通过不等于提权或 KernelSU 已工作。
