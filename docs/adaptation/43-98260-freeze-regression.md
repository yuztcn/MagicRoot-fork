# 1.0.4-fix 对比：6.12 / 6.6 98260 为什么容易死机

基线：

```text
59a33d7  2026-10-27 18:38  fix: keep UAF plant parked (1.0.4-fix soft cleanup)
```

当前：

```text
b69ab81  2026-10-30 01:26  debug: snapshot trace before drain ...
```

## 1. 结论先行

### 6.12.58 和 6.12.38 的 98260 二进制没有变

对照 1.0.4-fix：

```text
main/app/assets/98260/exploit-android-key-ptr
  59a33d7  sha256 fe67a61d...
  HEAD     sha256 fe67a61d...
  完全一致

main/app/assets/98260-6138/exploit-android-key-ptr
  59a33d7  sha256 99fe9581...
  HEAD     sha256 99fe9581...
  完全一致
```

所以这两个 profile 如果现在更容易死机，**不是 98260 UAF 二进制本身的代码变化**，而是外围链路：

- 新 `run.sh` 的 SuSFS / KSUD / soft-reboot 流程；
- 新的 KSU late-load / module patch；
- 新的 preflight、rootd 清理和 parked 策略；
- 新的 KSU 管理器模板选择。

### 6.6 和 6.12.23 / 6.12.38y 是新的二进制

1.0.4-fix 没有这些 profile：

```text
98260-6123   6.12.23
98260-6138y  6.12.38 (YLP-W00)
98260-g554   6.6.118 g554
98260-f171   6.6.118 f171
```

这些二进制不是 1.0.4-fix 验证过的那一株：

```text
g554   vs 1.0.4-fix:  311 字节差异
f171   vs 1.0.4-fix:  8058 字节差异
6123   vs 1.0.4-fix:  12566 字节差异
6138y  vs 1.0.4-fix:  1159 字节差异
```

其中 g554 的差异很小，像是只替换目标常量；f171/6123 的差异明显更大，不能假定只是常量。

## 2. 新目标常量的验证状态

### 6.6.118

`binary-sources/66118/pc98260_target_66118.h` 自己写着：

```text
Status: STATIC DERIVATION ONLY — never validated on a device.
GEO_TASK_OBJSIZE is a placeholder ...
```

g554 静态包的 header 还写着：

```text
LINK_ALLOC_CRED ... (cred_jar, boot-verified)
```

但 f171 的 `LINK_ALLOC_CRED` 不是同一组：

```text
g554 LINK_ALLOC_CRED = 0xffffffc080238458
f171 LINK_ALLOC_CRED = 0xffffffc0802536a0
```

这两个值对应不同 build，不能共用。

### 6.12.23

`pc98260_target_6123.h`：

```text
GEOM_MEMSTART_PFN  0x80000  /* inferred from 61258 mapping */
LINK_ALLOC_TASK    ...      /* observed */
```

`GEOM_MEMSTART_PFN` 只是从 6.12.58 推的，不是 6.12.23 实测。

### 6.12.38y

`pc98260_target_6138y.h` 明确标了一堆 `[inferred]`：

```text
LINK_ALLOC_TASK      inferred
GEO_CRED_ALLOC_SIZE  inferred
GEO_TASK_OBJSIZE     inferred
GEO_TASK_OBJ_PER_SLAB inferred
GEO_TASK_SLAB_PAGES  inferred
GEO_POSIX_TIMER_OBJ_PER_SLAB inferred
GEOM_MEMSTART_PFN    inferred
CAP_FULL             inferred
```

这些常量任一错误，都可能造成：

- 目标页 PFN 算错；
- fake cred 写到错误的 task_struct 偏移；
- `selinux_state` 零写打到错误地址；
- `posix_timers_cache` 的 slab 几何算错。

结果不是“exploit 失败”，而是**内核内存被写坏，然后下一次调度/退出时死机**。

## 3. 1.0.4-fix 之后新增的外围链路

### 3.1 soft reboot repair

1.0.4-fix 没有 `soft_reboot_repair`。

当前 `run.sh` 有：

```text
soft_reboot_claim()
soft_reboot_repair()
```

并且在链路尾部调用：

```text
soft_reboot_repair
```

如果存在以下任一情况：

```text
/data/local/tmp/magic/soft_reboot_module
/data/local/tmp/magic/soft_reboot_manager
/data/local/tmp/magic/soft_reboot_repair
MAGICROOT_REBOOT_MODULE=1
MAGICROOT_REBOOT_MANAGER=1
MAGICROOT_REPAIR=1
```

它会在 15 秒后执行：

```text
ksud soft-reboot
```

1.0.4-fix 没有这个自动动作。  
如果用户在模块/管理器授权场景下勾选了 repair，这个 userspace reboot 本身就可能表现为：

- 黑屏；
- 卡开机动画；
- 直接冷重启；
- “手机死机”。

当前代码虽然对 `susfs_guard_lkm` 做了保护：

```text
SOFT_REBOOT_REPAIR=skip reason=susfs_lkm_loaded full_reboot_required
```

但**普通 KSU 场景仍会调度 soft-reboot**。

### 3.2 SuSFS guard LKM

1.0.4-fix 的 `run.sh` 里没有 SuSFS 逻辑。

当前新增：

- SuSFS LKM 下载/加载；
- `susfs_insmod`；
- SuSFS guard 的 KMI 检查；
- KSU late-load 后再加载 guard。

如果 guard 的 vermagic/KMI/符号不匹配，`finit_module` 或 guard hook 可能直接导致内核 oops。  
这类死机通常发生在 **KSU 已经 late-load 成功之后**，看起来像“98260 成功后死机”。

### 3.3 KSUD / KSU 模板

当前新增/调整了：

- `ksud_kernelsu`
- `ksud_fina`
- 多个 `ksu-template-66118-*.ko`
- `ko_patch` 的 syms 选择

1.0.4-fix 只覆盖旧 profile。  
6.6 模板如果 KMI 或符号表不匹配，`ko_patch` 可能生成一个能插入但会崩的模块。

### 3.4 parked UAF 策略

1.0.4-fix 的原则是：

```text
keep UAF plant parked
```

当前增加了：

```text
FAIL=rootd_live_without_usable_socket
HINT=reboot required; do not SIGKILL
```

这本身是安全改进。  
但如果用户在 parked 状态下：

- 结束应用；
- `kill -9`；
- 再启动第二次 plant；

仍可能触发 timer-UAF zombie 的退出路径，直接 panic。

## 4. 死机类型判断表

| 现象 | 更可能的原因 |
|---|---|
| 6.12.58 / 6.12.38 原二进制，跑完 98260 后黑屏/重启 | `run.sh` 的 soft reboot、SuSFS、KSUD，不是 UAF 二进制 |
| 6.12.23 / 6.12.38y 在 exploit 中途 panic | 新常量（`GEOM_MEMSTART_PFN`、`LINK_*`、`GEO_*`）不匹配 |
| 6.6 g554 在 `[selinux]` 或 cred 阶段 panic | g554 静态 header 的地址/几何未真机验证 |
| 6.6 f171 在 cred 阶段 panic | f171 的 `LINK_ALLOC_CRED` 与 g554 不同，需单独验证 |
| KSU late-load 成功后马上死机 | SuSFS guard / KSU 模板 / KMI 不匹配 |
| 第二次运行 98260 立刻失败/死机 | parked zombie；必须重启，不能 SIGKILL 或再 plant |

## 5. 建议的验证顺序

### 6.12.58 / 6.12.38

先排除外围：

```text
MAGICROOT_REBOOT_MODULE=0
MAGICROOT_REBOOT_MANAGER=0
MAGICROOT_REPAIR=0
MAGICROOT_SUSFS=0
```

只跑 98260 + KSU，不加载 SuSFS，不 soft reboot。  
如果不再死机，问题在外围链路。

### 6.6 / 6.12.23 / 6.12.38y

先只做只读 preflight：

```text
MAGICROOT_98260_PREFLIGHT=1
```

并核对：

```text
/proc/slabinfo       posix_timers_cache / task_struct
/proc/iomem          memory start
/proc/kallsyms       若可读，核对 LINK_* 
```

在 `[selinux]` 之前不要进入 UAF。

### 任何失败后

```text
reboot
```

不要：

```text
kill -9 exploit
kill -9 rootd
第二次 plant
```

## 6. 最小修复建议

1. 给 6.6 / 6.12.23 / 6.12.38y 增加 `static_unvalidated` 标记，默认只允许 `--check`；
2. 在 `run98260.sh` 中把 6.12.58 / 6.12.38 的 SuSFS、soft reboot 默认关闭；
3. 对 6.6 只保留 g554 的 boot-verified cred site，f171 未验证前不默认启用；
4. 增加 `GEOM_MEMSTART_PFN` / slab 几何的只读校验，不匹配直接 abort；
5. 死机日志用 `pstore` / `last_kmsg` 确认是 UAF 写坏还是 SuSFS/KSU 模块 oops。

## 7. 关键文件

```text
main/app/assets/98260/run98260.sh
main/app/assets/run.sh
main/app/assets/kernel_profiles.sh
main/app/assets/98260-g554/
main/app/assets/98260-f171/
main/app/assets/98260-6123/
main/app/assets/98260-6138y/
binary-sources/66118/pc98260_target_66118.h
work/61821/build/pc98260_target_6123.h
work/61821/build/pc98260_target_6138y.h
```
