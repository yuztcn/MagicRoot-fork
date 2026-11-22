# 6.1.157 g08de1e2b38ba 静态核查（仅 98937 KASLR 目标）

日期：2026-11-21

来源：HyperBreak 接入阶段对本地 `boot(3).img` 的分析；镜像未随仓库分发。

## 1. 内核身份

```text
Linux version 6.1.157-android14-11-g08de1e2b38ba (build-user@build-host)
clang 17.0.2 / LLD 17.0.2  #1 SMP PREEMPT Tue Nov 3 11:42:36 UTC 2026
```

- 不在 98260 6.1 逐 build payload 表内，没有对应的
  `exploit-android-key-ptr`、`pc98260-su` 或 `ksm-*-base.ko`。
- BTF（本地镜像）：`input_dev` 1608 / `sw@464` / `num_vals@1520` /
  `max_vals@1524` / `vals@1528`；`cred` 176 / `euid@0x14` / `fsuid@0x1c` /
  `cap_eff@0x38`；`uhid_device` 9264 / `input_buf@80` / `worker@9216`。
- `uhid_device_add_worker = 0xffffffc008e9db1c`。

## 2. CVE-2026-98260 修复状态

上游修复 `acb03d388181`（exec: Cleanup POSIX timers right after
`de_thread()`）**未合入**：

```text
begin_new_exec = 0xffffffc00822c4bc
  0xffffffc00822caa8: bl <posix_cpu_timers_exit>   # exec_task_namespaces 之后
release_task   = 0xffffffc00819c08c
  +0xd0 / +0x380: bl <posix_cpu_timers_exit> / <posix_cpu_timers_exit_group>
```

`de_thread` 无清理调用，漏洞可达；但可达不等于 MagicRoot 已有可用 payload。

## 3. 已同步到 MagicRoot 的内容

`main/app/assets/kaslr-98937/targets.conf` 增加该 release 的常量：

```text
_stext        0xffffffc008010000
_etext        0xffffffc0090b0000
_text         0xffffffc008000000
prepare_creds 0xffffffc0080f6124
selinux_state 0xffffffc00a6fde00
```

该表供 98937 KASLR oracle 使用；未命中时仍回退原有 KASLR 源。

## 4. 边界

- 只做了静态镜像核对与 KASLR 常量同步；
- 没有为 g08de 编译 98260 payload，也没有生成 CGA base 模块；
- 因此**没有**加入 `run6157_full.sh` 分派，UI 也不把该构建标为可 root；
- 若后续正式接入，需要按 `docs/98260-612-NEW-KERNEL-PORTING.md` 提取
  `do_timer_create` / `prepare_creds` 分配调用点、编译 payload、生成 CGA
  模块，并在真机走完整 98260 链后再加入分派。
