# 6.6.118 boot image 地址核验

日期：2026-10-29

## 输入

| 名称 | boot sha256 | kernel sha256 | release |
|---|---|---|---|
| g554-new | `cd7ad501…` | `ebb5bd6e70c9a19d9fb536694201f471cb4c237f77bf028fad7b6abf8e6b3409` | `6.6.118-android15-8-g554929766a0d-abogki544555896-4k` |
| f171 | `3dacd60d…` | `e8ce5dbf904ecb602b7c486ed365f0812d71d1696bddf79d188f6872906f9c79` | `6.6.118-android15-8-gf17133276a57-abogki518694926-4k` |
| g554-ptp | `020b51cb…` | `ebb5bd6e70c9a19d9fb536694201f471cb4c237f77bf028fad7b6abf8e6b3409` | `6.6.118-android15-8-g554929766a0d-abogki544555896-4k` |

**g554-new 与 g554-ptp 是同一个 kernel**，boot 容器/AVB 尾部不同，不能据此拆 profile。

## 实测符号

通过 boot 内 kallsyms 提取（`vmlinux-to-elf` kallsyms finder）：

### g554

```text
do_timer_create   0xffffffc0803afc58
prepare_creds     0xffffffc080238438
copy_process      0xffffffc0801cb0fc
begin_new_exec    0xffffffc0801d20bc
selinux_state     0xffffffc0823ba418
init_user_ns      0xffffffc08218ef98
root_user         0xffffffc08218f228
init_groups       0xffffffc082190788
init_ucounts      0xffffffc082190cf8
memstart_addr     0xffffffc081699ac8
```

反汇编确认：

```text
copy_process:
  0xffffffc0801cb23c  bl kmem_cache_alloc_node
  0xffffffc0801cb240  _RET_IP_ (call_site)

prepare_creds:
  0xffffffc080238454  bl kmem_cache_alloc
  0xffffffc080238458  _RET_IP_ (call_site)

do_timer_create:
  0xffffffc0803afce8  bl kmem_cache_alloc
  0xffffffc0803afcec  _RET_IP_ (call_site)
```

### f171

```text
do_timer_create   0xffffffc0803aebac
prepare_creds     0xffffffc080253680
copy_process      0xffffffc0801e0d04
begin_new_exec    0xffffffc0801e7ccc
selinux_state     0xffffffc0823ba418
init_user_ns      0xffffffc08218ef98
root_user         0xffffffc08218f228
init_groups       0xffffffc082190788
init_ucounts      0xffffffc082190cf8
memstart_addr     0xffffffc081698a48
```

按 +0x20/+0x94/+0x144：

```text
prepare_creds call_site  0xffffffc0802536a0
do_timer_create call_site 0xffffffc0803aec40
copy_process call_site    0xffffffc0801e0e48
```

## 与本地 profile 对照

| 项 | 本地 g554 | 实测 g554 | 本地 f171 | 实测 f171 |
|---|---|---|---|---|
| timer site | `0x803afcec` | 同 | `0x803aec40` | 同 |
| cred site | `0x80238458` | 同 | `0x802536a0` | 同 |
| task site | `0x801cb240` | 同 | `0x801e0e48` | 同 |

结论：本地 g554/f171 原常量本来就是正确的。

此前按 BRM 的 `0x80038458` 修改 g554 是错误：

- `0x80038458` 属于 BRM `ge186062ea75f` 的 6.18 内核；
- 不是 g554；
- 已恢复 g554 payload/syms/header 为 `0x80238458` / `0x80238438`。

## 恢复后的 g554 资产

```text
exploit-android-key-ptr
size   2,213,008
sha256 36790AD58962F7CCEF9CA3B13C07436285A7D287AF72B25B5E0C44C5D7733C05

syms_66118*.txt
prepare_creds 0xffffffc080238438
```

## 验证边界

- 只做了 boot 提取、kallsyms 与反汇编，没有在 6.6 真机执行 plant；
- 没有重建 6.6.118 测试包；
- g554 两幅 boot 都指向同一 kernel，任一份都可作为静态来源。
