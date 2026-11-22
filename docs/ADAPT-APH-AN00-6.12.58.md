# APH-AN00 偏移与适配证据

## 内核身份

| 固件 | kernel_release | Image SHA-256 | 处置 |
| --- | --- | --- | --- |
| 10.0.0.112 | `6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k` | `411d87a6841685733804207d13000683f85b10c9bda1ec0feed0a63480e1f20a` | 新增 `aph112` |
| 10.0.0.136 | `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k` | `2b158518f3436f2f7efb31c012137d14d06e301b7570ab187a9df1be856fe8ab` | 复用 `61258` |

136 的目标常量、KASLR 源码及全部 226 个 LKM 符号地址均与现有 61258 一致。112 的绝对地址均从该固件 Image/kallsyms/反汇编重新推导。

## 112 的绝对地址变化

| 常量 | 现有 61258 | 新增 aph112 | 差值（新－旧） |
| --- | --- | --- | --- |
| `LINK_SELINUX_STATE` | `0xffffffc0827e7a60` | `0xffffffc0827e7a20` | `-0x40` |
| `LINK_INIT_USER_NS` | `0xffffffc082572138` | `0xffffffc082572128` | `-0x10` |
| `LINK_ROOT_USER` | `0xffffffc0825723b0` | `0xffffffc0825723a0` | `-0x10` |
| `LINK_INIT_GROUPS` | `0xffffffc082573878` | `0xffffffc082573868` | `-0x10` |
| `LINK_INIT_UCOUNTS` | `0xffffffc082573d48` | `0xffffffc082573d38` | `-0x10` |
| `LINK_ALLOC_TIMER` | `0xffffffc08051a110` | `0xffffffc0805199e8` | `-0x728` |
| `LINK_ALLOC_CRED` | `0xffffffc08019c474` | `0xffffffc08019b950` | `-0xb24` |
| `LINK_ALLOC_TASK` | `0xffffffc0801f0d64` | `0xffffffc0801d11d0` | `-0x1fb94` |
| `GEOM_MEMSTART_ADDR` | `0xffffffc08193af78` | `0xffffffc08193a738` | `-0x840` |
| `BNE_LINK` | `0xffffffc0806c82bc` | `0xffffffc0806c7ac0` | `-0x7fc` |

## 两版一致的函数内偏移

| 位置 | 偏移 |
| --- | ---: |
| `do_timer_create` 的目标分配调用 | `+0xac` |
| `prepare_creds` 的目标分配调用 | `+0x2c` |
| `copy_process` 的 task 位置 | `+0x190` |
| `begin_new_exec -> release_task` | `+0x410` |
| `begin_new_exec -> down_read_killable` | `+0x50c` |
| `begin_new_exec -> posix_cpu_timers_exit` | `+0x87c` |
| `begin_new_exec -> exit_itimers` | `+0x88c` |

## 两版一致的 BTF 几何

- `task_struct.cred=0x900`、`real_cred=0x8f8`、`comm=0x910`。
- `sizeof(struct cred)=0xb8`，`cap_effective=0x40`、`cap_bset=0x48`、`cap_ambient=0x50`。
- `sizeof(k_itimer)=0x100`，`it.cpu.node=0x78`。
- `sizeof(selinux_state)=0x80`，`enforcing=0`、`initialized=1`，写目标为 `selinux_state-7`。
- `CAP_FULL=0x1ffffffffff`。

## 112 的 64560 KASLR 数据

```text
worker_thread         0xffffffc080209330
rcu_gp_fqs_loop       0xffffffc08018c334
rcu_gp_kthread        0xffffffc08018be2c
folio_wait_bit_common 0xffffffc0802e9b30
ufshcd_issue_dev_cmd  0xffffffc080e54448
icc_set_bw            0xffffffc080378af0

prepare_creds         0xffffffc08019b924
selinux_state         0xffffffc0827e7a20
```

`syms_aph112.txt` 的 226 个官方 LKM 未定义符号全部解析，`MISSING=0`。

## 运行期边界

- 头文件的 `GEO_TASK_OBJSIZE=5696` 是回退值；运行时会读取 `/proc/slabinfo` 并覆盖为真实 task cache objsize。
- `GEO_POSIX_TIMER_OBJSIZE=256`、32 objects/slab、order-1、fragment page 8192。
- `GEOM_MEMSTART_PFN=0x80000` 为静态推断值，首次实机需用 `/proc/iomem` 或内核日志复核。
- KASLR slide 必须每次启动重新测量，不能从旧日志或其它 boot 代入。
- 首次运行先做 `--check` 和 KASLR 交叉校验，再验证 rootd；不把静态推导当成实机成功证明。

## 二进制哈希

```text
112 exploit-android-key-ptr:
23c2fde655197602fbac23df92ddbdae95e56ec71c407f683345a1cc7fb7b0be

共用 pc98260-su:
696240ec583616d3677e693d1e5d3783b7f590b682ace8d7ca830bc757516ca5

112 kaslr_slide_aph112:
7196a6d77421bd5e045505622391054609b47015c5ce44a46da7c540745d81a5
```
