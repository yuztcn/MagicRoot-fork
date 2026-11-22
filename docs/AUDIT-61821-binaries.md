# 6.18.21 g928 binary audit

## Target

```text
kernel  6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k
models  WKL-AN20 / WKL-AN80
boot    work/61821/boot-61821.img
kernel  offset 4096, size 43,207,168
sha256  65fc12d5c39002c5f2ff2e14c439f9c3fb7489272450a7224cc84acd0a8a4705
```

`pc98260_target_61821.h` declares the same kernel sha256.

## KASLR

98260 uses its own helper set:

```text
forker_618      663,344
kaslr_slide       7,984
grab_slide_618.sh
```

Anchor addresses were checked against the g928 kernel symbol table:

```text
worker_thread      ffffffc0801352b4
rcu_gp_kthread     ffffffc0802959fc
rcu_gp_fqs_loop    ffffffc080295bc0
```

HOneClick is a 64560 chain. Its `forker`/`kaslr_slide` binaries are not used in
the 98260 path. `run98260.sh` also rejects an external slide unless it is
2 MiB aligned and has at least 3 votes.

## KSU LKMs

All 6.18 templates are checked against `syms_61821_kernelsu.txt`:

```text
ksu-template.ko                 missing=0
ksu-template-61821-bakasu.ko    missing=0
ksu-template-61821-next.ko      missing=0
ksu-template-61821-sukisu.ko    missing=0
ksu-template-61821-fina.ko      missing=0
```

`ko_patch` rewrites vermagic to the exact kernel release and patches the
undefined symbols from the table. Manager selection for 61821 follows BRM:
BakaSU uses `com.resukisu.resukisu`, `ksud late-load --kmi android17-6.18
--package-name com.resukisu.resukisu`; official KernelSU is only used when the
user selected it.

## UAF safety

- single victim by default
- multi only with `PC98260_MULTI_VICTIM=1`
- stop after first single miss; do not reap the parked victim
- no order-0 AIO/pipe fallback for the order-1 timer page

## g928 BTF cross-check

Extracted the BTF blob from `work/61821/kernel-61821.bin`
(offset `0x1b46550`, 4,239,376 type bytes, 2,742,461 string bytes) and parsed it.

```text
k_itimer size          0x180
k_itimer.it offset     0xe0
task_struct.cred       0x908
task_struct.real_cred  0x900
cred size              0xb8
cred.uid/gid           0x08 / 0x0c
cred.suid/sgid         0x10 / 0x14
cred.euid/egid         0x18 / 0x1c
cred.fsuid/fsgid       0x20 / 0x24
cred.cap_*             0x30 / 0x38 / 0x40 / 0x48 / 0x50
cred.security          0x80
cred.user/user_ns      0x88 / 0x90
cred.ucounts           0x98
cred.group_info        0xa0
```

These match `pc98260_target_61821.h`.

`task_struct` BTF size is `0x1280`; the actual SLUB object size is measured
at runtime from `/proc/slabinfo` (`g_task_obj`), because the cache object can be
larger than the struct.  Do not hardcode the BTF size into the allocation filter.
