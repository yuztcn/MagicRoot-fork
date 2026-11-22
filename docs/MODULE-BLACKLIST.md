# vendor module_blacklist 与 KSU 加载（MagicRoot / 98260）

2026-11-22 在 g19a（MTN-AN00）的 CVE-2026-99491 日志里定位到：`finit_module`
在 SELinux 检查通过之后返回 `-EPERM`。g19a Image 的 config 显示
`CONFIG_SECURITY_LOCKDOWN_LSM` 未启用、`MODULE_SIG_FORCE=y`（99391 先清
sig_enforce），反汇编 `load_module` 可见 `blacklisted()`：

```
ldr x23, [x8, #0x6d8]   ; module_blacklist (char*，可写 .bss)
cbz x23, ...            ; NULL -> 跳过
strcspn(p, ","); bcmp(info->name, ...)  ; info->name = "kernelsu"
```

命中返回 `-EPERM`（`kernel/module/main.c` "Module %s is blacklisted"）。
Honor 的 bootloader 在 cmdline 里把 `kernelsu` 列进了 `module_blacklist`。

## permissive 也统一为「写-读回-验证」

两套 plant 的 SELinux 段现在都收敛到 `try_permissive()`（与 99491 exp 的
兜底一致）：

- 目标 `selinux_link - 7`：8 个零字节的最后一字节落在 `enforcing`，前 7
  字节落在 `avc_latest_notif_update.notif_lock`（state-8，零值即未加锁）；
- 每次写完读 `/sys/fs/selinux/enforce`，读到 `0` 才返回成功，否则最多
  重试 4 次（喷写可能 miss）；
- 61157 与 h1c 共用同一语义，日志 `[selinux] permissive (verified)`；
- `selinux_state = selinux_avc + 0x1820` 在 6.1/6.6/6.12/6.18 十个本地
  ELF 上一致（99491 侧已按此实现，无需新 key）。

## plant 侧的修法

`uaf_plant` 的 `one_uaf(target)` 会在 `target` 处写 8 个零字节（现在用于
`sig_enforce` 和 `selinux_state-7`）。`module_blacklist` 是普通 `char *`，
把指针对应地址交给 `one_uaf()` 即可让 `blacklisted()` 走 `cbz` 跳过；模块
仍用真名 `kernelsu` 加载，管理器和 `/proc/modules` 检测不受影响。

已改：

- `binary-sources/61157-g264/uaf_plant.c`：`--ksu` 段在清 `sig_enforce`
  之后清 `MODULE_BLACKLIST_LINK`（最多 3 次，打印
  `[ksu] zero module_blacklist attempt ...`）；
- `binary-sources/98260-h1c/uaf_plant.c`：`profile 115`（ge186）默认清
  `MODULE_BLACKLIST_LINK_115`；新增 `--module-blacklist-link <addr>` 可在
  运行时覆盖，0 表示跳过。

## 每构建地址

61157 系列（brm_plant 的链接基址 `0xffffffc080000000`；99491 profile 用
`0xffffffc008000000`，两者相差 `0x78000000`，KASLR slide 会吸收这个差值）：

| 构建 | module_blacklist（plant 基址） |
| --- | --- |
| g19a495a97bff（MagicPad3，两份构建数据布局相同） | `0xffffffc0826cf6d8` |
| g2646292297b1 | 需该构建 Image（暂无） |
| g7d3922fade43（ELP） | 需该构建 Image |

98260 / h1c 系列（`0xffffffc080000000` 基址，地址直接可用）：

| 构建 | module_blacklist |
| --- | --- |
| ge186062ea75f（BRM-AN00 / WKL，HOneClick 115） | `0xffffffc08296f9b8` |
| gfee2325de189（H1C 117，符号布局与 ge186 相同） | `0xffffffc08296f9b8` |
| g928d1bb4f1d7 / gf957 / g7fcbff | 需各自 Image |

## 构建

61157（静态 musl，例如 zig）：

```sh
zig cc -target aarch64-linux-musl -O2 -std=gnu11 -D_GNU_SOURCE -static \
  -fno-stack-protector -fno-pic -no-pie -I<offsets-dir> \
  -DMODULE_BLACKLIST_LINK=0xffffffc0826cf6d8 \
  uaf_plant.c pc98260_rootd.c -pthread -o brm_plant_magicpad
```

`offsets.h`（MagicPad3，plant 基址）：

```
TIMER_LINK     0xffffffc0803be8c0   /* do_timer_create+0x94 */
CRED_LINK      0xffffffc08010b7f8   /* prepare_creds+0x20 */
SELINUX_LINK   0xffffffc0826fca40
LINK_USER_NS   0xffffffc0820d0748
LINK_ROOT_USER 0xffffffc0820d09d8
LINK_GROUPS    0xffffffc0820d1cf8
LINK_UCOUNTS   0xffffffc0820d2268
```

6.18（动态 PIE）：

```sh
clang -O2 -s -fPIE -pie -Wno-macro-redefined \
  -DMODULE_BLACKLIST_LINK_115=0xffffffc08296f9b8 \
  uaf_plant.c pc98260_rootd.c -o exploit-android-key-ptr
```

重建后要更新 HyperBreak 的 `src/jb/assets/magicroot/MANIFEST.tsv`
（sha256/size）并重打 APK；设备侧日志应出现
`[ksu] zero module_blacklist attempt ...`，随后 `ksud late-load` 或
insmod 成功、`/proc/modules` 出现 `kernelsu`。

g264 / ELP / g7fcbff / gf957 的地址需要对应 boot.img 才能补；拿到后按
`module_blacklist = 该构建 modules_disabled + 8` 或符号表直接取值。
