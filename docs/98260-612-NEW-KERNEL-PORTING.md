# 98260 BRM（6.12.x/6.6.x）新内核移植辅助

## 这是什么

`tools/Chain98260TargetDraft.java` 是一个**仅供维护者在 PC/本机使用的离线工具**，
从用户提供的 `boot.img` 本地解析出一份 `pc98260_target_<id>.h` **草稿**。
它复用 APK 里已经在用的 `KernelProfileGenerator`（6.18.x 自适应生成器、
6.12.x/6.6.x 纯 kallsyms 导出都靠它），新增了两项：

1. 对 `do_timer_create` / `prepare_creds` 做最小化反汇编：在函数体内找第一条
   目标为 `kmem_cache_alloc*` 的 `BL` 指令，取该调用指令地址 +4 作为
   `LINK_ALLOC_TIMER` / `LINK_ALLOC_CRED`（即内核分配器 tracepoint/kprobe
   会观察到的 `_RET_IP_`）。
   2026-11-20 起增加回退：较新的 6.12.x 构建不再把 `alloc_posix_timer`
   内联进 `do_timer_create`（首发样本 6.12.81 g52d15df5db87），此时
   `do_timer_create` 体内没有 `kmem_cache_alloc*` BL，工具改扫
   `alloc_posix_timer` 体内，草稿注释按实际所属函数标注
   （`alloc_posix_timer+0x28`）。扫描对"体内无 kmem_cache_alloc* BL"
   是 fail-closed 的，两级尝试不会误配；人工核对时注意确认该函数
   内其余分配点不在默认 timer_create 路径上。
2. 复用已有的 BTF 解析（`cred`/`k_itimer`/`task_struct`），导出草稿里的
   `GEO_*` 字段。

## 它不是什么

- **不是** APK 功能：`MainActivity.java`、`run.sh`、`run98260.sh` 都不引用
  这个工具或它的输出；对设备端分派、部署、ASSETS 注册没有任何影响。
- **不会**让 App 自动支持一个全新的 6.12.x/6.6.x 内核。`exploit-android-key-ptr`
  是逐内核单独编译的二进制（已核对过仓库现有的 11 个 6.12/6.6 payload 目录，
  体积和哈希两两不同），这些常量是**编译期**写死进二进制的——不管常量怎么
  得到，新内核永远需要重新编译一个新二进制，这个工具只是把"手工反汇编"
  这一步自动化、产出草稿，不改变"必须重新编译+真机验证"这个事实。

## 为什么 LINK_ALLOC_TIMER / LINK_ALLOC_CRED 不能从别的构建借用

这两个偏移量是函数内部的调用点，**不是**跨内核分支稳定的常量，已用仓库里
现有的手工标注反证：

| 内核分支 | `do_timer_create+?` | `prepare_creds+?` |
|---|---|---|
| 6.12.x（g856/61258/61258b/61258c/6123/6138/6138y） | `+0xac` | `+0x2c` |
| 6.12.81（g52d15df5db87，alloc_posix_timer 未内联） | `alloc_posix_timer+0x28` | `+0x2c` |
| 6.6.x（6658/66118/f171/g554/6689） | `+0x94` | `+0x20`（6689 为 `0x20`，66118/6658 同为 `0x20`） |
| 6.18.x（61821） | `+0xb8` | `+0x2c` |

同理 `LINK_ALLOC_TASK`（`copy_process` 里 task_struct 分配的调用点）在
**同一个** 6.6.x 分支内部都不稳定（6.6.89 是 `+0x13c`，6.6.118 是 `+0x144`），
这也是为什么这个工具干脆不产出它——已确认 `binary-sources/*/uaf_plant_61258.c`
里这个常量根本没被引用，草稿里编出一个用不到、还不稳定的值没有意义。

## 已验证的程度

用两份真实 boot_ota 镜像（`6.12.23-...-gcd85666d7884-...`、
`6.6.89-...-g082e5a98dac1-...`，与仓库已有的 `g856`/`6689` 构建完全一致）
跑过这个工具，输出与手工编写的
`binary-sources/98260-6.12/pc98260_target_g856.h` /
`binary-sources/6689/pc98260_target_6689.h` 逐项核对：

- `LINK_SELINUX_STATE`/`LINK_INIT_USER_NS`/`LINK_ROOT_USER`/`LINK_INIT_GROUPS`/
  `LINK_INIT_UCOUNTS`/`GEOM_MEMSTART_ADDR`：精确匹配（纯 kallsyms 查表，
  本来就应该精确）。
- `LINK_ALLOC_TIMER`/`LINK_ALLOC_CRED`：两份镜像、两个不同内核分支，
  反汇编启发式算出的偏移量与人工标注**完全一致**（+0xac/+0x2c 和
  +0x94/+0x20）。
- `GEO_TASK_CRED`/`GEO_KITIMER_IT`/`GEO_KITIMER_SIZE`/`GEO_CRED_SIZE` 及
  全部 `cred` 字段偏移：精确匹配。

这只是**两个样本**，且两个样本都是仓库已经验证过的构建（用来验证算法，
不是用来证明算法对任何未来的新内核都成立）。对一个真正全新、谁都没有
实机验证过的构建：

- 反汇编启发式有可能命中错误的 `kmem_cache_alloc*` 调用（例如该函数在
  某个新内核版本里因为编译器内联策略变化，在目标调用之前插入了另一个
  不相关的 `kmem_cache_alloc` 调用）——这个工具目前找的是**第一个**匹配，
  没有办法自证"这就是对的那一个"。
- `GEO_CRED_*`/`GEO_KITIMER_*` 依赖镜像里确实嵌入了完整 BTF；如果某个
  新构建关闭了 `CONFIG_DEBUG_INFO_BTF` 或精简了 BTF，这个工具会直接报错
  （fail closed），不会猜测偏移。

## 正确的使用流程

```sh
mkdir -p /tmp/draft-out
javac -d /tmp/draft-out \
    main/compose-app/app/src/main/java/com/aoki/magicroot/KernelProfileGenerator.java \
    tools/Chain98260TargetDraft.java
java -cp /tmp/draft-out com.aoki.magicroot.Chain98260TargetDraft \
    /path/to/boot.img /tmp/draft-out/pc98260_target_NEW.h
```

1. 跑上面的命令，得到 `pc98260_target_NEW.h` 草稿。
2. **人工**用反汇编器（Ghidra/IDA/capstone）核对 `LINK_ALLOC_TIMER` /
   `LINK_ALLOC_CRED` 这两处调用点，确认是目标分配路径唯一匹配，不是误判。
3. 参照 `binary-sources/98260-6.12/build-98260-6.12.ps1` 编译出针对这个
   内核的新 `exploit-android-key-ptr` 二进制。
4. 在对应真机上走完整 98260 链路验证（不是预检，是真的触发一次 UAF 并确认
   成功提权），确认没有 panic / 误判成功。
5. 验证通过后，才把新的 `98260-<id>/` 资产目录、`run.sh`/`run98260.sh` 的
   内核分派 case、`kernel_profiles.sh` 的 flavor 选择加进代码，并更新
   `main/compose-app/.../MainActivity.java` 的 `ASSETS_98260` 注册（见
   `CLAUDE.md` 第 5 节资产修改工作流）。
6. 在本文件和 `BINARY-SOURCES.md` 记录这个新构建的验证状态
   （真机通过 / 仅静态验证），不要把第 4 步跳过的构建写成"已验证"。

## 相关

- [[docs/ADAPTIVE-61821-PROFILE.md]]：6.18.x 的完整在机自适应生成（已接入
  App 运行链路），以及 6.12.x/6.6.x 的纯 kallsyms 导出（已接入 App，但只
  服务于已有内核的 KSU LKM 符号表，不解决本文档说的"全新内核"问题）。
- `binary-sources/98260-6.12/pc98260_target_*.h`、`binary-sources/6689/`、
  `binary-sources/6658/`、`binary-sources/66118/`：人工编写的、已经在用的
  per-build 常量文件，是这个工具输出格式的参照样本。
