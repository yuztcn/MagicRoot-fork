# 98260 上游初始代码来源核查

日期：2026-11-14  
范围：MagicRoot `binary-sources/98260-6.12/` 与相关 98260 公开仓库  
方法：源码逐文件哈希、代码行相似度、函数/字符串交集、提交时间线；只读分析

---

## 一、结论

**MagicRoot 的 98260 代码不是单一上游，而是分层来源；不存在一个“唯一真正上游”。**

| 层 | 实际来源 | 证据 |
| --- | --- | --- |
| 初始 6.12 plant / fake-cred 链 | **xiaomi9pmroot** `plant/uaf_plant_v6.c` | MagicRoot 文件头明确写 "unchanged from xiaomi9pmroot/uaf_plant_v6.c"；代码行相似度 **0.571**；共享 68 个函数、141 个字符串 |
| real-cred 三原语（当前最终写入） | **woshigenm/CVE-2026-98260** `src/uid0.c` + `app/native/cve98260.c` | MagicRoot `docs/98260-REAL-CRED-PORT-PLAN.md` 称其为“上游”；`PLANT_ZERO/PLANT_PTR/PLANT_SELINUX`、`run_plant`、`mintwait`、`collect_site_pid` 只在该上游与 MagicRoot 中出现 |
| rootd/su 组件 | **xiaomi9pmroot 与 popsicle 共享**；popsicle 的 `8525ad4` 是全 GitHub 最早公开提交 | `pc98260_su.c` 逐字节相同；`pc98260_rootd.c` 103/104 行相同 |
| hnubl 3.1.8 的 G142 快照 | **MagicRoot `4047cac` 基线（2026-11-03）** | `uaf_plant` 逐字节相同；rootd/stubs/su 内容相同（CRLF）；0 处 `PLANT_*`；**不含** woshigenm real-cred 层 |
| YuKongA/CVE-2026-98260 | **woshigenm 的下游**，不是 MagicRoot 上游 | 其 `NOTICE` 明确写 `timer/timer.c derives from woshigenm ... src/uid0.c and src/poc.c`；与 MagicRoot plant 相似度仅 0.047 |
| OnePlus16-Jailbreak | **woshigenm 的下游**，不是 MagicRoot 上游 | `exploit/src/plant_core.inc` 头注释 "Adapted from woshigenm/CVE-2026-98260 (MIT)" |
| popsicle 的 plant | **未被 MagicRoot 使用** | `exploit-android-key-ptr.c` 与 MagicRoot plant 相似度 0.036；仅 rootd/su 共享 |

---

## 二、提交时间线

| 项目 | 仓库创建 | 初始提交 / 关键提交 | 相关文件 |
| --- | --- | --- | --- |
| `V4bel/InfinityCore` | 2026-10-16 15:36:38Z | `2fb73ac` 2026-10-16 15:35:58Z；`8509bf6` 10-17 | `timer/CVE-2026-98260-ubuntu.c`（概念原型 `locker`/`killer`/`wait_zombie_without_reap`）；`android.c` 仅为 239B 占位 |
| `ylh440104/InfinityCore-Android` | 2026-10-18 23:26:39Z | `1f4116e` 2026-10-18 23:29:42Z | `timer_lpe.c`（与 `V4bel` 行相似度 `0.519`） |
| `quyicheng03-boop` (64560) | 2026-09-05 11:06:27Z | `cb2a923` 2026-09-05 11:24:46Z | `src/temp-su.c`（`dada_temp_su_v1`，不含 `pc98260`） |
| popsicle (`quyicheng03-boop`) | 2026-10-23 08:56:37Z | `8525ad4` 2026-10-23 08:56:24Z（`70829ac` 10-29 转 MIT） | `src/pc98260_su.c`、`src/pc98260_rootd.c`、`src/exploit-android-key-ptr.c` |
| nezha (`quyicheng03-boop`) | 2026-10-23 12:12:15Z | `e0f3ec8` 2026-10-23 12:11:58Z（`17368b1` 10-29 转 MIT） | 自述从同作者 popsicle 移植；`pc98260_su.c`/`pc98260_rootd.c` 与 popsicle 逐字节同哈希 |
| xiaomi9pmroot（原名 `yt-root-98260`） | 2026-10-25 12:19:11Z | `d37dd2b` 2026-10-25 12:17:14Z（MIT） | `plant/uaf_plant_v6.c`、`plant/pc98260_su.c`、`plant/pc98260_rootd.c` |
| woshigenm | 2026-10-25 19:20:05Z（scaffold） | `bc53368`/`f77fd4e` 2026-10-26 12:45:42Z；`d5475c5` 2026-10-26 13:30:26Z | `src/poc.c`、`src/exp.c`、`src/uid0.c` |
| YuKongA | 2026-10-27 12:53:47Z | `ad1f4e7` 2026-10-27 12:52:48Z | `timer/timer.c` |
| MagicRoot | 本仓库历史 | `4047cac` 2026-11-03 17:11:41 +0800 首次纳入 `uaf_plant_61258.c` | 6.12 plant |

注：
- `ziadhany/ExploitArchive` (`pocs_archive/2026/CVE-2026-98260.json`) 留存了 `EAEdward/yt-root-98260` 的原始 URL，与 `xiaomi9pmroot` 初始提交说明（`yt-root-98260: 一键 root 工具链`）及 `LICENSE` 版权行 `Copyright (c) 2026 yt-root-98260 contributors` 一致，证实 `xiaomi9pmroot` 系由 `yt-root-98260` 更名而来。
- `V4bel/InfinityCore` 与 `xiaomi`（`0.025`）、`woshigenm`（`0.041`）、`popsicle`（`0.026`）源码行相似度极低，说明后者均未直接复用 `V4bel` 的 Ubuntu C 源码，而是仅在原理与概念命名上沿用了 `locker` / `killer` / `wait_zombie` 模式。
- 时间戳只能证明**公开提交顺序**，不能证明私下开发顺序。xiaomi 的 plant 早于 woshigenm 的公开代码约 24 小时，两者更可能共享一个未公开单独发布的早期 Android 实现，或由研究基线独立演化。

---

## 三、代码相似度矩阵

按去空行/纯注释后的代码行做 `difflib.SequenceMatcher`：

|  | MagicRoot | xiaomi | woshigenm uid0 | woshigenm cve98260 | YuKongA | OP16 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MagicRoot | — | **0.571** | 0.027 | 0.044 | 0.047 | 0.052 |
| xiaomi | 0.571 | — | 0.075 | 0.072 | 0.036 | 0.033 |
| woshigenm uid0 | 0.027 | 0.075 | — | 0.449 | **0.416** | 0.276 |
| woshigenm cve98260 | 0.044 | 0.072 | 0.449 | — | 0.296 | 0.217 |
| YuKongA | 0.047 | 0.036 | 0.416 | 0.296 | — | **0.642** |
| OP16 | 0.052 | 0.033 | 0.276 | 0.217 | 0.642 | — |

聚类很清楚：

```text
MagicRoot ──0.571── xiaomi
woshigenm ──0.416── YuKongA ──0.642── OP16
MagicRoot / xiaomi 与 woshigenm 系之间只有 0.03–0.08
```

因此：

- **MagicRoot 的 plant 主体**来自 xiaomi，不是 woshigenm/YuKongA/OP16；
- **woshigenm / YuKongA / OP16 是另一簇**，三者互相高度相关；
- 不能因为 MagicRoot 用了 woshigenm 的 real-cred 原语，就把整份 plant 说成
  woshigenm 下游。

---

## 四、MagicRoot 内部的分层证据

### 4.1 初始 plant：xiaomi

`binary-sources/98260-6.12/uaf_plant_61258.c` 头注释：

```text
PORT NOTE (madrid / Xiaomi 18 Pro Max, g284297031c53):
  ... The logic below is unchanged from xiaomi9pmroot/uaf_plant_v6.c
  except where marked "PORT:" ...
```

与 xiaomi 的 `uaf_plant_v6.c`：

- 代码行相似度 0.571；
- 共享 68 个函数，包括 `ask_child`、`child_race`、`leak_task`、
  `measure_slide`、`one_uaf`、`collect_nth`、`destroy_rings` 等；
- 共享 141 个字符串。

### 4.2 real-cred 原语：woshigenm

MagicRoot `docs/98260-REAL-CRED-PORT-PLAN.md`（2026-11-09）明确写：

- “上游与酷安 feed/74888861 推荐的 real-cred（原位修改真实 cred）”；
- “上游 `src/uid0.c`（本机 clang 编译）：cred leak 成功……”；
- “上游 `src/kernel_profile.h` 的 `struct cve98260_profile` 字段与我方
  `pc98260_target_*.h` 一一对应”。

`docs/98260-REAL-CRED-ROUTE-TEST.md` 标题直接写
“upstream woshigenm/CVE-2026-98260”，并分析其 `run_plant`、
`PLANT_ZERO/PLANT_PTR/PLANT_SELINUX`、`lifecycle.h`。

当前 MagicRoot `uaf_plant_61258.c` 包含：

```text
PLANT_ZERO / PLANT_PTR / PLANT_SELINUX（以 TILE_* 与注释形式）
leak_real_cred / mintwait / collect_site_pid
```

这些在 xiaomi `uaf_plant_v6.c` 中**不存在**（xiaomi 只有 `leak_cred`），
却在 woshigenm `src/uid0.c` / `app/native/cve98260.c` 中存在
（woshigenm 侧函数名为 `run_plant` / `leak_cred`）。说明它们是
2026-11-09 real-cred 移植时从 woshigenm 引入的**增量层**。

### 4.3 rootd/su：xiaomi 与 popsicle 共享

- `pc98260_su.c`：xiaomi 与 popsicle 逐字节相同（86 行）。
- `pc98260_rootd.c`：104 行中 103 行相同，仅权限检查一行不同。
- MagicRoot 的 `su98260.c` 与两者内容相同；`rootd.c` 是共享 rootd 的扩展版。

---

## 五、YuKongA 仓库的实际作用

`YuKongA/CVE-2026-98260`（MIT；`tools/extract` 为 Apache-2.0）：

- `NOTICE` 明确：

  ```text
  timer/timer.c derives from woshigenm/CVE-2026-98260 src/uid0.c
  and src/poc.c, used under the MIT license.
  ```

- 结构：`timer/timer.c`（1,825 行）+ `timer/kbuilds/*.h` + `tools/extract`；
  面向 `6.12.69-android16-6-g242e1a07f878` 与 `g5fd39602326e` 两个 build。
- 与 woshigenm `uid0.c` 相似度 0.416；与 MagicRoot plant 仅 0.047。
- 因此 YuKongA 是 **woshigenm 的 6.12.69 设备移植/下游**，不是 MagicRoot 的
  上游，也不包含 MagicRoot 的 `uaf_plant_61258.c` 代码。

---

## 六、最终判定

1. **MagicRoot 的初始 6.12 plant 代码来源是 xiaomi9pmroot**，不是 YuKongA、
   不是 woshigenm、不是 popsicle。
2. **MagicRoot 当前 real-cred 最终写入原语来自 woshigenm**，属于 2026-11-09
   之后的增量移植。
3. **rootd/su 是 xiaomi 与 popsicle 的共享组件**，不能只归给其中一方。
4. **YuKongA 与 OnePlus16-Jailbreak 都是 woshigenm 的下游**，与 MagicRoot 的
   plant 主体是平行关系；它们不是 MagicRoot 的上游。
5. **popsicle 的 plant 未被 MagicRoot 使用**；popsicle 只在 rootd/su 上有共享。
6. 若声明要写“MagicRoot 的 98260 初始代码来源”，准确写法是：

   ```text
   初始 plant：xiaomi9pmroot（MIT）uaf_plant_v6.c
   real-cred 原语：woshigenm/CVE-2026-98260（MIT）src/uid0.c + cve98260.c
   rootd/su：xiaomi9pmroot 与 popsicle 共享
   YuKongA / OnePlus16：woshigenm 下游，不是本链上游
   ```

---

## 七、hnubl 3.1.8 的快照边界

hnubl 的 `adaptation/aph136g142/src/` 不是 MagicRoot 当前源码，而是
**MagicRoot `4047cac`（2026-11-03）基线**：

| 文件 | hnubl vs `4047cac` |
| --- | --- |
| `uaf_plant_61258.c` | **逐字节相同**（2,795 行，`35402f5d…`） |
| `rootd.c` | 内容相同，仅 CRLF（146 行） |
| `su98260.c` | 内容相同，仅 CRLF（86 行） |
| `stubs.c` | 内容相同，仅 CRLF（2 行） |
| `pc98260_target.h` | 修改：移除 G856/61258C，新增 APH136G142 |
| `kaslr_slide_aph136g142.c` | 与 MagicRoot 64560 源逐字节相同 |

hnubl G142 源码中 `PLANT_ZERO`/`PLANT_PTR`/`PLANT_SELINUX`/
`leak_real_cred`/`mintwait` 均 0 命中。因此：

- hnubl 3.1.8 的 98260 G142 直接使用 **xiaomi 系 fake-cred 基线**；
- **不要**把 hnubl 3.1.8 描述为直接使用 woshigenm real-cred 或 YuKongA；
- woshigenm 的 real-cred 层是 MagicRoot 2026-11-09 之后的演进，只有
  hnubl 未来同步 MagicRoot 当前源码时才需要补该声明。

---

## 八、rootd/su 的全 GitHub 最早公开提交与生态分化

方法：对全 GitHub 代码索引执行 `filename:pc98260_rootd.c` / `filename:pc98260_su.c`（返回 10 仓库），并以 `"pc98260-root.sock"`（52 命中）、`PC98260_SOCK`（29 命中）、`PC98260_STOP_FILE`（6 命中）、`wait_zombie`（319 命中）、`kick_rss`（61 命中）及仓库关键词 `CVE-2026-98260`（57 仓库）作交叉检索与全树核验：

| 仓库 | 最早提交 | 时间（UTC） | 形态与备注 |
| --- | --- | --- | --- |
| `quyicheng03-boop/CVE-2026-98260-popsicle-android` | `8525ad4` | **2026-10-23 08:56:24** | 最早公开提交；10-23 `48accc8` 声明暂未开源，10-29 `70829ac` 转 MIT |
| `quyicheng03-boop/CVE-2026-98260-nezha-android` | `e0f3ec8` | 2026-10-23 12:11:58 | 同作者从 popsicle 移植；`su`/`rootd` 逐字节同哈希 |
| `sganggs/CVE-2026-98260-BRM-AN00` | `99f4f4b` | 2026-10-24 18:14:05 | `su`/`rootd` 与 popsicle 逐字节同哈希 |
| `EAEdward/xiaomi9pmroot` | `d37dd2b` | 2026-10-25 12:17:14 | `su` 逐字节同、`rootd` 103/104；另行独立实现 `uaf_plant_v6.c`（MIT） |
| `addxemmm/CVE-2026-98260-pudding-android` | `9fe8c41` | 2026-10-26 05:13:07 | `su`/`rootd` 与 popsicle 逐字节同哈希 |
| `AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak` | `f0a6112` | 2026-10-26 09:54:33 | 未被 `filename:` 索引命中；`su`/`rootd` 逐字节同 popsicle |
| `Lw5959/xring-cve-2026-98260` | `933b70f` | 2026-10-27 01:01:16 | `su` 逐字节同 popsicle（86 行），`rootd` 扩至 242 行（保留 86 行） |
| `b1gmang0/CVE-2026-98260-pandora-lpe` / `colorgarden` | `b9c46a8` | 2026-10-27 07:14:30 | 共享历史首提交；`su`/`rootd` 与 popsicle 逐字节同哈希 |
| `4627488/cve-2026-98260-nezha` | `db6d609` | 2026-10-28 02:15:40 | 仅脚本/文档，构建时从 `b1gmang0` 拉取源码，本身未分发 C 源码与二进制 |
| `Feiman55/CVE-2026-98260-GhostKey` | `f8525fe` | 2026-10-29 01:37:46 | GhostKey 改写版（`pc98260_su_main` 119 行 + `PC98260_STOP_FILE`） |
| `SecPhases/CVE-2026-98260-GhostKey` | `59b292a` | 2026-10-29 05:13:24 | 同 GhostKey 改写版（`su`/`rootd` 同 SHA-256） |
| `quyicheng03-boop/CVE-2026-98260-dada-android` | `b41bfe3` | 2026-10-29 13:47:37 | 同作者 10-29 适配，扩展至 `98`/`119` 行 |
| `superboyyy/HOneClick` | `9c6769f` | 2026-10-31 14:16:00 | 明确注明 `native/cve98260/` 改自 `sganggs`（`su` 仅改 socket 路径、`rootd` 保留全部主体），并标明禁止公开发布 |
| `feilongproject/redmi-k100-root` | `bcb3964` | 2026-11-03 13:12:09 | 打包预编译 `bin/cve98260`，二进制内含 GhostKey 符号 `pc98260_rootd_stop_main` / `PLANT_FAST` |
| `xingranya/onekeyjb` | `bd72c36` | 2026-11-04 00:35:55 | 内置 GhostKey `pc98260_rootd.c` / `su.c` |
| `heibaome/kernel` | `504e538` | 2026-11-04 14:17:24 | 内置 GhostKey `pc98260_rootd.c` / `su.c` |
| `starriv/CVE-2026-98260-Xiaomi-17-Pro-Max` | `0871888` | 2026-11-05 03:16:17 | `su` 逐字节同、`rootd` 扩写 |
| `hawyn2018/honor_8e5_ubl` | `1f6d114` | 2026-11-08 15:44:51 | 接入 MagicRoot `4047cac` 基线（`su` 86 行 CRLF、`rootd` 146 行） |
| `skyrocketingHong/CVE-2026-98260_nezha` | `e73b9a2` | 2026-11-13 10:49:33 | 沿用 `4627488` 模式，仅提供补丁与清单，不分发上游 exploit 源码/二进制 |

平行无 `pc98260_rootd/su` 生态（主要走 `woshigenm` real-cred / 直接 `ksud late-load` 或原理重写）：
- `woshigenm/CVE-2026-98260`（10-26）→ `YuKongA/CVE-2026-98260`（10-27）→ `Yunnijian/OnePlus16-Jailbreak` / `Shark` → `yoro1836/SamTimer`（11-01）→ `ANYAEGW/CVE-2026-98260-amg-an00`（11-06）；
- `qq2770355800/ExtractKit`（11-11，原理独立重写 + 对照 `V4bel` PoC）；
- 2026-10-23 之前创建的候选仓库（`V4bel/InfinityCore` 10-16、`ylh440104/InfinityCore-Android-CVE-2026-98260` 10-18、`jadedFella/lpe-study-notes` 10-18、`Yunnijian/Shark` 10-20、`NanoTurtle1145/root-my-s24` 08-16）均不含 `pc98260_rootd`/`su`。

**结论：popsicle 的 `8525ad4`（2026-10-23 08:56:24Z）仍是全 GitHub 当前可见的 `pc98260_rootd.c`/`pc98260_su.c` 最早公开提交；未发现更早的公开来源。** 保留：GitHub 代码搜索只索引默认分支当前文件且存在索引遗漏，无法排除已删除或私有仓库中更早的副本。

---

## 九、限制

- 只读静态比对，未执行任何 98260 载荷。
- 公开提交时间不能证明私下开发顺序；xiaomi 与 woshigenm 共享的
  `killer_fn`/`locker_fn`/`wait_zombie`/`kick_rss`/`leak_cred` 可能来自更早的
  共同实现，该共同祖先未在这两个公开仓库中单独出现。
- 代码行相似度用于定位同源关系，不构成法律意见。
