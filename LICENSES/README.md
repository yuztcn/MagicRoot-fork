# License texts

## 0. 项目自身许可

| File | Component | License |
| --- | --- | --- |
| `AGPL-3.0.txt` | MagicRoot 自研代码（应用 UI/控制器、部署脚本、profile 生成与适配修改） | AGPL-3.0（1.0.6 起）；1.0.5 及更早版本为 MIT |

## 1. 源码复用 / 二次修改组件

| File | Component | License |
| --- | --- | --- |
| `Xiaomi9pmroot-MIT.txt` | `EAEdward/xiaomi9pmroot`（原名 `yt-root-98260`，6.12/6.6 初始 plant 与共享 `rootd`/`su`） | MIT |
| `Woshigenm-MIT.txt` | `woshigenm/CVE-2026-98260`（98260 real-cred 三原语增量）与 `woshigenm/CVE-2026-98937`（可选 KASLR slide oracle PoC） | MIT |
| `Popsicle-MIT.txt` | `quyicheng03-boop/CVE-2026-98260-popsicle-android`（共享 `pc98260_rootd`/`su` 最早公开来源，10-29 转 MIT；未使用其 plant） | MIT |
| `HOneClick-MIT.txt` / `HOneClick-NOASSERTION.md` | `superboyyy/HOneClick`（`KernelProfileGenerator.java`、6.18 H1C、64560 审计源码；根 `LICENSE` 为 MIT 带尾注，API 标 `NOASSERTION`） | MIT (scope-noted) |
| `CVE-2026-64560-public-MIT.txt` | `Feng1586/CVE-2026-64560-public`（64560 零写原语；根 `LICENSE` 为 MIT 带尾注，API 标 `NOASSERTION`） | MIT (scope-noted) |
| `GhostLock-MIT.txt` | CVE-2026-64560 tooling（GhostLock） | MIT |
| `Honor-UBL-Adaptation-MIT.txt` | `honor_ubl` 3.1.1 `aph136g142` 双链路适配资料 | MIT |
| `Apache-2.0.txt` | Miuix、Jetpack Compose / AndroidX、Shizuku API（`XiaoTong6666` fork）、`Kyant0/AndroidLiquidGlass` | Apache-2.0 |

## 2. 未用源码、随包分发预编译产物

| File | Component | License |
| --- | --- | --- |
| `GPL-2.0.txt` | KernelSU、KernelSU-Next、BakaSU（预编译 `.ko` 模板与 6.1/6.18 历史回退 `ksud`） | GPL-2.0 |
| `GPL-3.0.txt` | SukiSU Ultra（预编译 `.ko` 模板）；6.1.x CGA 模块参考源码（`binary-sources/6157-g264/cga/`） | GPL-3.0 / GPL |
| upstream only | FinaSU、SuSFS（`inforcqb/susfs4ksu-lkm` 预编译 LKM / `susfs_insmod`） | 遵循各自上游仓库声明 |

## 3. 仅技术参考（未复用源码、未随包分发）

| File | Component | License |
| --- | --- | --- |
| `GPL-3.0.txt` | `xingranya/onekeyjb`（日志与验收口径参考）；`Yunnijian/OnePlus16-Jailbreak`（当前 `LICENSE` 为 GPL-3.0） | GPL-3.0 |
| `OnePlus16-Jailbreak-MIT.txt` / `NOTICE.txt` | `OnePlus16-Jailbreak` 早期快照保留文件 | MIT (snapshot) |
| `AzirX1337-MIT.txt` | `AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak`（背景参考） | MIT |
| upstream only | `YuKongA/CVE-2026-98260`（MIT）、`No-World/rootkit`（MIT）、LSPosed / Zygisk Next（仅设备端热修复，不随包分发） | 各自上游协议 |

The full notice is in `../THIRD_PARTY_NOTICES.md`.
The project's own license text is `../LICENSE`; the copyright notice and
third-party boundary statement are in `../NOTICE.md`.
