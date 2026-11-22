# MagicRoot 1.0.6

MagicRoot 是一个面向 **荣耀骁龙 8 Elite Gen 5 / 部分 Honor 机型**的一次性临时
Root 工具：不解除 BL 锁、不修改分区、不写入持久化内容，重启后自动失效。

> **原始发布页（酷安）**：<https://www.coolapk1s.com/feed/74522652>
>
> 发布页说明：预计可支持内核版本为
> `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k` 的任意 Honor
> 骁龙 8 Elite Gen 5 设备一键 Root。
>
> 当前版本：`1.0.6`（versionCode 13）。

## 使用须知

1. 单次执行约 **10–30 分钟**，请耐心等待，不要中途强杀应用。
2. 有低概率导致**设备重启或进程卡死**；等待重启完成后再次执行即可。
3. 建议提前为设备**降温**，不要短时间内多次重启执行。
4. 仅用于本人设备或明确授权设备。真机执行会临时切换 SELinux permissive、
   加载未签名 LKM，存在 panic / 重启风险，请自行承担。
5. 一次性临时 root，**重启即失效**；不要尝试改分区或做持久化。

## 支持范围

### 已实机验证

| 内核 release | 状态 |
|---|---|
| `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k` | 64560 与 98260 链路、KernelSU、LSPosed 热修复已完整验证（Honor MLY-AN00） |
| `6.1.157-android14-11-g2646292297b1` | CGA + su 路线有历史真机闭环；当前重建 APK 需复验 |
| `6.1.157-android14-11-g7d3922fade43` | M6 交接路线有历史真机闭环；当前重建 APK 需复验 |

### 静态适配（尚无对应真机记录）

- **6.12.38**：`g4b3671e1f5b7`、`g7ae…`、`gfde…`
- **6.12.81**：`g52d15df5db87`（该 build 未合入 98260 修复，仅适用 98260 链路）
- **6.6.118**：`g554929766a0d`、`gf17133276a57`、`ga812a1946391`、`g893e848657cc`
- **6.1.157**：`gaaa383620ebf`、`g3306a328b7be`、`g84ffa64b710b`、
  `g77f76e323a02`、`g8d63307071ad`
- **6.1.99 / 6.1.128**：各构建见 `docs/6157-SUPPORT-AUDIT.md`
- **6.18.21**：H1C 引擎；自适应 profile 生成器已用 g928 boot.img 验证，
  完整提权无对应设备

> 只有精确匹配 `uname -r` 的 profile 才会部署；未适配的构建会 fail-closed，
> 不会借用其他内核的符号表。

## 主要能力

- **两条提权链路**：CVE-2026-64560 分阶段流水线，以及 CVE-2026-98260
  UAF / rootd 链路；两条链路互相隔离。
- **多管理器后端**：KernelSU、BakaSU（resukisu）、FinaSU、SukiSU Ultra、
  KernelSU-Next、SukiSU Nova、MapleSU，可在首页切换。
- **运行时 LKM 修补**：按当前内核选择符号表，把模板 LKM 的未定义符号改写为
  `SHN_ABS` 绝对地址，并修正 vermagic。
- **管理器 LKM 提取**：优先从已安装管理器 APK 提取匹配 KMI 的 LKM / ksud；
  FinaSU 1.6.3 等容器格式走管理器自带的 `ksud debug extract-binary`。
- **6.18 自适应 profile**：可导入本机 boot.img，生成只对同一 `uname -r`
  生效的 profile，全程离线。
- **STP 平行空间修复**：98260 成功后调用 `StpClearStatus()`，清除 Honor STP
  对临时 root 的持久判决。
- **LSPosed 热修复**：只重启 zygote / lspd，不触碰 rootd 与 UAF 页面。

## 工作方式（简述）

1. 通过 Shizuku 以 shell 身份把运行资产部署到 `/data/local/tmp/magic`；
2. 按 `uname -r`、profile、链路与 Flavor 精确筛选资产，一次 ZIP 批量部署；
3. 64560：KASLR → SELinux permissive → fsuid → cred 两阶段写 → LKM 加载；
   98260：UAF 页面持有 → rootd → socket 交接 → cred 写入 → LKM 加载；
4. 加载管理器 LKM，完成管理器登记与启动；
5. 重启后临时 root、内核模块与工作目录状态全部消失。

## 目录

```text
main/compose-app/   Compose + Miuix 应用（UI 与控制器）
main/app/assets/    设备端脚本、payload、LKM 模板与符号表
binary-sources/     payload 源码、per-build 常量头与适配审计材料
docs/               内核适配、来源与恢复文档
tools/              静态门禁、审计、打包与真机辅助脚本
LICENSES/           第三方许可证全文
```

更多说明：

- [`README-98260.md`](README-98260.md)：98260 链路细节
- [`README-1.0.6-release.md`](README-1.0.6-release.md)：1.0.6 发布说明
- [`BINARY-SOURCES.md`](BINARY-SOURCES.md)：二进制来源与 SHA-256
- [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)：第三方组件与许可边界
- [`docs/6157-SUPPORT-AUDIT.md`](docs/6157-SUPPORT-AUDIT.md)：6.1.x 支持矩阵

## 构建

Windows 发布构建（JDK 25 + Android SDK Platform 37 + Build-Tools 37.0.0）：

```powershell
powershell -ExecutionPolicy Bypass -File .\main\app\build.ps1 `
  -Sdk <sdk> -Jdk <jdk25> `
  -Keystore <release.keystore> `
  -StorePass <storePass> -KeyAlias magicroot -KeyPass <keyPass>
```

提交前静态门禁：

```bash
bash tools/check.sh
```

## 安全与许可

- 仅用于本人设备或明确授权设备；一次性临时 root，重启即失效；
- 不修改分区、不做持久化、不制作永久 root；
- 不安装 LSPosed 管理器 APK，LSPosed 修复只做设备端热修复；
- 本项目自研部分自 1.0.6 起采用 **GNU AGPL-3.0**（见 `LICENSE`）；
  1.0.5 及更早版本仍为 MIT。通过网络提供修改版服务时，AGPL 第 13 条要求
  向使用者提供对应源码；
- 第三方源码与随包预编译产物沿用各自协议，边界见 `THIRD_PARTY_NOTICES.md`
  与 `LICENSES/`。AGPL-3.0 与 GPL-2.0-only 不兼容，随包 KernelSU 系 GPL-2.0
  预编译 LKM 按独立作品处理，不在本项目重授权范围内。

## 致谢

感谢酷安 @qiufeng1586 与 @熠寻 的无私分享，以及
xiaomi9pmroot、woshigenm/CVE-2026-98260、popsicle、HOneClick、
KernelSU 系列管理器等上游项目的公开工作。完整来源与许可边界见
`BINARY-SOURCES.md`、`THIRD_PARTY_NOTICES.md` 与 `docs/98260-UPSTREAM-ORIGIN.md`。

---

作者：酷安 @青木信史
