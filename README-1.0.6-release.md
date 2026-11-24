# MagicRoot 1.0.6 发布说明

发布：2026-11-21

版本：`versionCode 13` / `versionName 1.0.6`（上一版 1.0.5 / 12）

原始发布页（酷安）：<https://www.coolapk1s.com/feed/74522652>

> 发布页说明：预计可支持内核版本为
> `6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k` 的任意 Honor
> 骁龙 8 Elite Gen 5 设备一键 Root。

## 使用须知

1. 单次执行约 **10–30 分钟**，请耐心等待，不要中途强杀。
2. 有低概率导致**设备重启或进程卡死**；等待重启完成后再次执行即可。
3. 建议提前为设备**降温**，不要短时间内多次重启执行。
4. 一次性临时 root，重启即失效；仅用于本人设备或明确授权设备。

## 1.0.6 更新

### 1. STP 平行空间修复

Honor 的 WLAN / 平行空间 Root 判定最终来自：

```text
HwSecurityDiagnoseManager.getRootStatusSync()
  -> HwSecurityDiagnosePlugin (system_server)
  -> AppLayerStpProxy
  -> HwStpHidlAdapter.stpGetStatusByCategory(8)
  -> vendor.honor.hardware.hwstp.IHwStp/default
  -> hisecd / STP
```

m6 的 kill hisecd + 软重启 + persist 复位不会清除 STP 的持久 / kernel 判决。
`/vendor/lib64/libstp.so` 暴露的 `StpClearStatus()` 才能清掉该状态。

1.0.6 中 `assets/98260/stpclear` 通过 dlopen 调用该 API，`run.sh` 在 98260
成功后自动执行：

```text
STP_CLEAR_RC=...
StpClearStatus=0
```

开发阶段在 rootd-only full-cap 下实测：删除 user100 后重启 → 98260 rootd →
StpClearStatus → 平行空间 Root 弹窗消失，可正常创建 UserInfo{100:平行空间}。

注意：KSU 模式下 `/system/bin/su` 可能被 STP 再次扫描；rootd-only 路线已验证。
不要修改 `/system`、`/vendor` 分区。

### 2. 新内核适配（静态）

- **6.12.38** `g4b3671e1f5b7`：独立 payload、六套符号表、精确 `uname -r` 路由
- **6.12.81** `g52d15df5db87`：该 build 不再内联 `alloc_posix_timer`，
  `LINK_ALLOC_TIMER=alloc_posix_timer+0x28`；98260 修复未合入，仅适用 98260 链路
- **6.6.118** `g893e848657cc`：完整 payload、符号表与去重映射
- **6.1.157** `g8d63307071ad`：g264 CGA base、符号表并纳入 `run6157_full.sh`

以上均只有**静态适配**，没有对应真机运行记录。

### 3. 管理器后端

- 新增 **SukiSU Nova**（`com.sukisu.nova`）与 **MapleSU**
  （`dev.maplesu.manager`）两个 Flavor；
- 6.12 / 6.6 中已有精确内核镜像的 profile 补齐 nova 符号表；没有精确镜像的
  构建仍会在 `ko_patch` 阶段 fail-closed；
- 管理器 LKM 提取新增 `ksud debug extract-binary` 路径：FinaSU / Nova /
  MapleSU 优先取管理器自带的同 KMI 模块，内置模板只作回退。

### 4. 98260 payload 重建

- KASLR slide 改为多采样收敛校验；样本不收敛时拒绝运行；
- 各 profile 的 payload 与符号表统一刷新；
- 新增 teardown 标记、victim slab 归属、零残留重试、bounded chase 等回归用例。

### 5. UI 与默认参数

- 默认跳过 PREFLIGHT 开机等待（原限制移除）；
- 98260 churn 默认提升至每 CPU 256；
- 关于页同步来源归属与许可边界。

### 6. HyperBreak 接入同步

- 6.1.x 运行档位固定为 `attempts=6 / churn_per_cpu=32 / wait_cap=8`，
  不再沿用 98260 的 12/256/25（避免失败重试时 8 倍空转）；
- `AndroidManifest.xml` 的 `<queries>` 补齐 SukiSU Nova 与 MapleSU 包可见性；
- 新增 `docs/6157-G08DE-ADAPT.md`：g08de 仅同步 98937 KASLR 常量，
  没有 payload/CGA，不进入 `run6157_full.sh` 分派。

### 7. 仓库清理

- 移除 `binary-sources/66118/ksu/` 上游预编译件（仅供审计留档，hash 记录在
  `BINARY-SOURCES.md`）；
- 移除旧版发布草稿、1.0.4 审计输出与内核对照分析数据；
- 运行资产与内核适配目录全部保留，APK 功能不受影响。

### 8. 1.0.6 合并后的 98260 补充

- 98260 plant 在加载 KSU 前清零 vendor `module_blacklist`，并把 permissive
  写入统一为带 `enforce=0` 回读验证的共享 helper；
- 6.6.89 `g082e5a98dac1` 的六张符号表按镜像刷新（274 项），
  `98260-6689` payload 同步重建（99,144 B）；
- 6.18 H1C 的 ge186/gfee 地址与命令见 `docs/MODULE-BLACKLIST.md`；
  对应 plant 二进制未在本树重建。

## 验证状态

| 内核 | 状态 |
|---|---|
| 6.12.58 `g3a7ac1674240` | 64560 / 98260、KernelSU、LSPosed 热修复已完整验证 |
| 6.1.157 `g2646292297b1` | CGA + su 有历史真机闭环，当前 APK 需复验 |
| 6.1.157 `g7d3922fade43` | M6 交接有历史真机闭环，当前 APK 需复验 |
| 6.12.38 / 6.12.81 / 6.6.118 其余构建 | 静态适配 |
| 6.1.x 其余构建 | 静态适配 |
| 6.18.21 | H1C 生成器已验证，无设备完成完整提权 |

## 已知限制

- 6.18.21 与多数 6.1.x 构建没有对应真机，不能视为端到端验证；
- Nova 在部分 6.12 构建（61258b / aph112、6138y、6123）与 61821brm 缺表，
  选择后会 fail-closed；
- 自动化脚本不得调用 `ksud soft-reboot`；该操作可能拆除 UAF / rootd 并触发
  `page_request` panic；
- 一次开机不建议连续多次触发 98260；失败后 plant/socket 状态会保持到重启。

## 产物

- `MagicRoot-1.0.6.apk`（签名 APK）
- `MagicRoot-1.0.6.apk.sha256`（SHA-256 校验文件）

APK 的 SHA-256 以 GitHub Release 页面与同目录校验文件为准。

## 许可与致谢

本项目自研部分自 1.0.6 起采用 **GNU AGPL-3.0**（`LICENSE` 为协议原文，
版权声明与适用范围见 `NOTICE.md`）；1.0.5 及更早版本仍为 MIT。
通过网络提供修改版服务时，AGPL 第 13 条要求提供对应源码。第三方源码与
随包预编译产物沿用各自协议，边界见 `NOTICE.md`、`THIRD_PARTY_NOTICES.md`
与 `LICENSES/`；随包 KernelSU 系 GPL-2.0 预编译 LKM 按独立作品处理，
不在本项目重授权范围内。

感谢酷安 @qiufeng1586、@熠寻 的无私分享，以及 xiaomi9pmroot、
woshigenm/CVE-2026-98260、popsicle、HOneClick、KernelSU 系列管理器等
上游项目的公开工作。
