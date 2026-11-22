# MagicRoot 1.0.6

发布：2026-11-21 · `versionCode 13` / `versionName 1.0.6`

## 重点更新

- **STP 平行空间修复**：98260 成功后自动调用 `StpClearStatus()`，清除 Honor
  STP 对临时 root 的持久判决；
- **新内核适配**（静态）：6.12.38 `g4b36`、6.12.81 `g52d15`、6.6.118 `g893`、
  6.1.157 `g8d6`；
- **管理器后端**：新增 SukiSU Nova（`com.sukisu.nova`）与 MapleSU
  （`dev.maplesu.manager`）；
- **98260 payload**：KASLR slide 改为多采样收敛校验，不收敛时拒绝运行；
  各 profile payload 与符号表统一刷新；
- **管理器 LKM 提取**：新增 `ksud debug extract-binary` 路径；
- **默认参数**：跳过 PREFLIGHT 开机等待，98260 churn 默认每 CPU 256；
- **6.1 档位**：精确 6.1 profile 固定 attempts=6 / churn=32 / wait_cap=8，
  不再沿用 98260 的 12/256/25；
- **管理器可见性**：`<queries>` 补齐 SukiSU Nova 与 MapleSU；
- **98260 plant**：加载 KSU 前清零 vendor `module_blacklist`；permissive 写入
  增加 `enforce=0` 回读验证；6.6.89 g6689 符号表与 payload 刷新；
- **仓库清理**：移除上游预编译审计件与旧发布草稿，运行资产与内核适配全部保留。

使用须知、验证状态与已知限制见 [`README-1.0.6-release.md`](README-1.0.6-release.md)。
APK 与 SHA-256 校验文件见 GitHub Release。
