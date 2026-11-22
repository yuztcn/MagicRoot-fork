# MagicRoot 优化实施计划

对应审计：`.cccodroid/agents/97989ac0/03-项目优化全面审计-3925f8/report.md`

## 0. 总原则（全程不变，先读）

1. **不碰已验证链路语义。** 所有 shell 链路的分派、payload、符号、chmod、清理、rootd 保留等运行时行为保持逐字节等价；本计划只做"等价重构/删除死物/加固失败路径"，不改成功路径控制流。
2. **先安全网后重构。** 顺序固定为：基线快照 → 低风险整理 → 构建配置 → 代码健壮性 → 测试补齐 → 数据驱动 → 资产去重 → 文件拆分 → 文档收尾。高收益高风险项（资产去重）放在最后，前面所有阶段为其铺路。
3. **每阶段独立提交、独立回滚。** 一条 commit 只做一类改动；任何阶段验证失败 `git reset --hard` 回到上一阶段头，不影响已合并成果。
4. **静态验证 + 构建验证为合并门槛；真机验证为放行说明。** 无对应真机的路径（多数 6.1.x/6.6/6.18）只做"不回归静态行为"承诺，不声称真机验证。
5. 版本号、包名、签名、`uname -r` 精确匹配、Flavor 五路可切换、单页 UI、不新增任何机型/哈希门禁 —— 全程不变。

## 0.1 每次改动前的固定检查清单（Definition of Done）

- [ ] `bash -n` 过全部改动的 .sh
- [ ] 若动 MainActivity/gradle：`gradle assembleRelease` 成功（或至少 `compileReleaseJavaWithJavac` 在本机可用 JDK 下通过）
- [ ] 若动资产：`ASSET_PLAN`/`stagePlanBatch` 逻辑静态推演 + `tools/verify_98260_assets.py` 过
- [ ] 若动 profile 分派：`kernel_profiles.sh` 与 Java 侧映射对账一致
- [ ] 若动 APK 内容：对比构建产物 entry 清单（`unzip -l`）确认该删的删、该留的留
- [ ] commit message 用 `refactor:`/`chore:`/`perf:`/`docs:`/`test:` 前缀，写清"行为等价"或"行为变化点"

---

## 阶段 1：仓库卫生整理（零风险，先行）

目标：消掉噪音，让后续 diff 干净。全部是"删/忽略"，不改任何被引用文件。

| # | 动作 | 依据 | 验证 |
|---|------|------|------|
| 1.1 | `.gitignore` 增加 `__pycache__/`、`*.pyc`、`*.idsig` | `tools/__pycache__/*.pyc` 已被跟踪 | `git status` 干净、`git check-ignore` 命中 |
| 1.2 | `git rm --cached tools/__pycache__/*.pyc`（删跟踪，不删盘） | 编译产物不该进历史 | `git ls-files` 无 `.pyc` |
| 1.3 | 删 `about-texts.json`（1.0.4、零引用） | 审计孤儿文件 | `grep -rn "about-texts" main/` 无结果 |
| 1.4 | 删 `98260-aph112/run98260.sh` 死资产（未注册、aph112 走共享 run98260.sh） | ASSETS_98260 不含它 | `verify_98260_assets.py`；`grep aph112` 确认引用全是共享脚本 |
| 1.5 | 给 `main/app/src/`、`build-legacy.ps1`、`pack_apk.py`、`legacy-libs/` 加 `main/app/LEGACY.md` 标注"历史基线，不参与构建"，不删本体 | CLAUDE.md 要求保留基线 | 仅加文档 |
| 1.6 | `进度.md` 保留但移出跟踪：`git rm --cached 进度.md` + `.gitignore` 加 `进度.md` | 个人工作日志不该进源码历史 | 文件仍在盘上，`git ls-files` 不再含 |
| 1.7 | `git gc --aggressive --prune=now` | 1154 loose 对象、0 pack、83MB | `git count-objects -v` pack>0；`git fsck` 无错 |

**合并**：`chore: 仓库卫生整理（忽略产物/删死文件/标注旧版）`。回滚：`git revert`。

---

## 阶段 2：构建与配置修复（低风险）

| # | 动作 | 当前问题 | 验证 |
|---|------|----------|------|
| 2.1 | `build.gradle.kts` 去掉 storePassword/keyPassword 默认 `"MagicRoot"` 与回退 keystore 路径：env 缺失 → `error("MAGICROOT_KEYSTORE not set")` | 无 env 时静默默认签名 | 故意不传 env 构建→明确报错；传 env→正常出包 |
| 2.2 | proguard：`-keep class MainActivity { *; }`/`UiState { *; }` 收窄为默认 manifest keep（删除两行，验证 Activity 可启动） | 整类 keep 削弱 R8 | `assembleRelease` + apktool/jadx 抽查类名被混淆 + APK 反编译 manifest 入口保留；**真机冷启动 smoke 1 次** |
| 2.3 | `build.ps1`：build-tools 版本号 `37.0.0` 改为自动探测 `$Sdk\build-tools\` 最新目录 | 硬编码版本失效即死 | 临时重命名 `37.0.0` → 脚本仍能跑（测 fallback）|
| 2.4 | `main/app/AndroidManifest.xml`（旧版）：与 compose manifest 对齐或文件头加 `<!-- 旧版残留，不参与构建，以 compose-app 为准 -->` | 漂移误导 | diff 对齐后只剩注释差异；compose manifest 不动 |
| 2.5 | `about-texts.json`/`README-1.0.6-release.md`/`main/app/README.md`：1.0.6 README 标 `（预发布草稿，当前版本 1.0.5）`，`main/app/README.md` 加同样提示 | 版本漂移误导 | 纯文档 |

**验证门槛**：完整 `build.ps1` 出包成功 → `Get-FileHash`、`unzip -l` 对比 APK entry 数无意外减少、`apksigner verify` 通过。
**合并**：`chore: 构建配置修复（签名 fail-fast/proguard 收窄/build-tools 探测/旧 manifest 对齐）`。

---

## 阶段 3：代码健壮性修复（低风险，逐条独立 commit）

顺序即合并顺序；每条单独 commit，出问题可单独 revert。

| # | 动作 | 位置 | 验证 |
|---|------|------|------|
| 3.1 | `RemoteProcess`：新增 stderr drain——`shellShizuku`/`shell` 读 stdout 的同时用守护线程 drain `getErrorStream()` 到日志缓冲（保留前 4KB 供诊断） | MainActivity :4696-4793 | 构造 `sh -c 'i=0; while [ $i -lt 2000 ]; do echo xxxxxxxxxxx >&2; i=$((i+1)); done; echo OK'` 模拟 >64KB stderr → 不再 30s 超时（改前必现、改后必过） |
| 3.2 | 删 `installStpclearBase64`（无调用点死代码） | :3573 | `grep -rn installStpclearBase64` 只剩定义→删后 0 引用；编译过 |
| 3.3 | `stagePlanBatch`：`entries<=0` 判空前移到 cp/unzip 之前；`ASSET_MISSING` 计数并写进 `ASSET_BATCH` 日志 | :2108 | 单测式推演 plan=[] → 立即 false 不发远端命令；plan 含缺失项 → 日志出现 `missing=N` |
| 3.4 | SUSFS 更新：`expectedDigest` 为空时强制本地二次校验——下载后 SHA-256 与 GitHub `size`+ELF/vermagic 双验，并把 `digest absent` 显式 log 为警告级（不静默） | :1360-1376 | 构造无 digest 的 mock 响应 → 仍过 KMI 校验且日志出现 `SUSFS_DIGEST_ABSENT` |
| 3.5 | 裸 `new Thread`×32 → 统一 `private final ExecutorService worker = Executors.newCachedThreadPool(...)`，线程名统一 `magicroot-*`（保留现有命名）；onDestroy `worker.shutdownNow()` | 全文件 | 编译过；线程名一致；无行为变化（仍 daemon 式后台任务） |

**合并**：每行一个 `fix:`/`refactor:` commit。回滚：单独 revert 对应 commit，互不影响。

---

## 阶段 4：测试补齐（中风险前置，必须先于重构做）

| # | 动作 | 说明 | 验证 |
|---|------|------|------|
| 4.1 | 建 `main/compose-app/app/src/test/java/...` JUnit4 单测：`RunProgress`（已有孤立测试搬入）、`kmiOf`/`patchOfKernel`/`releaseOfVermagic`/`modinfoVermagic` 解析、`payloadDirFor6157`/`cgaBaseFor6157` 映射表、`finishKind`/`tailLines`/`section` 文本工具 | 这些是纯函数，最易测也最易回归 | `gradlew testReleaseUnitTest` 全绿；覆盖率不看数值，看关键分支 |
| 4.2 | 把 `tools/tests/RunProgressTest.java` 迁移进 4.1 的 test 源集，删除游离文件 | 游离测试从未运行 | 迁移后 `gradlew test` 实际执行到它 |
| 4.3 | 建 `tools/check.sh` 单入口：`bash -n` 全部 62 个 .sh + `verify_98260_assets.py` + `audit_kernel_flavors.sh` + `verify_61258c_profile.py` + 资产注册对账（assets 盘文件 ↔ ASSETS/ASSETS_98260 ↔ shouldStage*，即阶段 7 用的同一脚本） | 一键静态门禁，后续每阶段都跑 | 故意改坏一个脚本 → check.sh 非零退出 |
| 4.4 | 可选：`.git/hooks/pre-commit`（或 repo 内 `tools/install-hooks.sh` 安装）：跑 4.3 | 防漏检 | 模拟提交带 CRLF 的 .sh → 被拦 |

**合并**：`test: 接入 JVM 单测与一键静态门禁`。这是后续 5-7 阶段的安全网，**不绿不进下一阶段**。

---

## 阶段 5：内核映射数据驱动（中风险，纯重构）

目标：把散在 4 处的内核→profile 映射收敛为**单一数据源**，消灭"新增内核改 N 处漏一处"的事故模式。**行为必须逐条等价。**

5.1 在 `main/app/assets/kernel_profiles.json`（新资产）落唯一表：

```jsonc
{ "profiles": [
  { "id": "g264",  "release_prefix": "6.1.157-android14-11-g2646292297b1",
    "kernel_series": "6.1.157", "chain": "6157_cga",
    "payload_dir": "98260-g264", "cga_base": "g264/ksm-g264-base.ko",
    "stage_dirs": ["98260-g264", "ksu6157-g264", "su-g264"],
    "run_script": "98260/run6157_full.sh" },
  { "id": "g7d", "release_prefix": "6.1.157-android14-11-g7d3922fade43", ... }] }
```

5.2 Java 侧：`MainActivity` 增加一个小的 `KernelProfileTable`（assets 读 JSON、按 `uname -r` 前缀命中、暴露 `payloadDir/cgaBase/stageDirs/runScript`），替换 `shouldStageLegacyAsset`/`shouldStage98260Asset`/`payloadDirFor6157`/`cgaBaseFor6157` 里的硬编码 if 链。**先并存双跑**：新表算出的 stage 集合与旧函数比对，不一致 → 打 `PROFILE_MISMATCH` 日志并回退旧结果（灰度一版后删旧实现）。

5.3 shell 侧：`kernel_profiles.sh` 从同一 JSON 读 profile 段（device 上 `toybox` 无 jq → 发布期由 `tools/` 把 JSON 展开成 `kernel_profiles_table.sh`（纯 `case` 生成物，随 JSON 同步生成、带 `generated` 头注），脚本只 `source` 生成物）。**生成物进 git，diff 可见。**

5.4 对账测试（4.3 的 check.sh 增强）：遍历 `kernel_profiles.json` × `ASSETS`/`ASSETS_98260` × 资产目录，断言每个 profile 的 `stage_dirs` 与 `shouldStage*` 语义一致、每个 98260-* 目录恰被一个 profile 引用。

**验证**：静态对账全绿 + `stageAllRuntimeAssets` 对 6.12.58 / g264 / g7d / 61821 四个代表 profile 产出的 stage plan 与改动前**集合相等**（可写一次性 JUnit 断言）。真机 smoke：6.12.58 一次部署日志 `ASSET_PLAN`/`ASSET_BATCH` 与基线一致。
**合并**：`refactor: 内核 profile 映射数据驱动`。回滚：revert 即回旧 if 链。

---

## 阶段 6：APK 资产去重（最高收益，-49MB，高风险，最后做）

原则：**APK 内只存一份字节，部署时在设备端复制到各 profile 目录**——不改任何链路的运行时路径假设，shell 侧完全无感。

6.1 建 `assets-dedup` 目录约定：去重文件移入 `main/app/assets/_dedup/<sha256前16位>`，同时在 JSON（5.1 的表扩展字段 `dedup_map: {"目标相对路径": "_dedup/xxx"}`）登记。

6.2 `stagePlanBatch` 改动（MainActivity.java:2108）：写 ZIP 时按 `dedup_map` 把同一 `_dedup` 文件写入**所有目标路径**（即 ZIP 内仍含多份 → 设备端目录布局与今天完全相同），但 APK assets 里只存一份。**ZIP 变大但 APK 变小**；ZIP 传输本来就要解 114MB，多解 ~25MB 可接受（实测 2.4s→估 ~3s）。

6.3 更激进的备选（仅当 6.2 收益验证后还想再压）：ZIP 内只放单份 + 部署末尾 `cp` 到目标目录。需改 `normalizeBatchPermissions` 为"unzip→cp→chmod"三步；**风险更高**（cp 失败会留下半成品目录），放第二阶段单独评估，默认不做。

6.4 对 `exploit-android-perf` / `-chain` 同哈希对：保留两个名字（脚本按名调用），同样走 `_dedup`。

**验证**：
- `unzip -l MagicRoot.apk` 资产 entry 数从 ~305 降到 ~230；APK 体积 69MB→~40MB 级。
- `verify_98260_assets.py` 更新为认 `dedup_map`（同步改，CLAUDE.md 工作流第 5 步文档同步）。
- 真机：6.12.58 完整部署 → `ASSET_BATCH=ok entries=...`（entries 数应与去重前**相同**，因为 ZIP 内容不变）→ 一次 root 链路 smoke。
- 边界：某个 `_dedup` 文件被误删 → `requireCriticalAssets` 仍能在部署前报出（对账测试覆盖）。

**合并**：`perf: APK 资产去重（-49MB）`。回滚：revert + 恢复各目录实体文件。

---

## 阶段 7：文件拆分（纯移动，零行为变化，可最后或并行低优先级）

| # | 动作 | 验证 |
|---|------|------|
| 7.1 | `MainActivity.java` 拆出包级类：`ShizukuProc`（shellProcess/RemoteProcess/shell*）、`AssetStager`（stage*/normalize*/shouldStage*）、`SusfsUpdater`（updateSusfsLkm/downloadHttp/validateSusfsKo）、`StpSupport`（stpclear 全部）、`ManagerCatalog`（refreshInstalled*/manager*）、`RunLogSupport`（pollRunLog/exportLastRunLog/finishKind/tailLines） | 编译过；方法签名不变；IDE 结构对比无遗漏方法 |
| 7.2 | `MiuixHost.kt` 按页面拆 `home/`、`tools/`、`about/`、`wizard/`、`components/`（glass/ 保持） | 编译过；`@Composable` 数不变 |
| 7.3 | `run98260`/`run6157_full` 的 8 个同名函数抽进 `lib.sh`（扩充现 11 行文件），两脚本 `source "$D/lib.sh"` | `bash -n` + `check.sh` + 函数体逐字节 diff 确认等价 |
| 7.4 | `tools/` 124 文件中 72 个一次性 `doc_/patch_/fix_/update_` 脚本移 `tools/archive/`（保留历史，不在主路径） | `tools/check.sh` 仍绿；包路径无引用断裂 |

**合并**：`refactor: 拆分巨型文件（纯移动，无行为变化）`。

---

## 阶段 8：文档与发布清单收尾

| # | 动作 | 验证 |
|---|------|------|
| 8.1 | `SHA256SUMS.txt`/`SOURCE-MANIFEST.txt` 改为 `tools/package-source.ps1` 生成产物（不再手维护），构建流水线末尾重生成 | 生成后 `sha256sum -c` 全 OK、无失效条目 |
| 8.2 | `verify_apk.py`/`verify_98260_dual.py` 外部依赖在脚本头注"需要工作区外 port/ 参考目录，缺失时跳过而非失败" | 在干净环境跑不炸 |
| 8.3 | `CLAUDE.md` 第 4.3/5 节同步：`profiles.json` 单一数据源 + `dedup_map` + `check.sh` 新门禁 | 文档与代码一致 |
| 8.4 | `README-1.0.6-release.md` 并入正式 `RELEASE-NOTES.md` 或标注草稿（2.5 已做则跳过） | 文档单一版本事实 |
| 8.5 | 可选：GitHub Actions / 本地 `check.sh` 的最小 CI（lint + bash -n + gradle compileOnly，不签名不跑真机） | push 即跑 |

**合并**：`docs: 发布清单自动化与文档收敛`。

---

## 全程回归保障（横向，每阶段都过）

1. **静态门禁**：`tools/check.sh`（阶段 4 建立后每阶段必跑）。
2. **构建门禁**：阶段 2 起每次合并前 `build.ps1` 出包成功 + `apksigner verify` + `unzip -l` 资产清单对比基线。
3. **等价性证据**：
   - 阶段 5：stage plan 集合 diff = ∅
   - 阶段 6：设备端 `unzip -l .assets-batch.zip` 条目与去重前相同（文件名/路径一致，仅 APK 内存储位置不同）
   - 阶段 7：`javap`/方法签名清单 diff = ∅；shell 函数体 diff = ∅
4. **真机 smoke（有设备时，每阶段一次即可）**：6.12.58 MLY-AN00 部署 → root → LSPosed 修复三件套日志（`DONE`/`kernelsu`/`System server: connected`）。无设备阶段以"静态等价"为合并依据并在 commit 注明。
5. **不重复触发 98260**：真机验证每次开机至多一次，遵守 CLAUDE.md 安全边界。

## 阶段顺序总览

```
阶段1 仓库卫生   ──┐
阶段2 构建配置   ──┤ 低风险，可连续合并
阶段3 代码健壮   ──┘
阶段4 测试补齐   ←─ 安全网（门槛：不绿不进 5）
阶段5 数据驱动   ←─ 中风险
阶段6 资产去重   ←─ 高风险高收益（-49MB）
阶段7 文件拆分   ←─ 纯移动
阶段8 文档收尾   ←─ 清理
```

每阶段 = 测试基线 → 实施 → 静态+构建验证 → （有设备）真机 smoke → commit → 出问题 revert。全部完成后预期：APK ~40MB（-42%）、stderr 死锁消除、内核适配改为单表维护、静态检查一键化。
