# MagicRoot 1.0.3-bakasu（主项目）

主项目仅保留 6.12 内核路线。本版本为 **BakaSU 适配版**：默认根后端从官方
KernelSU 3.3.1 切换为 BakaSU（`com.resukisu.resukisu`），底层提权流水线为 CVE-2026-64560 分阶段链路（KASLR →
SELinux permissive → cred/fsuid 写入 → LKM 加载 → root_stage → 管理器加冕）。

- 版本：1.0.3-bakasu（versionCode 7）
- 包名：`com.aoki.magicroot`
- 桌面名称：`MagicRoot`
- targetSdkVersion：37

## 根后端（可在 UI 切换）

```text
BakaSU 内核    默认开（resukisu）
  管理器 com.resukisu.resukisu v4.2.0-rc3 (35252)
  用户态 ksud 4.2.0 (5,955,840 B)
  内核模板 ksu-template-bakasu.ko＝BakaSU KMI android16-6.12 nightly
           (508,792 B, vermagic 6.12.76-4k)，运行时由 ko_patch 打符号/vermagic
  符号表   syms_61258_bakasu.txt / syms_6138_bakasu.txt（241 项，
           覆盖 BakaSU LKM 全部 233 个未定义符号，MISSING=0）

官方 KernelSU  回退（official）
  管理器 me.weishu.kernelsu v3.3.1 (32680, uapi 5)
  用户态 ksud 3.3.1 (4,990,848 B)
  内核模板 ksu-template.ko（485,803 B, vermagic 6.12.76）
  符号表   syms_61258.txt / syms_6138.txt
```

UI「BakaSU 内核」开关切换后端；切换后需重新「部署资产」。后端选择通过
`$WORK/ksu_flavor` 与 `MAGICROOT_KSU_FLAVOR` 传给 `run.sh` /
`root_stage.sh`。

## 支持内核

```text
6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k
```

其他内核会进入 reserved/unsupported 分支并安全退出。

## 管理闭环（root_stage）

`root_stage.sh` 按 flavor 执行：

```text
resukisu:
  /data/adb/ksud <- 从已安装管理器 APK 提取的 ksud
  ksud install
  ksud feature set su_compat / kernel_umount / selinux_hide
  登记（三段式，见下）：kernel dynamic-manager set-apk（首选，真机验证）
                       -> manager add/set-enabled（若该 ksud 支持）
                       -> debug set-manager（CONFIG_KSU_DEBUG 缺失时归类为“自动识别”）
  连接验收：readlink /proc/<pid>/fd/* | grep ksu（默认等 10s）
  未连接：重新登记 + 重启管理器（monkey -> resolve-activity/am start 兜底）+ 再等 10s
  可选软重启修复：MAGICROOT_REPAIR=1 时 15s 后 ksud soft-reboot / ctl.restart zygote
  管理数据快照：/data/adb/ksu -> /data/local/tmp/magic/ksu-preserve
  setenforce 1 恢复（MAGICROOT_RESTORE_ENFORCING 默认 1，$D/no_restore_enforcing 关闭）
  su 通道自检
official:
  packages.list（chmod 644 -> 改名触发 -> 失败恢复）+ debug set-manager
  （CONFIG_KSU_DEBUG 缺失时同上归类）
  其余连接验收/重试/修复/快照逻辑相同
```

BakaSU 4.2.0-rc3 管理器的动态登记三元组（从 APK 签名块实测）：

```text
package = com.resukisu.resukisu
size    = 887
hash    = d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64
```

`root_stage.sh` 优先用 `ksud debug get-sign` 动态解析；解析失败时使用上述静态
回退值。

模块加载侧（`run.sh`）的强化点：patch 产物校验
与 `/data/local/tmp/ksu-official.ko` 副本、模块 Live 兜底轮询（wait_helper 超时
后轮询 120s）、加载失败 errno 诊断（ENOENT/EINVAL/EPERM + dmesg 尾部）、
`ksu_grant` 瞬态失败自动重试一次。

## 工作目录

```text
/data/local/tmp/magic
```

提权成功（`DONE`）后由 APK 清理工作目录、marks 与旧 stage 缓存。

## 签名

签名材料和口令由发布者本地维护，不随项目分发。构建时通过 `app/build.ps1`
参数传入。受限文件沙箱为 workspace-write，构建脚本默认把 `GRADLE_USER_HOME`
指向项目内 `.gradle-home`（可用同名环境变量覆盖）。

## 五种管理器后端

`main` 支持 5 个 KernelSU 系管理器后端（UI「内核后端」卡片循环切换）：

| flavor | 管理器 | 包名 | 配套 ksud | 内置 LKM 兜底 |
|---|---|---|---|---|
| `resukisu` | BakaSU 4.2.0-rc3 | `com.resukisu.resukisu` | 从管理器提取 | 6.12 原生模板 |
| `fina` | FinaSU 1.0.10 | `me.yuki.fina` | 从管理器提取 | 6.12 原生模板 |
| `kernelsu` | KernelSU 3.3.1 | `me.weishu.kernelsu` | `ksud` | 6.12 原生模板 |
| `sukisu` | SukiSU 4.2.1-r2 | `com.sukisu.ultra` | `ksud_sukisu` | 6.12 兼容模板（uapi5） |
| `next` | KernelSU-Next 3.4.2 | `com.rifsxd.ksunext` | `ksud_next` | 6.12 兼容模板（uapi5） |

**标准部署优先从已安装管理器提取**：`pm path` 定位管理器 APK →
`unzip -p lib/arm64-v8a/libksud.so`（重命名该库的分支会自动扫描候选 .so 并用
`-V` 校验）得到配套 ksud；签名三元组由 APK 用 `PackageManager` 的
`GET_SIGNING_CERTIFICATES` 计算并写入 `manager_sig`。管理器未安装时回退到
**不再内置 ksud**：请先安装对应管理器，否则运行会快速失败并提示安装。各 flavor 可用 `$WORK/ko-<flavor>.ko` 覆盖内置 LKM 模板；
内置模板与运行内核 KMI 不匹配时会明确失败，提示提供对应 KMI 的 ko。

## allow_shell 默认关闭

模块默认以 `allow_shell=0` 加载；冷启动时 `GRANT_ROOT / root_stage` 需要 shell 在
ksu allowlist 中，否则需显式同意 bootstrap（UI「allow shell」或
`MAGICROOT_BOOTSTRAP_ALLOW_SHELL=1`）。未同意时 grant 失败会提示开启并重启。

## 构建

```powershell
powershell -ExecutionPolicy Bypass -File .\app\build.ps1 `
  -Sdk <sdk> -Jdk <jdk25> `
  -Keystore <keystore> `
  -StorePass <pass> -KeyAlias magicroot -KeyPass <pass>
```

产物：

```text
app/MagicRoot.apk
```

### Gradle 配置缓存

两个 compose-app 均已启用 Gradle configuration cache（参考
[Gradle 9.3.1 配置缓存文档](https://docs.gradle.org/9.3.1/userguide/configuration_cache_enabling.html)）：

```properties
org.gradle.configuration-cache=true
org.gradle.configuration-cache.parallel=true
org.gradle.configuration-cache.problems=warn
```

首次构建存储配置缓存（日志 `Configuration cache entry stored.`），后续构建
直接复用（`Configuration cache entry reused.`，实测打包时间 61s → 8s）。
签名/参数通过 `build.ps1` 环境变量传入，会作为配置缓存输入被正确追踪；
修改 `gradle.properties` 或构建逻辑后缓存会自动失效并重新存储。

## 设备验证状态

见仓库根目录 `docs/`（真机报告与安全边界）。

`host/` 为研究套件源码，`docs/` 为技术文档。
