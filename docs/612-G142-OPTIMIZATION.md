# 6.12 / g142 四项优化（2026-11-08）

按「部署裁剪 → 预检退出码 → 去重 → KASLR 动态化」顺序实施。未安装 APK，
未执行 UAF/rootd/LKM/zygote/重启；本机为 g3a7ac，不是 g142。

## 1. 6.12 部署裁剪

`KernelLogHelper.is6157OnlyAsset()` 从现有 `PROFILES_6157` 和共享目录规则识别
6.1 专属文件；`MainActivity.shouldStageLegacyAsset()` 对所有 6.12 release 排除
这些文件，不再把 CGA/M6/61157 套件复制到 6.12 工作目录。

`pruneUnused6157AssetsOn612()` 在部署前清理旧版本已经留下的对应目录和文件，
范围只限 `/data/local/tmp/magic` 下的已知 6.1 路径。清理失败会记录
`ASSET_PRUNE_612=failed`，当前部署的必需资产仍按原逻辑 fail-closed。

静态计划核对：

```text
6.1-only files       113
removed bytes        150,983,149 (143.99 MiB)
61258 98260 plan     189 -> 76 files
典型部署数据量       159.25 MiB -> 约 15.26 MiB
```

这只减少设备端部署/占用，不删除 APK 中其他内核所需资产。6.1 自己的部署仍由
`shouldStage6157Asset()` 精确选择，不受 6.12 排除规则影响。

## 2. 98260 预检退出码

三份共享 `uaf_plant_61258.c` 保持逐字节一致。`preflight()` 现在返回：

```text
0  ok
2  blocked
3  inconclusive
```

`main()` 直接 `return preflight(quick)`；runner 原有 `exit "$RC"` 因而能把失败
传到 UI，不再把任何存活到打印 JSON 的预检都视为成功。

本机普通 uid 下实测 `--check --quick`：tracefs 不可写时输出
`"verdict":"blocked"`，退出码为 2。未进入 UAF 主路径。
`tools/test_98260_uaf_lifecycle.py` 新增 verdict/退出码与三源同步断言。

12 个共享源码 payload 均以 Termux clang 21.1.8、动态 bionic PIE 配方重建，
大小均为 76,160 B：

```text
65c019609811277058d0cea18fb9ac2bbbb541fde5a59a1b9176ff61ccb89be3  98260/exploit-android-key-ptr
a2f9bd8dc378bf929e1605648f4d92344ff389371210801e744edc06244e9a18  98260-61258b/exploit-android-key-ptr
a2f9bd8dc378bf929e1605648f4d92344ff389371210801e744edc06244e9a18  98260-aph112/exploit-android-key-ptr
b3b95bd21926564cb42b6abe8ced59482a86f38dd26a9043a3272cd8e4e63f6b  98260-61258c/exploit-android-key-ptr
12c393692f4b61434284f50af80b54b0e1848379ebe92917e1508f6ad98705ef  98260-6138/exploit-android-key-ptr
e7ef13c31c5b8a097df284a6aba8f0463c6b920e21e40345589f82b25e641c16  98260-6138y/exploit-android-key-ptr
3ccda0670c72d8c26181a632c2600bf7476946d862c20de549ba4e648e651da2  98260-6123/exploit-android-key-ptr
d34b729a50e2aa7639d5cbd11493581ff32420def7f29c1cd5de0763971f8e93  98260-g856/exploit-android-key-ptr
acb9454565e2209d134680ad801dd6c2eab58310d5ac71a2395d558af260c510  98260-g142/exploit-android-key-ptr
48654c1810faf7dd1698242a42bcd66fd5d9981a3a2de9f194ac96f494d01230  98260-6658/exploit-android-key-ptr
2d77d671427899f3f7c45bc303108533d6bce04793f8a5c8a56f552f2c4ac257  98260-6689/exploit-android-key-ptr
56dd1c2ee685e2f5abd1e58d44f70591dc44c3e0d90753831062ccd65500bc26  98260-ga812/exploit-android-key-ptr
```

既有目录 manifest、`build-98260-6.12.ps1` 记录 hash 与辅助 APK 校验已同步。
该改动只修正只读预检的返回契约，不代表真实提权成功率发生变化。

## 3. rootd 客户端去重

以下两个文件与顶层 `pc98260-su` 的 SHA-256 均为
`8838ab17e38252492df3761b74126855bde8a77ed5ab02255b67ebef81376ab1`：

```text
98260-g142/pc98260-su
98260-ga812/pc98260-su
```

二者已加入 `tools/asset_dedup_map.json` 和 Java canonical 映射。打包时删除重复
entry，部署时仍从 canonical 写回各自的原始相对路径。减少未压缩资产
836,032 B，设备端文件内容不变。去重映射总数由 39 增至 41。

## 4. g142 KASLR helper 动态化

`kaslr_slide_aph136g142.c` 未改，SHA-256 仍为
`ab7a3ff6b0382017e4a3296fe402132b2dae9132f04381346ff3239ebea340ef`。
使用以下配方重建：

```bash
clang -std=gnu11 -O2 -Wall -Wextra \
  -o kaslr_slide_aph136g142 \
  binary-sources/64560/kaslr_slide_aph136g142.c
```

结果由 NDK r29 静态 ET_EXEC（2,151,608 B，含调试信息）改为本机 clang 21.1.8
动态 bionic PIE（10,704 B），减少 2,140,904 B：

```text
50af62de1e9aa6768efd3f3f0fcd520b888fdf08aac756d819e22cc5e4cb0adb  kaslr_slide_aph136g142
```

`tools/test_kaslr_g142.py` 已加入 `tools/check.sh`，使用独立构造的合成 capture：
六锚点各出现三次，slide 为 `0x20b5600000`，逐项核对 18 票、6 锚点、
144 bytes、SELinux/PREPARE 地址和退出码 0；无锚点输入必须输出
`KASLR_ERROR=no_anchor` 并返回 2。

验证边界：当前开发环境拒绝执行原静态 ET_EXEC helper（`unexpected e_type: 2`），
Shizuku 也未运行，所以没有宣称完成原静态二进制的直接运行对照。本轮采用的是
「源码不变 + 独立预期值 + 动态产物实测」。没有真实 g142 trace capture，仍需在
目标设备比较实际采样并确认现有 3 票/5 锚点/1 MiB 外层门禁通过。

## 5. 最终构建与校验

- Release 构建成功，包名/版本保持 `com.aoki.magicroot` / 12 / 1.0.5。
- 最终 APK 经 baseline 移除、41 项去重、对齐和发布 key V3 签名；证书
  SHA-256 仍为 `ef572a91ebf470dc6606af3639e8aa8d28b4bd0768d31b5efbbb2933d92c8296`。
- `main/app/MagicRoot.apk`：61,529,131 B，SHA-256
  `e8ee127ccd18d64673083bfd6505dd87abc63b806d1a7d899b40edb613447343`。
- 对最终签名 APK 执行 `tools/check.sh`：ALL CHECKS PASSED。包括 65 个 Shell、
  35 个 manifest 项、328 个磁盘/APK 资产逐字节对账、31 个 profile、41 个去重
  映射、Java/KASLR、26 项 native/zygote 回归、H1C/6157/清理/su_entry 回归。
- `verify_98260_assets.py`、`verify_apk.py` 和源码包必需项检查通过。
  去重后的 APK 不再含 g142/ga812 的重复 pc98260-su entry，但 canonical 存在，
  最终门禁已验证运行时可还原的磁盘等价性。
- 未安装 APK；PowerShell 构建脚本未在 Windows NDK 环境执行；没有真实 root/KSU
  或 g142 KASLR 采样验证。

