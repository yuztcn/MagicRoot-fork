# RootKit v1.0.17 二进制分析与 64560 链路优化

参考：

- <https://github.com/No-World/rootkit/releases/tag/v1.0.17>
- `RootKit-v1.0.17.apk`
- SHA-256：`（构建时记录）`

## 1. APK 资产

```text
assets/flutter_assets/assets/x645          867,800 B   主漏洞/竞态二进制
assets/flutter_assets/assets/pc            737,032 B   判据/cred 辅助
assets/flutter_assets/assets/ml2           645,760 B   模块加载辅助
assets/flutter_assets/assets/ksupatch      719,480 B   KSU patch
assets/flutter_assets/assets/ksu_template.ko 404,928 B KSU LKM 模板
assets/flutter_assets/assets/koquery       649,640 B
assets/flutter_assets/assets/module.ko       4,016 B
assets/flutter_assets/assets/kallsyms_6.12.58.bin.gz
```

`x645` 内含大量 `P645_*` 参数，说明 v1.0.17 把 permissive、P1/P2、cred、模块加载合并为单二进制阶段机：

```text
P645_STAGE / P645_STAGE_FROM / P645_STAGE_TO
P645_PRE_PIPES / P645_CONC / P645_PIPE512
P645_TIMERS / P645_REPEATS / P645_PIPE_K
P645_ARM* / P645_V7 / P645_V8
victim_reaped at=... status=... (no panic)
```

本工程当前 `t64560_v36` 不含 `P645_*` 字符串，属于拆分式旧链路，不能直接套用这些环境变量。

## 2. 上游 v1.0.17 关键结论

- `PRE_PIPES=20000 → 512`：落位 62% → 80%，panic 12% → 7%；
- `pkill -9 -x x645`，不要 `pkill -f x645`（会匹配到 `sh -c` 包装进程）；
- `pc` 是判据生产者，不能每发后杀，否则 `CAPEFF_OK/ROOT_OK` 永远拿不到；
- 同 boot 反复重试会共享坏堆状态，失败后应完整重启；
- 3s/5s 重型轮询会推高 panic，跑链期间停止；
- P1/P2 一发命中；扩到 14 候选/多 cred 没有收益；
- panic 判定应看 boot_id/uptime/原生日志尾部，不应只用 `sys.resettype`。

## 3. 本工程已应用

- `run_v36()` 改为 `pkill -9 -x t64560_v36`，避免 `-f` 匹配包装 shell；
- 启动清理同样改为 `pkill -9 -x cred_target/t64560_v36/t64560_cred`；
- `CRED_TRY` 默认从 4 降为 2：
  `MAGICROOT_CRED_TRIES` 可调；失败输出完整重启提示；
- 新增 `SHOT_META`：
  ```text
  SHOT_META stage=permissive/fsuid/phase1
  uptime=... boot_id=... load=... mem_avail_kb=...
  ```
  便于 panic 后归因；
- 保留 “cred_target 不按发杀” 约束；
- 保留 P1/P2 单次 `run_cred`，不做 P1 扩展。

## 4. 未直接替换二进制的原因

rootkit `x645` 是单二进制阶段机，依赖 `pc/ml2/ksupatch/module.ko/ksu_template.ko` 与自己的 KSU 加载流程；
本工程 64560 使用 `t64560_v36 + t64560_cred + cred_target + ksu_grant` 拆分链路。
直接替换会改变 KSU patch/rootd/管理器交接，风险高于收益。

当前只吸收其**编排/清理/重试/归因**结论；二进制仍使用本工程已验证的 6.12.58 资产。

## 5. 验证状态

- 构建：AGP 9.4.1/Gradle 9.6.0，无构建警告；
- 设备：adb 离线，未实机回归；
- 预期日志新增：
  ```text
  CRED_RETRY_LIMIT=2
  SHOT_META stage=...
  ```
