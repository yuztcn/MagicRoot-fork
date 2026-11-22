# ColorOS 17 6.6.x KMRoot APK 逆向摘要

输入：`KMRoot(98260).apk.1`，包名 `com.km.kmroot` v0.4.3-98260（versionCode 43），debug 签名。
结构：Java/Shizuku 外壳 + 12 个载荷（伪装为 `lib/arm64-v8a/*.so`）+ `run.sh` 5 阶段编排。
载荷包含 exploit、rootd、KernelSU LKM、ksud、manager、完整符号表。

## 关键结论

- APK 的 exploit 目标为 OPPO/ColorOS `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`；
  与本项目 Honor 6.6.118 boot 同为 6.6.118/android15-8/4K，但不是同一 build。
- 目标 build 与 APK syms 104,356 个同名符号只有 35 个地址相同（0.03%）；KSU LKM 225 个导入符号有 214 个地址不同。
  => APK 的 `t98260_plant`/`t98260_su` 不能直接用于 Honor 6.6.118，必须按目标 build 重新派生/编译。
- 最值得复用：`take_slide.sh + prep_solve + syms.txt` 的 tracefs `sched_blocked_reason` 泄漏 + 全量 kallsyms 投票 KASLR 方法；与具体 build 无关。
- KSU 策略：base LKM + ksud 运行期解析 kallsyms + 替换 vermagic；该策略可在 6.6.118 上尝试，但跨小版本 struct 风险需上机验证。
- ColorOS 专用的 `com.oplus.exsystemservice` antiroot 处理不适用于 Honor；应替换为 Honor 安全组件排查。
- APK 不能直接作为产品：debug 签名、无清理/多机 profile、OPLUS 专用逻辑。

## 产物

- `work/adapt-66118/apk/REPORT.md`
- `work/adapt-66118/apk/APP-STRUCTURE.md`
- `work/adapt-66118/apk/EXTRACT/`（identity/dex/payload/manager/target-66118/tools）
