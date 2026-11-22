# onekeyjb 参考资料与落地改进

日期：2026-11-10。参考仓库：https://github.com/xingranya/onekeyjb

- 固定提交：`8657b405a0da25894f331994d8220c3edd234a08`
- 本地只读副本：`/data/data/cc.codroid/files/home/workspace/reference/onekeyjb`
- 许可证：GPL-3.0；全文沿用 `LICENSES/GPL-3.0.txt`
- 未执行其下载脚本、未构建或运行其二进制；大型生成索引 `knowledge/ai-kb`
  未作为事实来源。

## 1. 已阅读的 knowledge 资料

- `02-越狱链路原理.md`：root 实测判据、运行锁、高负载等待、失败语义。
- `03-管理器适配.md`：五家管理器、ksud 随机库名与运行时取材；其需要写
  `/data/app` 的 ksud 归一化没有被引入。
- `07-故障排查.md`：日志/诊断顺序与必须硬重启的条件。
- `10-98260执行引擎.md`：阶段标记、逐行同步与重启后回读、结果分类。
- `13-踩坑与修复记录.md`：回收未命中时不能盲写、按一次尝试计数、成功后
  同步落状态；源码修改用函数锚点而非行号。
- `14-验证清单.md`：编译/资产 hash 与真机验收分开，明确“编译通过 ≠ 功能通过”。

其余主题（云端目录、更新协议、热切换、机型 UI 规范）与本次双分支目标无直接
关系，没有据此添加功能。

## 2. 已核对的其他源码

- `native/executor/main.c` / `leak.c` / `exec.h`：其自研执行器目前只有 leak，
  `main.c` 明确返回 `plant 尚未实现`；不能把该执行器当作 MagicRoot 的写路径。
  `leak.c` 的多调用点 slide 投票是可参考思路，但本次没有替换已验证的 slide
  与 cred 自检。
- `merged-app/.../JailbreakController.kt`：逐行 `FileOutputStream(append)`、
  `flush()`、`fd.sync()`，启动时读取 `onekey-live.log` 的最后 400 行。
- `SystemReadinessGate.kt`：boot_completed、Awake、procs_running 的稳定采样；
  与现有 PREFLIGHT 等待方向一致，未照搬其阈值。
- `RunReport.kt`：区分“未写内核”和“已写但未 root”，避免一律要求重启。
- `Cve98260Engine.kt`：已有 root 短接、管理器运行时取材；文档与日志文案存在
  不一致处，未把其 boot 重试语义作为事实依据。

## 3. 已落地的改进

### LiveLogStore

新增独立纯 Java 实现：

- `main/.../LiveLogStore.java`
- 每次 append/reset 都 flush + `FileDescriptor.sync()`；
- MainActivity 用单后台 writer 串行写入，不在 UI 线程做文件 I/O；
- 新运行截断旧日志，应用启动时恢复最后 400 行并标注可能被软重启/panic 中断；
- 设备侧 run.log 的轮询行也进入同一持久化存储，成功自动清理后仍可回看。

这与 rc16/rc17 的取证缺口直接相关：此前成功后清理或 panic 可能同时失去
native/run 日志。持久化不能替代 dumplog 内核栈，但能保留用户态最后进度。

### 软重启风险可见

`98260_SOFT_REBOOT_SAFE=0` 在成功页显示“提权完成 · 禁止软重启”并反馈风险，
不再把 DONE 误解为收尸安全。

### 关于页与许可

关于页新增 onekeyjb 链接、GPL-3.0 说明及双分支/late-load 实际行为；
`THIRD_PARTY_NOTICES.md` 记录固定提交、参考范围和未采用部分。

## 4. 明确不做

- 不引入 onekeyjb 的机型/签名/版本硬性门禁。
- 不引入热切换、`/data/app` 写入或通用加载器替换。
- 不采用其未完成的 plant，也不据此修改 real-cred 的 tile/cap 写原语。
- 不因为其文档中的“3 秒”结论而声称 MagicRoot 有相同命中率和速度。
- 本地测试通过不等于 fake/real 新链路已完成真机验证。

## 5. 测试

- `LiveLogStoreTest`：真实 JVM 文件写入、同步后关闭重开、尾部恢复、unicode、
  reset 截断和非法参数，全部通过。
- 生命周期静态回归新增 live-log 接线检查；完整 `tools/check.sh` 作为最终门禁。
- real/fake 两个默认包均重新构建并比较签名、资产与 DEX。

最终结果：`LiveLogStoreTest all passed`，生命周期 47/47，完整
`tools/check.sh` 为 `ALL CHECKS PASSED`。候选包同为 61,205,489 B：
real=`/sdcard/cccodroid/MagicRoot-real-cred.apk`（`cc3cdc6e…7109`），
fake=`/sdcard/cccodroid/MagicRoot-fake-cred.apk`（`ef4ce60e…85a5`）。
两包 286 项资产一致，About/风险标记均在 DEX 中验证。

改进后的源码快照：`/sdcard/cccodroid/MagicRoot-1.0.5-onekeyjb-source.zip`，
775 文件，SHA-256 `8e893d432a002aed3eee1ae2287fa99619d0dca5ece54dd3eccf6c534620c7a5`；
不含 APK、密钥或日志。改进前的 dual-cred 备份仍是独立文件，未被覆盖。
