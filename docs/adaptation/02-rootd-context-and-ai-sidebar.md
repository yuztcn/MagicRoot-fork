# Rootd service/property context 修复与 AI 侧边栏初步结论

## 1. rootd service/property context 修复

问题：
- 原 `run98260.sh` 固定传 `--no-real-cred`，fake cred 只改 effective uid，real uid 仍 2000。
- rootd 子进程 exec `/system/bin/sh` 后降权到 shell uid，无法执行 m6 四步。
- rootd 进程 SELinux context 无效，property service 报：
  `init: Unable to set property ... getpeercon() failed: Protocol not available`。

修复：
1. 去掉 `--no-real-cred` 后验证：
   `[real_cred] task->real_cred installed (uid: 0)`
2. rootd 增加 `!argv` 直接 exec 协议，绕过 `/system/bin/sh`。
3. rootd 子进程 setcon 到 `u:r:system_server:s0`。

验证结果：
- `!/system/bin/toybox id` -> `uid=0(root)`
- `CapEff=000001ffffffffff`
- `cmd -l` 可列出系统服务
- `setprop debug.magicroot.test 7` -> 成功，读回 7
- `setprop persist.sys.root.status 0` -> 成功

实验二进制：
`build/binaries/98260-6.12-direct3/exploit-android-key-ptr-61258`

## 2. m6 四步结果

用 full-cap rootd 执行：
- kill hisecd
- kill securityserver
- kill system_server
- 重启后 setprop rootstatus 0

`cmd activity start-activity` 重新打开 InitActivity 后仍显示：

`该设备已经 Root，使用“平行空间”会存在风险，已禁止使用。`

说明 m6 的 hisecd/持久判决清洗 **没有清掉 HUKS/securityserver 的 root 判定**。

补充测试：
- 按已知格式写入 HUKS debug 文件：
  `/data/user/0/com.hihonor.securityserver/asset_debug_info.txt`
  内容 `msc.asset.debug=true`
- 重启 securityserver 后仍被拦。
- `msc.parallelspace.debug_mode` 无法通过 setprop/ksud resetprop 写入（property 被保护）。

结论：剩余 gate 在 HUKS/securityserver 判决层，不在 m6/persist.sys.root.status。

## 3. AI 侧边栏初步分析

候选包：
- com.hihonor.assistant (YOYO Suggestions)
- com.hihonor.aipluginengine (Honor AI Basic Services)
- com.hihonor.brain (HihonorSmart)
- com.honor.aimm (AIModelManager)

静态扫描：
- assistant：无 HwSecurityDiagnoseManager/getRootStatusSync/ASSET_COMMON/persist.sys.root.status 字符串。
- aipluginengine：只有 sidebar UI 资源/图标，无直接 root 检测字符串。
- brain：仅有通用 root 词条，无明确 detector。
- aimm：dex 中未发现相关 root 路径。

判断：AI 侧边栏很可能不是自己直接查 Root，而是通过系统 securityservice/HUKS 或应用列表过滤间接受限。需要在打开侧边栏时抓 logcat/dumpsys 才能定位。

## 4. 设备当前状态

KSU=0，su 不存在，SELinux=Enforcing，persist.sys.root.status=0，user100 仍存在，rootd 已清理。

## 日志

- work/root-98260-parallel-logs/direct3-systemserver.log
- work/root-98260-parallel-logs/direct2-realcred.log
- work/m6-recreate-log.txt
- work/m6-recreate.xml
