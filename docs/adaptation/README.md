# 适配与逆向思路索引

本目录随完整 source 提供以下适配/逆向记录：

0. 00-ROOT-DETECTION-FIX-REPORT-CN.md
   完整 Root 检测原理与修复方式总报告。

1. 01-STP-clear-fix.md
   STP/hisecd 根因、StpClearStatus 实测、平行空间修复。
2. 02-rootd-context-and-ai-sidebar.md
   rootd real-cred/direct-exec/system_server context 与 AI 侧边栏结论。
3. 03-honor-id-analysis.md
   com.hihonor.id Root/DRM/Widevine/AI 关系。
4. 04-securityserver-huks-analysis.md
   system_server securityserver、STP HIDL、HUKS 消费链。
5. 05-native-analysis.md
   libhisec/libhonordetect/Widevine/HUKS native 反编译。
6. 06-ai-sidebar-magicvoice.md
   YOYO 侧边栏 magicvoice Root 状态导出路径。
7. 07-root-targets-and-widevine.md
   gtxdrivers/游戏管家/安全公共服务/Widevine 结论。

已验证二进制曾位于 binary-sources/98260-6.12/verified/，审计副本已从公开树移除；
SHA-256 保留在 docs/adaptation/VERIFIED-BINARIES-SHA256SUMS.txt，复现说明见 docs/ADAPT-ROOTD-STP-REPRO.md。
所有操作均未修改 /system 或 /vendor 分区。
8. 09-66118-STATIC-ADAPT.md / 09a/09b
   Honor AAK 6.6.118 boot.img 静态适配：符号/常量/profile/编译产物；AVB 私钥不可得，禁止改刷 boot。
9. 10-66118-APK-ANALYSIS.md / 10a/10b
   ColorOS 17 6.6.x KMRoot APK 逆向；OPPO build 常量不可跨 Honor 6.6.118 复用。
10. 11-SUSFS-LKM-ADAPTATION.md / 11a
   SuSFS LKM 预编译模块加载、接口与适配风险。
11. 46-98260-susfs-off-finalize.md
   98260 未启用 SuSFS 时 98% 停滞的根因、统一收尾标记与超时保护。
12. 47-6157-termux-su-entry.md
   6.1.x CGA 无内核 su_compat：su_lkm 用户态入口与 Termux su 搜索列表修复。
13. 48-61258-reclaim-and-finalize-fix.md
   6.12.58 回收页复合页匹配、全屏日志返回丢步骤、98260 收尾 98% 卡顿的修复。
14. ../6157-CGA-FEATURE-RESTORE.md
   g264/gaaa 的 su_compat、kernel_umount、selinux_hide 恢复与可复现构建记录。

