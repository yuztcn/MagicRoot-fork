# SpaceGate 3.3 分析：平行空间检测绕过路径

APK：`（平行空间）SpaceGate-3.3.apk.1`
- package: `com.spacegate.unlock`
- versionName: `3.3` / versionCode `19`
- 类型：LSPosed/Xposed 模块
- scope（resources）：仅 `com.hihonor.parallelspace`
- xposed_init：`com.spacegate.unlock.MainHook`

## 它做了什么

不在 system_server 清 STP，也不改属性；只在平行空间进程内改判定结果：

1. `com.hihonor.android.securitydiagnose.HwSecurityDiagnoseManager.getRootStatusSync`
   - after hook
   - 如果返回 Integer 非 0，则 `setResult(0)`

2. `com.hihonor.parallelspace.parallel.g1.e()`
   - before hook
   - `setResult(Boolean.FALSE)`

3. `com.hihonor.parallelspace.spacemanager.SpaceDispatcher.d()`
   - before hook
   - `ensureUserRunning()`

## ensureUserRunning

- 从 `AndroidAppHelper.currentApplication()` 取 UserManager；
- `findParallelUserId()` 找到平行空间 userId；
- `isRunning()` 检查；
- 未运行则通过 Honor `com.hihonor.android.app.ActivityManagerEx`
  启动 profile（反射 `startProfile(am, UserHandle/int)`）；
- 轮询 40 次等待 running；
- 另有 `su -c "am start-user 100"` / `su -c "am stop-user 100"` 命令字符串。

## 关键结论

- SpaceGate 是**进程内 hook**，不是 STP 清零；
- 它只影响 `com.hihonor.parallelspace`，不改变全局 STP；
- 它依赖 LSPosed 注入，且需要 root 才能启动 User 100；
- 它绕开的是应用层 `getRootStatusSync` 和 `g1.e`，不是 hisecd 的持久状态；
- Coolapk 的 `am stop-user 100` 只是 reset User 100；对已 root 的普通 App，
  还要保证 User 100 再被拉起，否则 `am start` 可能只启动壳。

## 对本项目的影响

本项目不是 Xposed 模块，无法在平行空间进程内 hook。因此采用：

```text
am stop-user 100
am start-user -w 100
stpclear（rootd full-cap）
am start -n com.hihonor.parallelspace/.launcher.InitActivity
```

其中 `am start-user -w 100` 是本次从 SpaceGate 补上的关键步骤。

如果用户已安装 LSPosed：

- 可安装 SpaceGate 作为 target 进程 hook；
- 此时 STP clear 不是唯一路径，SpaceGate 会把
  `getRootStatusSync`/`g1.e` 的返回值压掉；
- 但 SpaceGate 不能替代其他应用的 root 隐藏。

本项目不打包 SpaceGate APK，避免未经授权分发第三方模块。


## MLY-AN00 实测补充

该机平行空间实际 userId 为 **103**，不是 100：

```text
UserInfo{103:平行空间:20000410}
```

`am stop-user 103` 会把 profile 置为 `RUNNING_LOCKED`，导致内部应用持续
“程序准备中”；正常设置入口会把它拉起为 `RUNNING_UNLOCKED`。
本项目最终不 stop-user，只清 STP 后交给平行空间启动。
