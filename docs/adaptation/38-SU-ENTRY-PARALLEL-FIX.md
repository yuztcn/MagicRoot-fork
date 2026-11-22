# su entry 隐藏方案与平行空间修复审计

日期：2026-10-29

## 1. 日志结论

```text
PARALLEL_FIX_BEGIN user=100
STP_CLEAR_STAGE_*_FAILED=KSU_RC=127
STP_CLEAR=missing
PARALLEL_FIX_FAILED=KSU_RC=127
```

`KSU_RC=127` 不是 stpclear 本身的问题，而是：

```text
findSuEntry() 只检查 canExecute()
→ 选中坏掉的 /system/bin/su 或 /product/bin/su
→ su -c 返回 127（命令/后端不存在）
→ 三个 stpclear 暂存路径全部失败
```

`user=100` 是第二个独立问题：

```text
findParallelUserId() 的 root 调用也因 KSU_RC=127 失败
→ 直接 return 100
→ 实际平行空间 user 103 被忽略
```

## 2. su entry 当前暴露面

`su_entry.sh` 之前默认：

```text
/product/bin 整个目录 cp 到 $D/product_bin
→ 放入 su 包装器
→ mount --bind 到 /product/bin
```

结果：

```text
/product/bin/su 对全部 app 可见
Duck Detector 命中 SU binary (/product/bin/su)
```

这不是隐藏，而是主动增加了一个检测路径。

同时 `/system/bin/su` 仍可能是 KSU su_compat shim，`/data/local/tmp/magic/su` 也可能被文件扫描命中。

## 3. 已修复

### 3.1 su entry

- 默认不再创建 `/product/bin` bind mount；
- 启动时若发现旧的 `$D/product_bin -> /product/bin` 挂载，尝试卸载；
- 只有显式：
  ```text
  MAGICROOT_SU_ENTRY_PRODUCT_BIN=1
  ```
  才保留旧的调试路径，且必须存在 `su_forward`；
- Termux 搜索顺序改为：
  ```text
  /data/adb/ksu/bin/su
  /data/local/tmp/magic/su
  ...
  ```
  不再把 `/product/bin/su` 放第一；
- `SU_ENTRY_BACKEND` 优先 `/data/adb/ksu/bin/su`。

### 3.2 su 探测

`findSuEntry()` 现在对每个候选执行：

```text
su -c 'id -u'
```

要求：

```text
rc=0
stdout=0
```

才接受。候选顺序：

```text
/data/adb/ksu/bin/su
/system/bin/su
/product/bin/su
/debug_ramdisk/su
```

坏入口会被跳过，不再直接把 127 抛给 stpclear。

`ksuRootExec()` 改为 `redirectErrorStream(true)`，stderr 也会进入错误日志。

### 3.3 平行空间 user

`findParallelUserId()` 只接受：

```text
UserInfo{<id>:...平行...}
```

或：

```text
UserInfo{<id>:...parallel...}
```

不再无条件 `return 100`。

识别失败返回 `-1`，界面明确提示“未识别到平行空间用户”，不会再对 100 执行 stop/start/launch 的错误路径。

## 4. 仍需处理

1. **旧 `/product/bin` 挂载**：本次修复在下次 su_entry 运行时才卸载；当前 boot 若已经挂载，重启最干净。
2. **`/system/bin/su` / `/data/local/tmp/magic/su`**：仍可能被 app 扫描到；游戏侧需 SuSFS scheme 3/4 对指定 UID 隐藏。
3. **Root 管理器包**：5 个包仍在，Duck 仍会命中；需卸载/隐藏。
4. **LSPosed**：仍是最高风险项，和 su entry 独立。

## 5. 验证顺序

1. 重跑 98260 链，确认：
   ```text
   SU_ENTRY_PRODUCT_BIN=disabled
   SU_ENTRY_BACKEND=/data/adb/ksu/bin/su
   SU_ENTRY=ok
   ```
2. 点“修复平行空间”，期望：
   ```text
   PARALLEL_FIX_BEGIN user=103
   STP_CLEAR_STAGE=base64-inline
   STP_CLEAR_RC=0
   PARALLEL_FIX 完成
   ```
3. 若仍是 127，抓：
   ```bash
   ls -l /system/bin/su /product/bin/su /data/adb/ksu/bin/su
   /data/adb/ksu/bin/su -c id
   ```
4. Duck 复测应不再命中 `/product/bin/su`；LSPosed/manager 仍会命中。


## 6. 现场追加证据

22:20 左右在设备上直接检查：

`	ext
/system/bin/su: No such file or directory
/product/bin/su: 9056 bytes, wrapper
/data/adb/ksu/bin/su: Permission denied (from adb shell)
/data/local/tmp/magic/su: absent
su -c id: 内核接口未允许执行 /system/bin/su
persist.sys.root.status=0
`

说明当时的真实状态是：

`	ext
KSU 模块已加载
但 KSU su provider 已失效
/product/bin/su 包装器依赖已关闭的 rootd socket
→ 所有 app su 调用 KSU_RC=127
`

根因不是 stpclear，而是：

`	ext
su_entry=1 + su_compat=0
→ 只有 rootd/product 包装器
→ run98260 先清 rootd，再 feature set su_compat 0
→ 持久 su provider 消失
`

## 7. 追加修复：su_entry 强制持久 su provider


un98260.sh 现在：

`	ext
if su_entry=1 and su_compat=0:
    su_compat=1
    log 98260_SU_COMPAT_OVERRIDE=1 reason=su_entry_needs_persistent_provider
`

原因：

- 不再创建 /product/bin bind mount；
- 如果仍保持 su_compat=0，su_entry 就没有持久 provider；
- 强制 su_compat=1 后，KSU /system/bin/su 保留，rootd socket 可以正常清理；
- app/manager 后续调用 /system/bin/su，不再依赖 rootd。

代价：

- /system/bin/su 仍然是一个可见路径；
- 游戏侧仍需用 SuSFS scheme 3/4 对指定 UID 隐藏；
- 但不会再出现“root 成功、su 全坏”的状态。
