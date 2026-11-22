# SuSFS LKM 未加载原因与修复

## 1. 现象

设备：

```text
KernelSU: Live
SELinux: Enforcing
su: 可用
SuSFS LKM: 未加载
```

App 开关已开启（SharedPreferences `magicroot_susfs/enabled=true`），但 run.log：

```text
SUSFS_LOAD=disabled reason=switch_off
```

## 2. 原因

`run.sh` 读取 marker 内容：

```sh
SUSFS_ENABLE=${MAGICROOT_SUSFS:-$(cat "$D/susfs" ...)}
```

旧版 MainActivity 写 marker 用的是：

```java
shell("touch " + WORK + "/susfs");
```

marker 是 0 字节空文件；`cat` 输出空串，`case` 判为 0，因此始终 `switch_off`。

## 3. 修复

- App 改为写内容：

```java
shell("echo 1 > " + WORK + "/susfs; chmod 644 " + WORK + "/susfs");
```

- `run.sh` 兼容旧空 marker：

```sh
if [ -z "$SUSFS_ENABLE" ]; then
    [ -f "$D/susfs" ] && SUSFS_ENABLE=1 || SUSFS_ENABLE=0
fi
```

- 已加载但 `/sys/module` 不可见的场景，改用 `/proc/susfs_path` 二次判定：

```sh
if [ -d /sys/module/susfs_guard_lkm ] || [ -e /proc/susfs_path ]; then
    echo "SuSFS_LKM_LOADED=1"
fi
```

## 4. 加载验证

KSU 已加载时直接用设备 root：

```text
./susfs_insmod susfs_guard_lkm.ko
LOADER_RC=0
/sys/module/susfs_guard_lkm exists
/proc/susfs_path、/proc/susfs_hide_modules 等出现
susfs_insmod: resolved 110/110; unresolved 0
```

第二次通过 `ksud insmod` 尝试会报 `EEXIST`，这是模块已加载的正常表现；run.sh 现在先检查 `/proc/susfs_path`，不会误判。

## 5. 文案

用户可见文案统一为 **SuSFS LKM**：

- 主界面开关：`SuSFS LKM`
- 副标题：`默认关 · 与 Flavor 独立，仅加载 SuSFS LKM`
- About 参考：`SuSFS LKM：...`
- 日志：
  - `SuSFS_LKM_LOAD=...`
  - `SuSFS_LKM_LOAD_RC=...`
  - `SuSFS_LKM_LOADED=...`

内核模块名、`/proc/susfs_*`、`susfs_insmod`、`susfs_guard_lkm.ko` 等内核 ABI/路径保持原名，不能改。

## 6. 当前设备

```text
KernelSU: Live
SELinux: Enforcing
SuSFS LKM: 已手动加载（/sys/module 与 /proc/susfs_path 存在）
marker: /data/local/tmp/magic/susfs = 1
```

新 APK 已安装；下次 98260 运行会看到 marker=1，若模块已加载则直接复用并输出 `SuSFS_LKM_LOADED=1`。
