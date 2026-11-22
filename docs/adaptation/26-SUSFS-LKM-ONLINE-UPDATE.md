# SuSFS LKM 在线更新

## 功能

About/设置页新增：

```text
SuSFS LKM 在线更新
检查并更新 SuSFS LKM
```

流程：

1. 用 `System.getProperty("os.version")` 确定当前内核 release（fallback：`uname -r`、`/proc/version`）。
2. 解析：
   ```text
   KMI     = 6.12
   Android = android16
   ```
3. 请求：
   ```text
   https://api.github.com/repos/inforcqb/susfs4ksu-lkm/releases/latest
   ```
4. 在选择资产时要求：
   - 文件名以 `susfs_guard_lkm` 开头、以 `.ko` 结尾；
   - 优先 `-android16-6.12.ko`；
   - 没有精确 Android 版本时，回退到 `-6.12.ko`。
5. 下载到应用私有目录：
   ```text
   /data/user/0/com.aoki.magicroot/files/susfs/
     latest.txt
     susfs_guard_lkm-<tag>-<kmi>.ko
   ```
6. 校验：
   - HTTP 状态与大小；
   - GitHub release 的 `sha256:` digest；
   - ELF magic；
   - `.modinfo vermagic` 的 `major.minor` 必须等于当前 KMI。
7. 通过 app 的 Stellar/Shizuku shell 暂存到：
   ```text
   /data/local/tmp/magic/susfs_guard_lkm.updated.ko
   ```
   私有目录始终保留一份；暂存失败时提示保持 Stellar/Shizuku 可用。

## 加载优先级与回退

`run.sh` 的 `susfs_load()`：

1. 若 `susfs_guard_lkm.updated.ko` 存在，读取 vermagic；KMI 与当前内核一致时优先加载；
2. 加载失败（或 KMI 不匹配）后，继续尝试内置：
   ```text
   /data/local/tmp/magic/susfs_guard_lkm.ko
   ```
3. 两者均失败才报告：
   ```text
   SuSFS_LKM_LOADED=0
   SuSFS_LKM_FALLBACK=exhausted
   ```
4. 成功时输出：
   ```text
   SuSFS_LKM_USED=...
   SuSFS_LKM_SOURCE=updated|bundled
   SuSFS_LKM_FALLBACK=0|1
   ```

在线模块不可能因为损坏、KMI 错误或 insmod 失败而破坏内置回退路径。

## 实测

设备内核：

```text
6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
```

下载：

```text
tag   = v2.3.0-r18.5
asset = susfs_guard_lkm-android16-6.12.ko
size  = 3258016
```

私有目录：

```text
susfs_guard_lkm-v2.3.0-r18.5-6.12.ko
latest.txt
```

暂存：

```text
/data/local/tmp/magic/susfs_guard_lkm.updated.ko
```

UI 状态：

```text
已下载 v2.3.0-r18.5 / susfs_guard_lkm-android16-6.12.ko；提权时优先加载新版模块
```

## 权限

`AndroidManifest.xml` 增加：

```xml
<uses-permission android:name="android.permission.INTERNET" />
```


## 内置 LKM 升级记录

内置资产已更新为最新 release：

`	ext
tag      = v2.3.0-r18.5
asset    = susfs_guard_lkm-android16-6.12.ko
size     = 3258016
sha256   = 1F50330AD2597A527EA200DD7F2A5AA21C1B3EB5A845E176B9EFBC3322266214
vermagic = 6.12.76-4k
`

内置路径：

`	ext
main/app/assets/susfs_guard_lkm.ko
`

在线更新下载到私有目录后仍优先于内置模块；加载失败回退到该内置最新模块。
