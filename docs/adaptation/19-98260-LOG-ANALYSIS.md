# 98260 运行日志检查与修复（2026-10-28 20:54）

设备：

```text
MLY-AN00 / MagicOS 11.0.0.111
kernel 6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k
```

## 1. 设备状态

```text
uptime 2087s
SELinux: Permissive
su: 不存在（NO_SU）
KSU: 未加载
SuSFS LKM: 未加载
rootd: 仍存活
```

最近 run.log：

```text
CHAIN=98260
98260_SYMBOLS=flavor=sukisu profile=61258 slide=0x2a9a400000
98260_KSU_PATCH_RC=0 missing=15 flavor=sukisu profile=61258 template=ko-sukisu.ko
98260_KSU=failed reason=ko_patch
98260_SU_ENTRY=skipped reason=ksu_disabled_or_not_loaded
98260_ROOTD_KEPT reason=auto_ksu_disabled_or_not_loaded
98260_SUCCESS=1
SuSFS_LKM_LOAD=disabled reason=switch_off
```

`98260-ksu.log`：

```text
PATCHED=230 MISSING=15 VERMAGIC=6.12.58-... SMP ...
98260_KSU_PATCH_RC=0 missing=15 flavor=sukisu profile=61258 template=ko-sukisu.ko
```

## 2. 根因

管理器中提取的 `ko-sukisu.ko` 实际为：

```text
size 523,744
vermagic 6.6.127-4k-g46a034eca005-dirty
```

而设备是 6.12.58。错误 KMI 模板经 `ko_patch` 后：

```text
PATCHED=230 MISSING=15
```

导致内核模块无法加载，`su` 缺失，设备停留在 Permissive。

KMI 探测空值问题：

- `extractManagerLkm` 在 staging 阶段读取 `uname -r`，个别 Stellar/Shizuku shell 包装器会返回空；
- 空 KMI 时旧逻辑接受第一个 carve 候选（6.6.127）；
- `ko-sukisu.ko` 被写入 override，`kernel_profiles.sh` 优先使用，覆盖了原本 6.12.76 的内置模板。

## 3. 修复

### 3.1 KMI 选择

- `uname -r` 为空时回退到 `System.getProperty("os.version")`；
- KMI 为空时不再接受任意候选；
- 提取前删除旧 `ko-<flavor>.ko`，无匹配时不留 stale override。

### 3.2 管理器 KO 失败回退

`run98260.sh` 在 `ko_patch` 失败或 `MISSING>0`，且模板是
`ko-<flavor>.ko` 时，自动改用内置模板重打：

```text
98260_MANAGER_KO_FALLBACK=1
from=ko-sukisu.ko to=ksu-template-sukisu.ko
reason=missing_symbols_or_patch_rc
98260_KSU_PATCH_RETRY=... missing=0
```

### 3.3 SELinux

KSU 未加载时尝试通过 rootd `setenforce 1`；设备当前 rootd 无
CAP_MAC_ADMIN，实际设置仍被拒绝，需要完整重启恢复 Enforcing。

## 4. 设备端验证

使用当前设备已存在的 rootd，直接对比两个模板：

```text
内置 ksu-template-sukisu.ko:
PATCHED=245 MISSING=0 VERMAGIC=6.12.58-...

管理器 ko-sukisu.ko（6.6.127）:
PATCHED=230 MISSING=15 VERMAGIC=6.12.58-...
```

结论：内置模板正确；管理器的 6.6.127 模板不可用于本机 6.12.58。
新回退逻辑会选中内置模板。

## 5. 当前设备建议

- 立即完整重启恢复 SELinux Enforcing，并清除残留 rootd；
- 重启后用新 APK 重跑 98260，预期日志：
  ```text
  MANAGER_LKM=... kernel=6.12 ...
  ```
  或管理器模块不匹配时：
  ```text
  MANAGER_KO_FALLBACK=1
  KSU_PATCH_RETRY missing=0
  ```
- 若管理器 carve 仍没有 6.12 候选，回退到内置 6.12.76 模板。


## 6. 第二轮日志补充

用户截图显示回退已触发，但 retry 仍打印 missing=15。检查代码发现是回退解析取了**第一条** PATCHED 行：

`sh
grep -m1 '^PATCHED=' " | tail -1
`

ko_patch 的 manager 失败行先写入，所以 -m1 永远取到 missing=15。

已改为：

`sh
grep '^PATCHED=' " | tail -1
`

这样 retry 后会读取内置模板的最后一个结果。若内置模板实际为 MISSING=0，KSU 会继续加载；否则仍按失败处理并提示重启。
