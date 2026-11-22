# init_cred：late-load / throne 注册修复

日期：2026-11-11

## 1. 问题与修复原则

FinaSU 的 `do_track_throne()` 用 `override_creds(ksu_cred)` 读取
`/data/system/packages.list`。direct-finit/late-load 调用者的凭据可能缺少
`CAP_DAC_OVERRIDE`，即使签名和 UID 已登记，crown 仍会因 `-13` 失败。

上游 `woshigenm/CVE-2026-98260` 的 `patch_track_throne()` 将该凭据引用改为
`init_cred`，不是给所有 uid0 进程补权限。本文实现相同方案，并补上 FinaSU 的
`do_track_throne` 包装层变体。

约束：

- 不修改 `packages.list` 的内容或永久权限；
- 不把 `ksu_cred` 的能力提升扩散到普通进程；
- 不使用未证明的 `init_cred` 地址；
- 不把 `TRACK_THRONE=already` 仅建立在“模块里存在 init_cred”上。

## 2. 实现

### `throne_patch.c`

`binary-sources/64560/native/throne_patch.c` 只移植 throne 相关部分，不带入
上游 `patch_noenforce`：

1. 在 `track_throne` 或 `do_track_throne` 范围内找 `ADRP + LDR` 的
   `ksu_cred` 重定位；
2. 改为 `ADRP + ADD` 的 `init_cred` 重定位；
3. 没有 `init_cred` 时追加名字和未定义符号，交给原有 per-profile 符号解析；
4. `already` 必须同时看到该函数范围内的 `init_cred` ADRP+ADD 重定位以及
   对应的 `add` 指令；否则复用已有符号继续修补，不重复追加。

`binary-sources/64560/native/ko_patch.c` 与
`main/app/native/ko_patch.c` 都在普通符号解析前调用它。原有
`PATCHED/MISSING/REPAIRED` 和 SHN_XINDEX 修复保留。
`build-binaries.ps1` 已把 `throne_patch.c` 加入 ko_patch 构建。

### late-load 消费路径

- **fake**：`ko_patch` → `ksud insmod` → 同一 `ksud late-load` 用户态阶段。
  late-load 本身返回码必须为 0；不再先加载管理器内嵌的原始 KO。
- **primary**：同样先 `ksud insmod "$PATCHED"`，再 late-load，避免 primary
  静默换成内嵌原模块；其 late-load 返回码同样必须为 0。
- fake/primary 都在写日志前保存 `$?`，避免把 `tee` 的返回码误当作 late-load
  返回码。
- **real direct-finit / staged patched-KO late-load / H1C / insmod fallback**：
  这些路径本来就消费 `$PATCHED`，现在输出包含 init_cred 修复。

无证明地址时，`ko_patch` 输出 `TRACK_THRONE=unavailable`；fake 明确记录
`98260_INIT_CRED_FALLBACK=legacy_embedded` 并保留旧链路。该兼容路径不被描述
为修复。`no_reloc`、`partial`、符号缺失或 vermagic 不匹配仍 fail closed。

## 3. 静态验证

`tools/test_init_cred_patch.py` 验证：

- 五种 Flavor 的 `track_throne`/`do_track_throne` 修补；
- FinaSU `do_track_throne` 的 ADRP/LDR → ADRP/ADD 指令和重定位；
- 6.6、6.12、6.18 模板；
- 幂等 `already`，不重复追加 init_cred；
- fake/primary 都先消费 patched KO，且 late-load RC 被检查；
- 无证明地址显式为 unavailable，不伪造完成。

## 4. 地址来源

已用精确 boot 或现有同内核全重叠映射补齐：

- g142：既有 `init_cred`；
- 6123、61258、61258b、6138、6138y：既有记录；
- g856：`boot_ota_1793682544248.img` → `0xffffffc0823f2aa8`；
- 61258c：BSN-AN00 10.0.0.102 boot.img → `0xffffffc082573870`；
- 6689：`boot_ota_1793726728599.img` → `0xffffffc082170698`；
- f171：`boot（winrt，内核6.6.118）.img` → `0xffffffc082190790`；
- g554：`6.6.118-...-g554929766a0d...img` → `0xffffffc082190790`；
- ga812：`build/kallsyms/ga812.txt` → `0xffffffc0821a0790`；
- g264：对照包内 AMG-AN00 10.0.0.175 boot.img → `0xffffffc00a0d1d00`；
- g19a / ELP / MagicPad 路径使用各自已有表。

`tools/sync_init_cred_symbols.py` 只在所有重叠符号地址一致时把主表值传播到
其他 Flavor，并同步 per-profile `SHA256SUMS.txt`。没有用相邻版本、型号或
`init_task` 偏移猜地址。

### 6658 补齐证据（2026-11-11 补充）

用户补充的 `init_boot_(2).img` 是 Android v4 init_boot，`kernel_size=0`，未用于
符号提取。另一份完整 `boot (3).img` 精确匹配
`6.6.58-android15-8-g6484937db664-abogki407459068-4k`：

```text
boot SHA-256    bf22d44ba14dd87327ea7b5dc8bb28fd71b1ae4b71c39e1f10a204c62039e278
kernel SHA-256  fdd20c970461e368fee4e361b03a2d5e72132192f5a13f1bb5467958937ff2b8
kallsyms        109221 项，SHA-256 0d41540906ba8d2a66981f26668e757763d260e40d54e7d36d304c39088648cc
init_cred       0xffffffc082170748
```

导出器使用当前 `KernelProfileGenerator` / `ExportKernelKallsyms` 源码重新编译。
五张 6658 表与导出的重叠项分别为 225 / 227 / 239 / 240 / 251，全部地址零差异，
随后五表均只追加同一个 `init_cred`。五个 Flavor 的实际 6.6 模板均验证
`TRACK_THRONE=patched`、`MISSING=0`，且 ELF 中 `init_cred` 为上述 ABS 地址。
此前列出的 unavailable 缺失项因此全部补齐；未知未来 profile 仍保持 fail-closed。

## 5. 当前 ko_patch

```text
main/app/assets/ko_patch
SHA-256 fe3f983200083767baa822d76d46d32f6aa42bb3e4419762306b894b1f6dc10c
```

本文件只记录本机静态构建与验证，不表示已在真机重新运行 UAF 或所有内核都完成
管理器注册。真机验收应同时看到：

```text
TRACK_THRONE=patched（或严格 already）
98260_INIT_CRED_MODULE_LIVE=1
Crowning manager: <package>(uid=<uid>)
管理器进程持有 anon_inode:[ksu_driver]
```

## 6. 最终构建

```text
main/app/MagicRoot.apk
61,213,682 B
SHA-256 9ce6cdd0abbf5e67e2e08e5b0c81fb3cdb464ed6ef6ec38618906af76569bd7a
V3 certificate ef572a91ebf470dc6606af3639e8aa8d28b4bd0768d31b5efbbb2933d92c8296
```

APK 中 327 个资产按去重映射与工作树逐字节一致；`6157-integrity.tsv` 当前
SHA-256 为 `716bff07d37682e24f34e0422702c67debbe068dbb2fda811a6c6959087f8bc9`。
未安装此包，未执行真机 UAF、insmod 或 soft-reboot。
