from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
doc = WS / "docs/reference/kernel-adaptation-61258-61238.md"
t = doc.read_text(encoding="utf-8")
t += """

---

## 8. 构建与静态产物（2026-10-25 19:30）

- `main/app/assets/ksu_grant` 已用 zig 重编：
  `zig cc -target aarch64-linux-musl -O2 -static -s`，27,288 B；
  原 1,044,968 B（未 strip）的旧二进制保留在 `.probe/ksu_grant.old`。
- APK 重新构建通过：
  - `versionCode=8 / versionName=1.0.3`
  - size = **3,814,455 B**
  - sha256 = `69dc57bf0e556aa050e1ed03fd6d6c691956e1f39bce9f41393ec666f193c58e`
  - `tools/verify_apk.py`：`All required assets and flavor markers present.`
- 静态审计：`refs/kernel-audit/audit.json`（本次运行已重新生成，污染扫描 0 命中）。
- 运行期验证仍然待设备连接后执行；本包未安装到设备。
"""
doc.write_text(t, encoding="utf-8", newline="\n")
print("doc updated")

dv = WS / "docs/DEVICE-VERIFY.md"
dt = dv.read_text(encoding="utf-8")
if "## 21. 6.12.58/6.12.38 专项适配" not in dt:
    dt = dt.rstrip() + """

---

## 21. 6.12.58/6.12.38 专项适配（2026-10-25 19:30）

按五项要求完成静态适配与构建：

1. perf known-cred + 分离写 cred/加载模块：现有 `cred_target`（perf
   kmem_cache_alloc + capset → cred）+ `t64560_cred`（known-cred writer）
   链路确认，run.sh 增加 `CRED_LEAK_SELF_CHECK`/失败提示；
2. KASLR：现有 `kaslr_slide_61258/6138` 的文本锚点 + raw 值投票之上，新增
   run.sh `KASLR_CROSS_CHECK`（用 profile 的 prepare_creds/selinux_state link
   与 slide 独立重算并逐字符比对，votes/anchors/bytes 阈值，fail-closed）；
3. ko_patch：`PATCHED/MISSING` 自检进 run.sh，missing>0 在 permissive 前失败；
   ko cache 命中也会打印缓存的自检行；
4. ksu_grant：新增双 magic reboot 后门（0xcafebabe/0xdeadcafe）+ `/dev/ksu`
   兜底 + `KSU_FD_SOURCE`；run.sh 记录 `KSU_GRANT_METHOD`；
5. 6.18 复用审计：无 0x908/6.18 模板/6.18 resolve 地址进入运行时资产；
   6.12.58 `prepare_creds` 反汇编确认 task->cred=0x900、cred_size=0xb8。

详见 `docs/reference/kernel-adaptation-61258-61238.md` 与
`refs/kernel-audit/audit.json`。当前无设备连接，真机验证待补。
"""
    dv.write_text(dt, encoding="utf-8", newline="\n")
    print("DEVICE-VERIFY §21 appended")
"""
"""
