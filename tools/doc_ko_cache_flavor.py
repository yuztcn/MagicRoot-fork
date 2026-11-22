from pathlib import Path

WS = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced")
p = WS / "docs" / "DEVICE-VERIFY.md"
t = p.read_text(encoding="utf-8")
if "## 34. ko_cache_keep 与 ko_flavor" not in t:
    t = t.rstrip() + """

---

## 34. `ko_cache_keep` 与 ko_flavor 切换分析（2026-10-25 23:20）

### 结论

`KO_CACHE_KEEP`（实际变量 `KO_CACHE_MAX`）**本身只是持久缓存保留数量，不参与
flavor 选择**；但它旧版的实现存在两个会间接影响“实际加载哪个 KO”的问题：

1. 持久缓存文件名使用截断后的 key：
   `tr ': |' '___' | cut -c1-180`。同 boot/slide/uname/flavor 下，如果模板
   被替换但 key 的差异落在 180 字符之后，旧 `.ko` 可能与新 key 共用文件名。
2. 命中持久缓存时只检查文件存在，**不校验该缓存文件对应的完整 key**；
   旧版 `ko.cache` 校验只在工作目录分支发生，持久缓存分支没有 sidecar。

因此理论上存在：切换 flavor/模板后，仍从同名持久缓存加载旧 KO。`KO_CACHE_MAX`
调大/调小不会直接改变 flavor，但保留更多旧条目会增加这类 stale 命中概率；
调小则会删除缓存，只影响速度，不会修复错误命中。

### 修复

- key 增加 `PROFILE_ID`、`KSU_FLAVOR`、模板/syms/ko_patch 的 **sha256**
  （不再只依赖 `size:mtime`）；
- 持久缓存文件名改为完整 key 的 sha256 前 32 位，消除截断碰撞；
- 每个持久 `.ko` 配一个 `.key` sidecar，内容为完整 `KO_KEY`；恢复时必须
  sidecar 完全匹配，否则输出 `KO_CACHE_STALE` 并删除，强制重新 patch；
- `ko.cache` 继续保存完整 key；
- `prune_ko_cache` 只做保留/过期清理，**永远排除当前 KO**，并同步删除
  sidecar；日志明确标注
  `KO_CACHE_KEEP=... (retention only; not a flavor selector)`；
- 新增日志：`KO_CACHE_IDENTITY`、`KO_CACHE_SAVED`、`KO_CACHE_STALE`、
  `KO_PATCH_SKIPPED reason=... flavor=...`。

修复后，flavor/模板变化会得到不同 key/tag，旧缓存不会被恢复；实际加载的
`ksu-patched.ko` 必定来自当前 flavor + 当前模板内容 + 当前 syms + 当前
`ko_patch`。
"""
    p.write_text(t, encoding="utf-8", newline="\n")
    print("appended DEVICE-VERIFY §34")
else:
    print("§34 present")
