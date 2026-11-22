#!/system/bin/sh
# ksu_loader.sh — CGA-W00 (MagicPad3) KernelSU late-load.
#
# Runs as uid 0 in the KERNEL domain: the exploit's rooted child execs
#   /system/bin/sh <this script>
# (root.c dc_spawn_child -> KSU_ACTIVATE). By then the exploit has already:
#   * patched our cred (uid 0, full caps, security sid = kernel)
#   * flipped the runtime sig_enforce bool to 0 (CONFIG_MODULE_SIG_FORCE's only
#     real gate; sysfs is bool_enable_only so it cannot be cleared from sysfs)
#   * pointed random_table[4].data (boot_id ctl_table.data) back at the true
#     sysctl_bootid buffer
#   * set selinux_state.enforcing = 0 (Permissive)
#
# Order is the whole point (H80GT recipe):
#   util-root -> inject policy -> load .ko -> ksud stages -> restore knobs
#   -> ENFORCE LAST (too early and the root process can no longer write files or
#      exec programs).
#
# HARD LESSON (2026-09-19 run 1): if hisecd IS ever frozen (markers
# FREEZE_HISECD / FREEZE_HISECD_LONG) it MUST be thawed on every exit path. A
# failure that leaves it SIGSTOPped wedges Honor's periodic root scan, and
# `adb reboot` / `setprop sys.powerctl` / `svc power reboot` all silently no-op -
# only a physical power cycle recovers the device (we hit that twice). By default
# it is no longer frozen at all (its anti-root reaction is harmless - see the
# section 2 comment), and every /proc/modules read and ksud call is guarded with
# `timeout` so a bad load can never hang this script.
# ★ fix-20261017：RD 按脚本自身位置解析（透过软链调用时仍得 /data/local/tmp/ksu）。
#   原来写死，一旦部署目录和软链不一致，本脚本所有读写都打到空目录上，
#   日志里全是 not found，看起来像「加载失败」。
_lself=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
RD=${_lself:-/data/local/tmp/ksu}
# ★ 2.78：装载前就打开台账 fd（见 _stage 注释）。失败也不影响主流程。
{ : >>"$RD/ksu_stage.log"; } 2>/dev/null
exec 9>>"$RD/ksu_stage.log" 2>/dev/null || true
{ _u="?"; while IFS= read -r _l; do _u="${_l%%.*}"; break; done < /proc/uptime 2>/dev/null
  printf '=== loader start uptime=%s ===\n' "$_u"; } >&9 2>/dev/null || true
mkdir -p "$RD" 2>/dev/null
# ★ 2026-10-16：补上 BOOT —— 原文件从未定义它，而日志行里引用了 `boot=$BOOT`
#   ⇒ 真机日志里渲染成 "boot= ts=…"（值没填）。
BOOT=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
[ -n "$BOOT" ] || BOOT=unknown
OUT=$RD/ksu_load.log
> $OUT
{
  echo "=== loader start ==="
  id; getenforce; echo "uptime=$(cut -d. -f1 /proc/uptime)"
  echo "=== payloads ==="; ls -l $RD

  # ★★ 2.39：这几个函数原来是定义在 915 行（早期解析之后）★★
  #   2.38 把「早期解析」插在第 60 行，结果 bash 报 `_extract_mgr_ksud: inaccessible or not found`
  #   —— 调用时函数还不存在。现在把定义整体提到 payloads 之后、任何调用之前。
_mgr_ver() {
  [ -f "$RD/ksud_mgr" ] || return 0
  # 只认 KernelSU 系带后缀的版本串（4.2.0-rc3 / 4.2.1-r2）。
  # 不加后缀会撞上二进制里第一个无关版本号（实测抓到 0.15.1），别乱猜：
  # 没有后缀的管理器（FinaSU / 官方）交给包名映射。
  # \b 必须加：不加会把 versionCode 和版本号粘成 "352524.2.0-rc3"（实测踩过）
  # ★★ 2.39（真机：SukiSU 一直「未知版本」⇒ 永远选 r1 的 ko）★★
  #   根因：\b 是 PCRE 语法，**Android toybox grep 不支持**（POSIX ERE 无 \b），
  #   这条 grep 在设备上恒空；之前在 PC 上验过没问题，其实手机上从未生效。
  #   ⇒ 去掉 \b，改用 awk 卡主版本号 <= 20，滤掉 versionCode 粘连串（352524.2.0-rc3）。
  grep -a -o -E '[0-9]+\.[0-9]+\.[0-9]+-(rc|r)[0-9]+' "$RD/ksud_mgr" 2>/dev/null \
    | awk -F'[.-]' '($1+0)<=20 && ($2+0)<=30 && ($3+0)<=60 {print; exit}' | head -1
}

_extract_mgr_ksud() {
  # ★ 2026-10-20：uapi 对齐 —— 自编 ko 是 uapi5，而随包的 ksud_success 是 uapi2、
  #   ksud_resukisu 是 uapi4。supercall 结构体对不上时 su/模块安装会静默失败。
  #   做法：从用户选的那个管理器 APK 里抽 lib/arm64-v8a/libksud.so（版本天然对齐）。
  _mp2=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
  # ★ 2.36：把 marker 原样喊出来，并核对「这个包真的装着」。
  #   实测事故：界面选了 SukiSU，marker 却还是上一次的 me.yuki.fina ⇒ 加载了 FinaSU 的 ko。
  if [ -n "$_mp2" ]; then
    if pm list packages 2>/dev/null | tr -d '\r' | grep -qx "package:$_mp2"; then
      echo "  [mgr] marker=$_mp2（已安装 ✓）"
    elif ls -d /data/app/*/"$_mp2"-*/ >/dev/null 2>&1; then
      echo "  [mgr] marker=$_mp2（/data/app 可见 ✓）"
    else
      echo "  [mgr] !! marker=$_mp2 但设备上找不到这个包 ⇒ 忽略，改自动识别"
      _mp2=""
    fi
  else
    echo "  [mgr] marker 为空 ⇒ 自动识别"
  fi
  # ★ 2.29：ksud_mgr 和它的来源包名一起记；换了管理器就重抽，避免拿上一代的 ksud
  #   （上一代的 supercall 字段可能对不上新 ko，症状是「su 能跑但不换域」）。
  if [ -x "$RD/ksud_mgr" ]; then
    _old_pkg=$(tr -d ' \r\n' < "$RD/ksud_mgr.pkg" 2>/dev/null)
    # ★ 2.34：`-z "$_old_pkg"` 不能算「同一个」。老版本抽的 ksud_mgr 没有 .pkg 记录，
    #   管理器换了却仍被当成最新 ⇒ _mgr_ver 读到上一代 ksud（FinaSU 的 ksud 没有 -rc/-r 串）
    #   ⇒ 日志「（未知版本）」⇒ 选错 ko（实测选了 r1 的 kernelsu_sukisu.ko）。
    if [ -z "$_mp2" ] || [ "$_mp2" = "$_old_pkg" ]; then
      [ -f "$RD/ksud_src" ] || printf 'mgr' > "$RD/ksud_src" 2>/dev/null
      return 0
    fi
    echo "  [ksud] 管理器从 $_old_pkg 换成 $_mp2 ⇒ 重抽 ksud_mgr"
    rm -f "$RD/ksud_mgr"
  fi
  [ -z "$_mp2" ] && _mp2=$(cat /data/data/io.github.knowlily.m6shell/files/manager_pkg /data/data/com.dsh.ppgroot/files/manager_pkg 2>/dev/null | tr -d ' \r\n' | head -1)
  # ★ 2026-10-23（管理器接管 / 新机直用）：没指定就按已装包名自动识别。
  #   不识别的话会掉到随包 ksud（uapi4/2），配 uapi5 的 ko 时 su 与模块安装会静默失败。
  # ★★ 2.37/2.38（真机事故：界面选 SukiSU，实际加载 FinaSU）★★
  #   原来是 `[ -z "$_mp2" ] || ! pm list packages | grep -qx ...`——本函数跑在
  #   u:r:kernel:s0，pm 一律空返回 ⇒ marker 明明写着 com.sukisu.ultra 也被判成"无效"
  #   ⇒ 自动识别（_mgr_list 第一位就是 me.yuki.fina）⇒ 还把 marker 覆盖回去。
  #   ⇒ marker 非空就无条件相信，只在空的时候才自动识别。
  if [ -z "$_mp2" ]; then
    _auto2=$(_detect_mgr_pkg)
    if [ -n "$_auto2" ]; then
      echo "  [ksud] 未指定管理器 ⇒ 自动识别到 $_auto2"
      _mp2=$_auto2
    fi
  fi
  [ -z "$_mp2" ] && { echo "  [ksud] 没有可用管理器 ⇒ 跳过管理器 ksud（将用随包 ksud，可能 uapi 不匹配）"; return 1; }
  _persist_mgr_pkg "$_mp2"
  _apk=$(pm path "$_mp2" 2>/dev/null | sed -n 's/^package://p' | head -1)
  [ -z "$_apk" ] && _apk=$(cmd package path "$_mp2" 2>/dev/null | sed -n 's/^package://p' | head -1)
  # ★ 2026-10-24：pm/cmd 在 boot 早期常被 system_server 忙挂（实测 12:12 就取不到 me.yuki.fina，
  #   而 adb 手工 pm path 立刻有结果）⇒ 补 dumpsys codePath 兜底
  [ -z "$_apk" ] && _apk=$(dumpsys package "$_mp2" 2>/dev/null | sed -n 's/^ *codePath=//p' | head -1)
  # ★★ 2.18（用户实测：清空 /data/local/tmp/route/m6 后 su 就没实权）★★
  #   上面三路全都依赖 PackageManager，而本函数跑在 exploit 之后的 u:r:kernel:s0 域，
  #   pm / cmd / dumpsys 一律空返回 ⇒ 抽不到 ksud_mgr ⇒ 退回随包的 ksud_resukisu(uapi4)
  #   / ksud_success(uapi2) ⇒ 重定向还在、supercall 字段错位 ⇒ su 能跑但**拿不到真权**。
  #   平时看不出来，只因为 RD 里留着上一次成功抽出来的 ksud_mgr；一清目录就暴露。
  #   ⇒ 兜底用 /data/app 目录 glob（目录名就是包名，不经过 PMS）。
  if [ ! -f "$_apk" ]; then
    _apk=$(ls -d /data/app/*/"$_mp2"-*/base.apk 2>/dev/null | head -1)
    [ -n "$_apk" ] && echo "  [ksud] pm 取不到 ⇒ glob 定位到 $_apk"
  fi
  [ -f "$_apk" ] || { echo "  [ksud] 取不到 $_mp2 的 APK 路径 ⇒ 用随包 ksud"; return 1; }
  mkdir -p "$RD/_kst" || return 1
  ( cd "$RD/_kst" && unzip -o "$_apk" "lib/arm64-v8a/*" >/dev/null 2>&1 )
  # ① 标准名 libksud.so（官方 / Next / BakaSU / FinaSU）
  _kpick=""
  [ -f "$RD/_kst/lib/arm64-v8a/libksud.so" ] && _kpick="$RD/_kst/lib/arm64-v8a/libksud.so"
  # ② 改名的 ksud（SukiSU 把 ksud 塞成 libdhxddxovny.so 这种随机名）
  #    判据：arm64-v8a 下体积最大（>2MB）且 ELF magic 对得上
  if [ -z "$_kpick" ]; then
    for _c in $(ls -S "$RD/_kst/lib/arm64-v8a/"*.so 2>/dev/null); do
      _sz=$(wc -c < "$_c" 2>/dev/null)
      [ "${_sz:-0}" -gt 2000000 ] || continue
      _mg=$(od -An -tx1 -N4 "$_c" 2>/dev/null | tr -d ' \n')
      [ "$_mg" = "7f454c46" ] && { _kpick="$_c"; echo "  [ksud] 候选（改名）：$(basename "$_c") ${_sz}B"; break; }
    done
  fi
  if [ -n "$_kpick" ]; then
    mv -f "$_kpick" "$RD/ksud_mgr" && chmod 755 "$RD/ksud_mgr"
    echo "  [ksud] 已从 $_mp2 抽出 ksud_mgr ($(wc -c < "$RD/ksud_mgr" 2>/dev/null) B) ⇒ 与 ko 同源"
    _persist_mgr_pkg "$_mp2"
    printf '%s' "$_mp2" > "$RD/ksud_mgr.pkg" 2>/dev/null
    echo "  [ksud] 来源包名=$_mp2 版本=$(_mgr_ver)"
    printf 'mgr' > "$RD/ksud_src" 2>/dev/null
  else
    echo "  [ksud] 抽取失败（该管理器可能没有 libksud.so）⇒ 用随包 ksud"
  fi
  rm -rf "$RD/_kst"
  [ -x "$RD/ksud_mgr" ]
}

_ko_is_bundled() {
  # ★ 2026-10-20（用户要求）：默认只认 APK 里打包的 ko。
  #   判断依据 = $RD/bundled_ko.md5（构建时生成，md5 + 字节数 + 文件名）。
  #   对不上 ⇒ 视为「用户自己丢进来的自备 ko」⇒ 默认跳过；要强制用就建 ALLOW_FOREIGN_KO。
  #   没有清单文件时一律放行（兼容旧包/手工部署）。
  #
  # ★ 2026-10-24 修：原来用 `cut -d' ' -f2` 取字节数，但清单里 md5 与 size 之间是
  #   8 个空格 ⇒ f2 是空串 ⇒ 每一份 ko 都被判「与清单不符」⇒ 全部跳过 ⇒ 回退到
  #   os9-selx11（uapi4）⇒ SukiSU/FinaSU 管理器报「需要更新内核」。
  #   改用 shell 内建 read 按空白切词（不依赖 awk/cut 的空格假设）。
  #
  # ★ 另一处：dc_ksu 的 ko_patch 是**就地**改 ko（symtab 写 SHN_ABS，随 KASLR 变），
  #   所以「同一份 ko 下一次启动 md5 必然不同、大小不变」。故以**字节数**为准，
  #   md5 不同只提示不拒绝，否则每次开机都会把自家 ko 当外人踢掉。
  [ -f "$RD/bundled_ko.md5" ] || return 0
  _b=$(basename "$1")
  _want_md5=""
  _want_sz=""
  while read -r _m _s _n; do
    if [ "$_n" = "$_b" ]; then _want_md5=$_m; _want_sz=$_s; break; fi
  done < "$RD/bundled_ko.md5"
  [ -z "$_want_sz" ] && return 1
  _got_sz=$(wc -c < "$1" 2>/dev/null | tr -d ' \t')
  [ "$_want_sz" != "$_got_sz" ] && return 1
  if command -v md5sum >/dev/null 2>&1; then
    _got_md5=$(md5sum "$1" 2>/dev/null | cut -d' ' -f1)
    if [ -n "$_got_md5" ] && [ "$_want_md5" != "$_got_md5" ]; then
      echo "  [ko] $_b 大小一致但 md5 不同（ko_patch 就地改过）⇒ 放行"
    fi
  fi
  return 0
}

# ★ 2026-10-23（新机直用）：管理器包名自动识别。
#   手机上没有 MANAGER_PKG 也没在 App 里选过时，靠已装包名推断该用哪份 ko ——
#   否则一律落到 kernelsu_custom.ko（BakaSU），装了官方/Next 管理器的人会 ioctl 全被拒。
# 把最终选定的管理器包名落盘：加冕(_mgr_pin)、ksud 抽取、自检三处共用同一口径
_persist_mgr_pkg() {
  [ -n "${1:-}" ] || return 0
  _cur=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
  # ★ 2.37：marker 是用户的显式选择，loader 不许拿自动识别的结果去覆盖它。
  #   只有 marker 为空时才写（写入后即可被 _mgr_ver / ko 选择复用）。
  if [ -n "$_cur" ] && [ "$_cur" != "$1" ]; then
    echo "  [mgr] marker=$_cur 是用户选择 ⇒ 不覆盖成 $1"
    return 0
  fi
  [ "$_cur" = "$1" ] && return 0
  printf '%s' "$1" > "$RD/MANAGER_PKG" 2>/dev/null && echo "  [mgr] MANAGER_PKG 落盘：$1"
  return 0
}

_detect_mgr_pkg() {
  # ★ 2.13（跟 3.16.35 对齐）：本函数在 exploit 之后的 u:r:kernel:s0 域里跑，
  #   `pm list packages` 会**直接空返回**（app_process exec 被拒），于是永远识别不到管理器
  #   ⇒ 退回 kernelsu_custom.ko（uapi5），装了 FinaSU/SukiSU 就变成「管理器说需要更新内核」。
  #   兜底用 /data/app 目录 glob：目录名就是包名，不需要 PackageManager。
  #   优先级按用户日常：FinaSU → SukiSU → 官方 → Next → BakaSU → ReSukiSU。
  _mgr_list="me.yuki.fina com.sukisu.ultra me.weishu.kernelsu kqvdie.zeykvw.hpbcyd com.bakasu.bakasu com.resukisu.resukisu com.resukisu.ksu"
  _pm=$(pm list packages 2>/dev/null | tr -d '\r' | sed 's/^package://')
  if [ -n "$_pm" ]; then
    for _c in $_mgr_list; do
      echo "$_pm" | grep -qx "$_c" && { echo "$_c"; return 0; }
    done
    return 1
  fi
  for _c in $_mgr_list; do
    if ls -d /data/app/*/"$_c"-*/ >/dev/null 2>&1 || ls -d /data/app/*/"$_c"/ >/dev/null 2>&1; then
      echo "  [mgr] pm 不可用 ⇒ 目录 glob 识别到 $_c" >&2
      echo "$_c"
      return 0
    fi
  done
  return 1
}


  # ★★ 2.19（真机：清空 /data/local/tmp/route/m6 后提权，su 没实权）★★
  #   App 把 assets 推到 RD 时是 0644，而 RD 里那些带 +x 的文件都是历史上手工 chmod
  #   留下的"遗产"。一清目录，ksud_* / load_ko / ko_patch2 全部 rc=127：
  #     "没有可执行的 ksud ⇒ 跳过加冕" / "/dev/su 无法生成"
  #   ⇒ su_path 不进 insmod 参数、sucompat 没目标 ⇒ su 能跑但拿不到真权。
  #   统一在入口把可执行文件补上 +x（幂等，失败也不影响后续）。
  for _x in ksud_mgr ksud_resukisu ksud_success ksud load_ko ko_patch2 \
            poison_trap.sh ksu_probe.sh dc_ksu_run.sh post_root.sh kmsg_dumper; do
    [ -f "$RD/$_x" ] && chmod 755 "$RD/$_x" 2>/dev/null
  done
  _bad=""
  for _x in load_ko ko_patch2 ksud_mgr ksud_resukisu; do
    [ -f "$RD/$_x" ] && [ ! -x "$RD/$_x" ] && _bad="$_bad $_x"
  done
  [ -n "$_bad" ] && echo "!! 仍不可执行:$_bad（su/装载会受影响）"

  # ★★ 2.38：管理器 ksud 必须在**所有决策之前**解析好 ★★
  #   实测 20:21 那轮：su 段落拿到的是上一代的 ksud_mgr（FinaSU，7,452,064 B），
  #   而真正的重抽发生在 ko 选择之后 ⇒ _mgr_ver 读到空 ⇒ 选了 r1 的 kernelsu_sukisu.ko，
  #   /dev/su 也铺成了 FinaSU 的 ksud ⇒ SukiSU 管理器「有 root 但检测不到自己的内核」。
  echo "=== 早期解析管理器（su / ko 决策之前）==="
  _extract_mgr_ksud || true
  echo "  [mgr-early] ksud_mgr=$(wc -c < "$RD/ksud_mgr" 2>/dev/null || echo 0)B 版本=$(_mgr_ver)"

  # ★★★ 2.21（真机：提权成功 → 内核 panic → 重启后 pstore 只有 root 能读）★★★
  #   /sys/fs/pstore/console-ramoops-0 里躺着上一个 boot 的 panic 现场，
  #   但 App/adb shell 都读不到（0400 root）。exploit 拿到 root 之后、**装载 ko 之前**
  #   是唯一能安全采集的窗口，所以放在最前面，采完顺手把尾部打到日志里。
  #   想只采集不装载（怕再 panic）：touch $RD/HARVEST_ONLY
  _PS=$RD/pstore_prev
  mkdir -p "$_PS" 2>/dev/null
  for _f in /sys/fs/pstore/*; do
    [ -f "$_f" ] || continue
    cp -f "$_f" "$_PS/$(basename "$_f")" 2>/dev/null
  done
  for _f in /data/system/dropbox/*LAST_KMSG* /data/system/dropbox/*SYSTEM_BOOT* \
            /data/system/dropbox/*SYSTEM_TOMBSTONE* /data/system/dropbox/*SYSTEM_RESTART*; do
    [ -f "$_f" ] || continue
    cp -f "$_f" "$_PS/dropbox_$(basename "$_f")" 2>/dev/null
  done
  # 上一轮自己抓的 dmesg 快照（root 0640，shell 读不到）
  for _f in "$RD/ksu_dmesg_snapshot.txt" "$RD/kmsg_cap.txt"; do
    [ -f "$_f" ] && cp -f "$_f" "$_PS/$(basename "$_f")" 2>/dev/null
  done
  # ★ 2.22：把「当前 boot 的真实符号地址」也存下来 —— 用来验 next_sym_addr_uapi5.txt
  #   里的 271 条地址是否还跟本机内核对得上（对不上 ⇒ ko_patch2 把 240 个符号
  #   patch 到错误地址 ⇒ 装载后所有 execve 直接 SIGSEGV ⇒ 之后内核被踩烂 panic）。
  #   shell 读到的是全 0（kptr_restrict），只有 root 这一下能拿到真地址，所以存文件。
  cat /proc/kallsyms > "$_PS/kallsyms_now.txt" 2>/dev/null
  [ -s "$_PS/kallsyms_now.txt" ] || echo "[harvest] kallsyms 读不到"
  dmesg 2>/dev/null > "$_PS/dmesg_now.txt"
  cp -f "$RD/next_sym_addr_uapi5.txt" "$_PS/" 2>/dev/null
  chmod 755 "$_PS" 2>/dev/null
  chmod 644 "$_PS"/* 2>/dev/null
  _pn=$(ls -1 "$_PS" 2>/dev/null | wc -l)
  echo "=== pstore 采集: ${_pn:-0} 个文件 → $_PS"
  ls -l "$_PS" 2>/dev/null | head -8
  if [ "${_pn:-0}" -gt 0 ]; then
    for _f in "$_PS"/*ramoops* "$_PS"/dropbox_*LAST_KMSG*; do
      [ -f "$_f" ] || continue
      echo "--- tail 4000B of $(basename "$_f") ---"
      tail -c 4000 "$_f" 2>/dev/null | tr -d '\000' | tail -30
      echo "--- end $(basename "$_f") ---"
    done
  fi
  # ★★ 2.23：内核日志落盘（KMSG_TAP）★★
  #   这台机器 /sys/fs/pstore 是空的、dropbox 不收 LAST_KMSG、logcat -b kernel 是加密的(HKS)，
  #   所以在 panic 之后**拿不到任何内核现场**。唯一可行：装载前起一个把 /dev/kmsg
  #   持续 dd 到文件的进程，每块 conv=fsync（panic 时最多丢最后 4KB）。
  #   touch $RD/KMSG_TAP 开启；换 sucompat 开着跑才需要。
  # ★★ 2.50：诊断期结束 —— 不再强制，改回「marker 说了算」★★
  #   2.45 那轮证实：helper（fork 出来的子进程）也没能写日志 ⇒ 装载后失权是
  #   整个进程树的事，fork 解决不了。现在只能靠**装载前就起来的 dd 循环**去
  #   持续抓 /dev/kmsg —— 它是唯一不依赖我们进程 open/exec 的通道。
  #   抓到的就是 ko 自己的打印（syscall hooks ENABLED/DISABLED、hook_manager、
  #   init 期间任何报错），能定死「管理器为什么认不到内核」。
  #   （2.46~2.49 曾在这里无条件 touch KMSG_TAP；诊断期结束后撤回）
  if [ -f "$RD/KMSG_TAP" ] && [ ! -f "$RD/KMSG_TAP_OFF" ]; then
    pkill -f kmsg_live.txt 2>/dev/null
    : > "$RD/kmsg_live.txt"
    chmod 666 "$RD/kmsg_live.txt" 2>/dev/null
    # ★★ 2.61 KMSG_TAP 三次迭代的最终写法 ★★
    #   ① 2.46 老写法：`while :; do dd … count=1; done`
    #      → 每轮 fork+exec；insmod 后 execve 全废，循环正好在装载瞬间死掉。
    #   ② 2.60 改单进程 `dd if=/dev/kmsg of=… bs=4096 oflag=sync`
    #      → 实测只写了 31 行（18:08:15.70 ~ .91，约 200ms）就停了：dd 遇到 /dev/kmsg
    #        的短读就当成 EOF 退出，根本没有"内层循环"。而且 toybox dd 不支持
    #        oflag=sync 时那句 `if ! cmd &` 也救不回来（后台化后条件恒真）。
    #   ③ 现在：`exec cat /dev/kmsg > 文件` —— 单进程、无 re-exec、
    #      cat 对短读不退出，会一直读下去；脏页由内核回写（实测复位后文件完整保留）。
    setsid sh -c "exec cat /dev/kmsg > '$RD/kmsg_live.txt'" \
      >/dev/null 2>&1 </dev/null &
    sleep 1
    echo "=== KMSG_TAP: 已启动，写 $RD/kmsg_live.txt ($(wc -c < "$RD/kmsg_live.txt" 2>/dev/null) B)"
    ls -lZ "$RD/kmsg_live.txt" 2>/dev/null
  fi
  if [ -f "$RD/HARVEST_ONLY" ]; then
    echo "=== HARVEST_ONLY ⇒ 采集完退出，不装载 ko（避免再次 panic）==="
    echo "M6_VERDICT: HARVEST"
    exit 0
  fi

  # ★ fix-20261017（真 bug）：$RD/ksud 在 m6 包里**根本不存在** —— 本路线只有
  #   ksud_success / ksud_resukisu（shared/ksud 属于 kit 路线，RouteKit 不会推过来）。
  #   而下面 1c 步（关掉 Honor bootfail 的 do-recovery）与几处兜底都直接调 $RD/ksud
  #   ⇒ 全是 not found，ro.sys.ping_bf_dorecovery 保持 true，
  #   「提权成功后 10~60 秒自动重启」就少了一道保险。
  #   这里在任何调用之前，把 $RD/ksud 软链到真实存在的那份。
  if [ ! -x $RD/ksud ]; then
    for _k in $RD/ksud_mgr $RD/ksud_resukisu $RD/ksud_success; do
      # ★ 2.19：assets 推上来是 0644，先 chmod 再判 -x（清空 RD 后就是这批文件）
      [ -f "$_k" ] && chmod 755 "$_k" 2>/dev/null
      if [ -x "$_k" ]; then
        ln -sfn "$_k" $RD/ksud 2>/dev/null && echo "ksud alias: $RD/ksud -> $_k"
        break
      fi
    done
  fi
  [ -x $RD/ksud ] || echo "!! $RD/ksud 仍不可用 —— 1c 步的 resetprop 保险会失效"

  # ══════════════════════════════════════════════════════════════════════════
  # ★★★ fix3-20261018：收尾把 SELinux 切回严格 —— 与 kit（MagicPad3）路线对齐
  #
  #   kit 的 section 10 是 `sleep 20` 后直接 `echo 1 > /sys/fs/selinux/enforce`，
  #   并把 chcon 写成硬前提。m6 这边原来只有 `$RD/ENFORCE` 才切，默认停 Permissive。
  #   现在改成**默认切**，但补上 kit 用真实事故换来的两个前提：
  #
  #   ① /dev/su 必须打成 u:object_r:ksu_file:s0
  #      kit 2026-09-28 实测（boot 649073b4）：cp 出来的 /dev/su 继承 device 标签，
  #      Enforcing 下 untrusted_app 不允许执行 device 文件 ⇒ **所有域一起丢 su**；
  #      更糟的是 enforce 写回 0 会被拒（rc=1）、setenforce 0 返回 EINVAL ⇒ 自锁，
  #      只能重打一发 exploit。所以标签没确认好就**不切**（宁可不切，不自锁）。
  #   ② 模块没 Live 就不切（切了只会让系统更脆，收益为 0）。
  #
  #   开关：KEEP_PERMISSIVE=保持宽容（旧行为）· ENFORCE_DELAY_SEC=20 · ENFORCE_VERIFY_SEC=5
  # ══════════════════════════════════════════════════════════════════════════
  _selinux_stage_su() {
    # ★ 2026-10-24：/dev/su 想打 ksu_file 标签，必须等 ko 把 policy 装进去之后 ——
    #   而那时本进程已经没有权限了。所以只要已经有可用的 su 落点（SU_PATH_RUNTIME，
    #   通常是 apk_data_file 的 libksu_su.so）就视为铺好，否则会永远"不切严格"。
    # ★ 2.20：落点也可以是 /dev/su + apk_data_file（装载前就打好），
    #   反正 sucompat 只认路径；装载后 exec 已坏，这里补标签也补不了。
    # ★ 2.76：先看装载前的记录（装载后 stat/access 会假阴性）
    if [ "${DEV_SU_BYTES:-0}" -gt 0 ] 2>/dev/null; then
      echo "[selinux] 装载前已确认 /dev/su=${DEV_SU_BYTES}B ⇒ 视为铺好（不再用装载后的 stat 判定）"
      chcon u:object_r:ksu_file:s0 /dev/su 2>/dev/null
      return 0
    fi
    if [ "${DEV_SU_RUNTIME:-0}" = "1" ] && [ -n "$SU_PATH_RUNTIME" ]; then
      _lb=$(ls -Z "$SU_PATH_RUNTIME" 2>/dev/null | awk '{print $1}')
      echo "[selinux] su 落点=$SU_PATH_RUNTIME 标签=${_lb:-?} ⇒ 视为铺好"
      return 0
    fi
    if [ ! -s /dev/su ]; then
      _src=""
      for _c in "$RD/ksud_mgr" /data/adb/ksud "$RD/ksud_resukisu" "$RD/ksud_success" "$RD/ksud"; do
        if [ -x "$_c" ]; then _src="$_c"; break; fi
      done
      if [ -n "$_src" ]; then
        cp -f "$_src" /dev/su 2>/dev/null && chmod 755 /dev/su 2>/dev/null
        echo "[selinux] /dev/su 暂存自 $_src（$(wc -c < /dev/su 2>/dev/null || echo ?) B）"
      else
        echo "[selinux] !! 没有可用的 ksud ⇒ /dev/su 无法生成"
        return 1
      fi
    fi
    chcon u:object_r:ksu_file:s0 /dev/su 2>/dev/null
    _ctx=$(ls -Z /dev/su 2>/dev/null)
    case "$_ctx" in
      *ksu_file*) echo "[selinux] /dev/su 标签 OK: $_ctx"; return 0 ;;
      *)          echo "[selinux] !! /dev/su 标签不是 ksu_file: ${_ctx:-<读不到>}"; return 1 ;;
    esac
  }

  _selinux_finalize() {
    _live=$1
    # 内建读 /sys 的两个小工具（见下方 2.67 说明）
    _enforce_now() {
      _ev=""
      { read -r _ev < /sys/fs/selinux/enforce; } 2>/dev/null
      case "$_ev" in
        1*) echo 1 ;;
        0*) echo 0 ;;
        *)  echo "${_ev:-?}" ;;
      esac
    }
    _enforce_txt() { case "$(_enforce_now)" in 1) echo Enforcing;; 0) echo Permissive;; *) echo '?';; esac; }
    if [ -f "$RD/KEEP_PERMISSIVE" ]; then
      echo "[selinux] KEEP_PERMISSIVE ⇒ 保持 Permissive（$(_enforce_txt)）"
      return 0
    fi
    if [ "$_live" != "1" ]; then
      echo "[selinux] 模块未 Live ⇒ 不切严格（保持 $(_enforce_txt)）"
      return 0
    fi
    if ! _selinux_stage_su; then
      echo "[selinux] ⇒ 为防自锁，**本次不切严格**。补好 /dev/su 标签再跑（或 touch $RD/KEEP_PERMISSIVE 明确保持宽容）"
      return 1
    fi
    echo "[selinux] ${ENFORCE_DELAY_SEC:-20}s 后切 Enforcing（先让系统稳住，kit 同款）"
    sleep "${ENFORCE_DELAY_SEC:-20}"
    _stage enforce_write
    echo 1 > /sys/fs/selinux/enforce 2>/dev/null
    # ★ 2026-10-19 修：原来用 `while read ... break` 读 /sys/fs/selinux/enforce，
    #   该文件**没有结尾换行** ⇒ read 返非零 ⇒ 循环体一次都不进 ⇒ 日志永远 `readback=?`，
    #   看着像"没切成功"（真机两轮都被误导，实际 getenforce 一直是 Enforcing）。
    #   改成 getenforce 优先、cat 兜底。
    # ★ 2.67：这一段跑在装载**之后**，外部命令（getenforce/cat/tr）随时可能执行不了
    #   （syscall 钩子打断 exec ⇒ rc=127，甚至卡住）。改成纯内建读 /sys，不再 fork/exec。
    _v1=$(_enforce_now)
    echo "[selinux] 写入后 readback=${_v1:-?}（$(_enforce_txt)）"
    sleep "${ENFORCE_VERIFY_SEC:-5}"
    _stage enforce_verify
    _v2=$(_enforce_now)
    echo "[selinux] ${ENFORCE_VERIFY_SEC:-5}s 后 re-read=${_v2:-?}（$(_enforce_txt)）"
    case "$_v2" in
      1) echo "[selinux] ✓ SELinux 已切回严格（与 kit 路线一致，$(_enforce_txt)）"
    _probe_exec "切 Enforcing 后" ;;
      *) echo "[selinux] !! 没站住（$_v2）—— 若 dmesg 有 'SELinux enforcing disabled (kernel-side)'，就是 ko 自己按回去了" ;;
    esac
  }

  # ══════════════════════════════════════════════════════════════════════════
  # ★★★ fix5-20261018：管理器自愈（BVL rootshell 的副作用）
  #
  #   ko 的 `ksu_bvl_rootshell` 每 3 秒把 init_cred 发给「shells + granted apps」
  #   ⇒ 已授权 App（管理器自己也在里面）的进程会以 **uid 0** 写自己的数据；
  #     于是 /data/data/<mgr>/files/datastore/app_preferences.preferences_pb
  #     变成 root:root 600 ⇒ 管理器下次以 10511 启动、120ms 内读它 → EACCES
  #     → 闪退（真机实证，见 patches.md 附 4）。
  #
  #   这里做的：把「已被加冕的管理器」的数据目录按回它自己的 uid，并挂一个
  #   1 秒一次的守护（只在属主变了才 chown，不是无脑 -R 刷盘）。
  #   关掉：touch $RD/NO_MGR_SELFHEAL
  # ══════════════════════════════════════════════════════════════════════════
  # ★ 2026-10-19：新机首装时 appid 一定是 4294967295（内核默认「无管理器」），
  #   而管理器的「越狱模式」靠 allowlist + 自己装的 ksu fd 也能跑 ⇒ 表面一切正常，
  #   但内核侧「谁是管理器」始终空着，后果：
  #     · _mgr_selfheal 直接跳过 ⇒ datastore 属主被 rootshell 写成 root 也没人救 ⇒ 管理器闪退
  #     · 管理器做模块安装/内核状态变更时，走 manager-only 的 ioctl 会被拒
  #   这里在 uid=0 下自动补一次，可用 marker 关掉：
  #     touch $RD/NO_MGR_CROWN
  _mgr_crown() {
    [ -f "$RD/NO_MGR_CROWN" ] && { echo "[mgr] NO_MGR_CROWN ⇒ 不加冕"; return 0; }
    # 动态管理器：加冕由内核按签名完成（track_throne），手工 set-manager 反而会把
    # appid 钉在某个固定包名上，之后换成改名/改签名的管理器就不认了。
    if [ -f "$RD/DYNAMIC_MGR" ]; then
      echo "[mgr] DYNAMIC_MGR ⇒ 跳过手工加冕（交给内核按签名 track_throne）"
      return 0
    fi
    _kc=""
    # 2026-10-20：优先用与 ko 同版本的管理器 ksud（uapi 对齐），其次才是随包的两个
    for _k in "$RD/ksud_mgr" "$RD/ksud_resukisu" "$RD/ksud_success" /data/adb/ksud; do
      if [ -x "$_k" ]; then _kc=$_k; break; fi
    done
    if [ -z "$_kc" ]; then echo "[mgr] 没有可执行的 ksud ⇒ 跳过加冕"; return 0; fi
    # 2026-10-20 修：原来顺序固定把 com.resukisu.resukisu 排第一 —— 用户选的若是官方
    #   me.weishu.kernelsu / Next，加冕就会落到另一个管理器上（真机现象：管理器"没加冕"）。
    #   现在把「选 ko 时用的那个管理器」排第一。
    _pref=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
    [ -z "$_pref" ] && _pref=$(cat /data/data/io.github.knowlily.m6shell/files/manager_pkg /data/data/com.dsh.ppgroot/files/manager_pkg 2>/dev/null | tr -d ' \r\n' | head -1)
    for _pkg in ${_pref:+$_pref }com.resukisu.resukisu me.weishu.kernelsu com.bakasu.bakasu com.resukisu.ksu kqvdie.zeykvw.hpbcyd com.sukisu.ultra me.yuki.fina; do
      if grep -q "^$_pkg " /data/system/packages.list 2>/dev/null; then
        echo "[mgr] 自动加冕：$_pkg（ksud=$(basename $_kc)）"
        # ★★ 2.51（吸收 MagicRoot 1.0.3）★★
        #   ① set-manager 的参数是 **APK 路径**，不是包名 —— 官方 ksud 会去读这个 APK
        #      算签名，传包名它找不到文件，静默失败（我们之前一直传包名）。
        #   ② 再补一条 packages.list 重命名触发：内核的 track_throne 靠 inotify/文件名
        #      变更来重新扫描，光 chmod 不触发。失败要能恢复，不然系统包管理会崩。
        #   ③ 最后兜底写 /data/adb/ksu/.dynamic_manager（KernelSU 的稳定文件格式）。
        _apk=$(ls -d /data/app/*/"$_pkg"-*/base.apk 2>/dev/null | head -1)
        [ -n "$_apk" ] || _apk=$(ls -d /data/app/*/"$_pkg"*/base.apk 2>/dev/null | head -1)
        if [ -n "$_apk" ]; then
          echo "  [mgr] set-manager 用 APK 路径：$_apk"
          "$_kc" debug set-manager "$_apk" 2>&1 | sed 's/^/  /'
        else
          "$_kc" debug set-manager "$_pkg" 2>&1 | sed 's/^/  /'
        fi
        # packages.list 改名触发（先 chmod，再原子换名再换回）
        if [ -f /data/system/packages.list ]; then
          chmod 644 /data/system/packages.list 2>/dev/null
          if mv /data/system/packages.list /data/system/packages.list.m6 2>/dev/null; then
            if ! mv /data/system/packages.list.m6 /data/system/packages.list 2>/dev/null; then
              cp -f /data/system/packages.list.m6 /data/system/packages.list 2>/dev/null
              echo "  [mgr] !! packages.list 回名失败，已 cp 兜底"
            else
              echo "  [mgr] packages.list 已触发重扫（改名→改回）"
            fi
          else
            echo "  [mgr] packages.list 改名失败（SELinux/只读）⇒ 跳过触发"
          fi
        fi
        # 兜底：直接写动态管理器记录
        if [ -d /data/adb/ksu ]; then
          printf '%s' "$_pkg" > /data/adb/ksu/.dynamic_manager 2>/dev/null && \
            chmod 644 /data/adb/ksu/.dynamic_manager 2>/dev/null && \
            echo "  [mgr] 已写 /data/adb/ksu/.dynamic_manager=$_pkg"
        fi
        return 0
      fi
    done
    echo "[mgr] packages.list 里没有已知的管理器包 ⇒ 跳过加冕"
  }

  # 用户选中的管理器包名（MANAGER_PKG 优先，其次 App 自己写的 manager_pkg）
  _mgr_pref() {
    _pf=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
    [ -n "$_pf" ] || _pf=$(cat /data/data/io.github.knowlily.m6shell/files/manager_pkg /data/data/com.dsh.ppgroot/files/manager_pkg 2>/dev/null | tr -d ' \r\n' | head -1)
    printf '%s' "$_pf"
  }

  _mgr_pin() {
    # ★ 动态管理器模式（BakaSU / SukiSU 的「动态管理器」）：
    #   内核按**签名**认管理器（KSU_SIGNATURE_INDEX_DYNAMIC_MANAGER=255），
    #   包名可以是任意伪装名。这时把 mgr_pkgs 收紧成单包名会把动态管理器挡在外面。
    if [ -f "$RD/DYNAMIC_MGR" ]; then
      echo "[mgr] DYNAMIC_MGR ⇒ 不收紧 mgr_pkgs（让内核按签名认管理器）"
      return 0
    fi
    _pk=$(_mgr_pref)
    [ -n "$_pk" ] || return 0
    _pp=/sys/module/kernelsu/parameters/mgr_pkgs
    [ -f "$_pp" ] || return 0
    if [ "$(cat "$_pp" 2>/dev/null)" = "$_pk" ]; then
      echo "[mgr] mgr_pkgs 已是单包名：$_pk"
      return 0
    fi
    if printf '%s' "$_pk" > "$_pp" 2>/dev/null; then
      echo "[mgr] mgr_pkgs 收紧为单包名：$_pk（防加冕到别的管理器）"
    else
      echo "[mgr] mgr_pkgs 写入失败（只读？）—— 若加冕错人，见 docs/progress_20261022.md §10"
    fi
  }

  # 运行时切换步骤②开关。模块参数是 0644，可以直接写 sysfs —— 不用卸载模块
  # （这台机器 ksud unload 必 panic，所以只能这么改）。
  # ★ 2026-10-23：调试旋钮必须独立成一个函数。原先塞在 _su_cred_apply 末尾，
  #   而那里在「su_cred 已是该值」时会提前 return 0 —— 于是参数永远写不进去
  #   （连着两轮真机都是 su_dbg=0）。挪到最前面单独调用，跟 su_cred 的取值无关。
  _su_dbg_apply() {
    if [ -f "$RD/SU_CHECK_DBG" ]; then
      _du=$(cat "$RD/SU_CHECK_DBG" 2>/dev/null | tr -dc '0-9')
      [ -z "$_du" ] && _du=0
      _pd=/sys/module/kernelsu/parameters/su_dbg_uid
      if [ -f "$_pd" ]; then
        printf '%s' "$_du" > "$_pd" 2>/dev/null
        printf '1' > /sys/module/kernelsu/parameters/su_dbg 2>/dev/null
        echo "[su] 调试开：su_dbg=1 su_dbg_uid=$_du（会刷 access/stat 日志）"
      else
        echo "[su] 本 ko 没有 su_dbg 参数（旧 ko）⇒ 调试旋钮跳过"
      fi
    else
      [ -f /sys/module/kernelsu/parameters/su_dbg ] && printf '0' > /sys/module/kernelsu/parameters/su_dbg 2>/dev/null
    fi
  }

  # ★ 2026-10-23（新机直用）：一眼可读的自检块。
  #   换一台同型号手机时，先看这一段就知道卡在哪：内核对不对、管理器认没认到、
  #   su 参数是不是 2、SELinux 是不是 Enforcing。
  _fresh_selfcheck() {
    echo "=== selfcheck ==="
    echo "  内核      : $(uname -r 2>/dev/null)"
    _ko_now=$(grep -o 'kernelsu_[a-z0-9_]*\.ko' <<EOF 2>/dev/null
$CUSTOM_KO
EOF
)
    [ -n "$_ko_now" ] && echo "  ko        : $_ko_now" || echo "  ko        : (未记录)"
    _mp=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
    [ -z "$_mp" ] && _mp=$(cat /data/data/io.github.knowlily.m6shell/files/manager_pkg /data/data/com.dsh.ppgroot/files/manager_pkg 2>/dev/null | tr -d ' \r\n' | head -1)
    [ -z "$_mp" ] && _mp=$(_detect_mgr_pkg 2>/dev/null)
    if [ -n "$_mp" ]; then
      _muid=$(stat -c %u /data/data/$_mp 2>/dev/null)
      if [ -n "$_muid" ]; then
        echo "  管理器    : $_mp (uid=$_muid)"
      else
        echo "  管理器    : $_mp（未安装/取不到 uid）"
      fi
    else
      # pm 在 root+kernel 域里可能调不动（binder 被拒），此时不能断言"没装"
      echo "  管理器    : 未读到（pm 不可用？）—— 不影响已加的冕 su_mgr_appid=$(cat /sys/module/kernelsu/parameters/su_mgr_appid 2>/dev/null)"
    fi
    for _sp in su_cred su_dbg su_check; do
      [ -f /sys/module/kernelsu/parameters/$_sp ] && \
        echo "  $_sp$(printf '%*s' $((10-${#_sp})) '') : $(cat /sys/module/kernelsu/parameters/$_sp 2>/dev/null)"
    done
    echo "  SELinux   : $(getenforce 2>/dev/null)"
    # ★ 2026-10-23：su 的落点文件在 App 的安装目录里 —— 装新 APK 会换目录、文件消失，
    #   表现就是"能重定向但拿不到 root"。这里直接点出来，别让人去猜。
    _sp=$(cat /sys/module/kernelsu/parameters/su_path 2>/dev/null)
    if [ -n "$_sp" ]; then
      if [ -f "$_sp" ]; then
        echo "  su 落点   : OK ($(basename "$_sp"))"
      else
        echo "  su 落点   : ✗ 文件不存在 ⇒ 装过新 APK，需要重新越狱一次"
      fi
    fi
    if [ -f /data/adb/ksud ]; then
      _ks_src=$(cat "$RD/ksud_src" 2>/dev/null)
      case "$_ks_src" in
        mgr) _ks_note="管理器自带（与 ko 同源）" ;;
        *)   _ks_note="⚠ 随包兜底 —— uapi 可能与 ko 不同源，模块/su 可能失败" ;;
      esac
      echo "  ksud      : $(wc -c < /data/adb/ksud 2>/dev/null) 字节  $_ks_note"
    else
      echo "  ksud      : 缺失"
    fi
    echo "=== selfcheck end ==="
  }

  _su_cred_apply() {
    _su_dbg_apply
    _p=/sys/module/kernelsu/parameters/su_cred
    [ -f "$_p" ] || { echo "[su] 读不到 su_cred 参数（装载后本进程无权限，或 ko 太旧）⇒ 跳过"; return 0; }
    # 2026-10-23：默认改为 2（task_work + escape_with_root_profile 换 SELinux 域）。
    # 真机验证：13 次 escape rc=0、零 panic、context=u:r:ksu:s0。
    # 用 1 的话只换 uid 不换域，连 0644 的 sysfs 参数都写不进去（"半个 root"）。
    if [ -f "$RD/NO_SUCRED" ]; then
      _v=0
    elif [ -f "$RD/SU_CRED_PLAIN" ]; then
      _v=1
    else
      _v=2
    fi
    _cur=$(cat "$_p" 2>/dev/null)
    if [ "$_cur" = "$_v" ]; then echo "[su] su_cred=$_v（已是该值）"; return 0; fi
    if printf '%s' "$_v" > "$_p" 2>/dev/null; then
      echo "[su] 运行时设置 su_cred=$_v（免重载模块）"
    else
      echo "[su] su_cred 写入失败 —— 本轮仍按模块加载时的值跑"
    fi
    _su_dbg_apply
  }

  _mgr_selfheal() {
    [ "$1" = "1" ] || return 0
    [ -f "$RD/DYNAMIC_MGR" ] && { echo "[mgr] DYNAMIC_MGR ⇒ 跳过 mgr_pkgs 收紧/自愈"; return 0; }
    [ -f "$RD/NO_MGR_SELFHEAL" ] && { echo "[mgr] NO_MGR_SELFHEAL ⇒ 跳过自愈"; return 0; }
    # ★ 2026-10-22：把 mgr_pkgs 收紧成"只有用户选的那一个包名"。
    #   现有 ko 的 crown_manager 是"任意匹配 + packages.list 字母序"，设备上同时装
    #   com.resukisu.resukisu(10512) 与 me.weishu.kernelsu(11207) 时会加冕到前者，
    #   真管理器所有 ioctl 被 permission denied（现象：添加超级用户时报
    #   "更新 app profile 失败"，kmsg 里是 cmd=0x40004b0c permission denied）。
    #   收紧成单包名后，无论 ko 是哪个版本都只会加冕对的那个。
    _mgr_pin
    _ma=""
    while IFS= read -r _l; do _ma=$_l; break; done < /sys/module/kernelsu/parameters/ksu_debug_manager_appid 2>/dev/null
    case "$_ma" in ''|*[!0-9]*) _ma=0 ;; esac
    if [ "${_ma:-0}" = "0" ] || [ "${_ma:-0}" = "4294967295" ]; then
      echo "[mgr] 内核侧没有管理器（appid='$_ma'）⇒ 尝试自动加冕"
      _mgr_crown
      _ma=""
      while IFS= read -r _l; do _ma=$_l; break; done < /sys/module/kernelsu/parameters/ksu_debug_manager_appid 2>/dev/null
      case "$_ma" in ''|*[!0-9]*) _ma=0 ;; esac
      if [ "${_ma:-0}" = "0" ] || [ "${_ma:-0}" = "4294967295" ]; then
        echo "[mgr] 自动加冕未生效（appid='$_ma'）⇒ 跳过自愈；手动：/dev/su debug set-manager <包名>"
        return 0
      fi
      echo "[mgr] 加冕成功：appid=$_ma"
    fi
    if [ "$_ma" -lt 10000 ] 2>/dev/null; then echo "[mgr] appid=$_ma 不是 App ⇒ 跳过自愈"; return 0; fi
    _mp=""
    while read -r _p _u _r; do
      if [ "$_u" = "$_ma" ]; then _mp=$_p; break; fi
    done < /data/system/packages.list
    if [ -z "$_mp" ]; then
      echo "[mgr] uid=$_ma 在 packages.list 里找不到包名（管理器被卸载/换签名？）⇒ 尝试重加冕"
      _mgr_crown
      _ma=""; while IFS= read -r _l; do _ma=$_l; break; done < /sys/module/kernelsu/parameters/ksu_debug_manager_appid 2>/dev/null
      case "$_ma" in ''|*[!0-9]*) return 0 ;; esac
      while read -r _p _u _r; do if [ "$_u" = "$_ma" ]; then _mp=$_p; break; fi; done < /data/system/packages.list
      [ -z "$_mp" ] && { echo "[mgr] 重加冕后仍找不到包名 ⇒ 跳过自愈"; return 0; }
    fi
    _md=/data/data/$_mp
    if [ ! -d "$_md" ]; then echo "[mgr] $_md 不存在 ⇒ 跳过自愈"; return 0; fi
    chown -R "$_ma:$_ma" "$_md" 2>/dev/null
    restorecon -R "$_md" >/dev/null 2>&1
    pkill -f "ksu_mgr_heal" 2>/dev/null
    # ★ 检查点要比目录深一层：20:35 那轮 root 属主只落在
    #   files/datastore/app_preferences.preferences_pb 上，而 files 目录本身还是 App 的
    #   ⇒ 只看 $D/files 的旧守护永远不触发（真机踩过）。
    # 2026-10-21 修：守护进程继承的是 kernel 域（rootshell 换 cred 后），直接 chown 会被
    #   SELinux 拒（avc denied，scontext=u:r:kernel:s0），既修不好属主又刷爆 audit。
    #   改成通过 /dev/su 执行，落在正常 su 域；间隔也从 1s 放到 3s。
    setsid sh -c "M=ksu_mgr_heal; while :; do o1=\$(stat -c %u $_md/files/datastore/app_preferences.preferences_pb 2>/dev/null); o2=\$(stat -c %u $_md/files/datastore 2>/dev/null); o3=\$(stat -c %u $_md/files 2>/dev/null); if [ \"\$o1\" != \"$_ma\" ] || [ \"\$o2\" != \"$_ma\" ] || [ \"\$o3\" != \"$_ma\" ]; then /dev/su -c \"chown -R $_ma:$_ma $_md; restorecon -R $_md\" >/dev/null 2>&1; fi; sleep 3; done" >/dev/null 2>&1 </dev/null &
    echo "[mgr] 自愈守护已起：$_mp(uid=$_ma) —— rootshell 每 3s 会把它写回 root，这里按回来"
    _mgr_restart "$_mp"
  }

  # ★ 2026-10-22：管理器"接管"的关键不是加冕，而是 fd。
  #   ksu_install_fd() 是内核在管理器进程调用 setresuid 时塞进去的；
  #   如果管理器在模块加载前就已经在跑，它永远不会再 setresuid ⇒ 拿不到 fd ⇒
  #   界面显示核心未连接/未接管。做法：force-stop 后重开一个全新进程。
  _mgr_restart() {
    [ -n "$1" ] || return 0
    am force-stop "$1" >/dev/null 2>&1
    sleep 1
    monkey -p "$1" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 \
      || am start -n "$1/.ui.MainActivity" >/dev/null 2>&1 \
      || cmd activity start-activity -n "$1/.ui.MainActivity" >/dev/null 2>&1 \
      || true
    sleep 2
    if pidof "$1" >/dev/null 2>&1; then
      echo "[mgr] 已重启 $1（新进程 setresuid 后内核才会注入 fd）"
    else
      echo "[mgr] 重启 $1 失败 —— 手动打开一次管理器，它就会接管"
    fi
  }


  # ★ 十三改（审计修复）：**uid=0 前置断言**。
  #   为什么：审计发现原脚本没有任何 uid=0 前置检查，而
  #     · L38-40 kptr 写失败只剩一行 echo
  #     · L291-297 于是从 kallsyms 拿到全零地址，却**按长度 16 判为有效**
  #       ⇒ bootid_ctl 被拼成 0000000000006070、bootid_buf 被拼成全零，当合法参数传给内核
  #     · 同套件的 post_root.sh:8-13 自己写着「非 uid0（miss 轮 loader 以 shell 跑到这里）」
  #       ⇒ 说明"以 shell 身份跑到这里"是**被观测到的真实形态**
  #   ⇒ 这里直接早退，避免污染内核状态后才失败。
  if [ "$(id -u 2>/dev/null)" != "0" ]; then
    echo "!! NOT ROOT (uid=$(id -u 2>/dev/null)) —— loader 必须以 uid=0 运行"
    echo "!! 本轮的提权未成功（exploit 阶段没拿到 uid=0），直接退出，不改任何内核状态。"
    echo "=== final ==="
    getenforce 2>/dev/null
    exit 9
  fi
  echo "uid=0 前置断言通过"
  # ★ 2026-10-22：上一轮内核 panic 后重启了。pstore/ramoops 里通常还留着 panic 现场，
  #   必须在做任何别的改动之前先抄一份出来 —— 一重启模块就没了，只有 root 能读它。
  if [ -d /sys/fs/pstore ] && [ -n "$(ls -A /sys/fs/pstore 2>/dev/null)" ]; then
    mkdir -p "$RD/pstore" 2>/dev/null
    cp -f /sys/fs/pstore/* "$RD/pstore/" 2>/dev/null
    chmod -R 644 "$RD/pstore" 2>/dev/null
    echo "[pstore] 已抄出 $(ls -1 "$RD/pstore" 2>/dev/null | tr '\n' ' ')"
  else
    echo "[pstore] 空的（这次重启没留下 panic 记录，或 ramoops 未开）"
  fi
  # ★ 十八改：现在有 root 了，把管道页软配额关掉（=0）。
  #   为什么在这里设：exploit 那一步还没 root，只能诊断不能改；
  #   但本 boot 内后续任何一次需要大管道的动作（以及若 root 存活到下次尝试）
  #   都会受它影响。同时把真实值记进日志，便于复盘。
  if [ -w /proc/sys/fs/pipe-user-pages-soft ]; then
    _ps=$(cat /proc/sys/fs/pipe-user-pages-soft 2>/dev/null)
    echo 0 > /proc/sys/fs/pipe-user-pages-soft 2>/dev/null
    echo "pipe-user-pages-soft: ${_ps:-?} -> $(cat /proc/sys/fs/pipe-user-pages-soft 2>/dev/null)（0=关闭软限制）"
  fi
  if [ -w /proc/sys/fs/pipe-user-pages-hard ]; then
    echo 0 > /proc/sys/fs/pipe-user-pages-hard 2>/dev/null
    echo "pipe-user-pages-hard 也设为 0（关闭硬限制）"
  fi
  # ★ 十五改（审计修复）：**每轮开头清掉上一轮的 ksu_load_ok**。
  #   为什么必须清：它跨 boot 保留在 /data/local/tmp/route/m6/。
  #   若不清，任一次加载成功后，**之后每一轮（含完全失败的轮次）**
  #   都会走进"写 ksu_success_stamp.txt"那段，而 stamp 里写的是**本轮** boot_id
  #   ⇒ App 判据 `led.equals(cur)` 成立 ⇒ 把失败轮报成「没复位 ★ 真成功」。
  rm -f $RD/ksu_load_ok $RD/ksu_success_stamp.txt 2>/dev/null
  echo "已清上一轮的 ksu_load_ok / ksu_success_stamp.txt（避免幽灵成功）"

  # ---- 1. kptr_restrict: /proc/kallsyms must show REAL addresses, because
  #         load_ko resolves the .ko's SHN_UNDEF symbols from it (that is how
  #         non-exported symbols like avc_has_perm get bound).
  KR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
  echo "kptr_restrict was=$KR"
  echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "kptr write FAILED"

  # ---- 1b. SURVIVAL LEVERS - keep the jailbreak alive across the crash that
  #          follows a load.
  # Device-verified chain (2026-09-19): KSU loads -> 10-60s later a framework
  # restart happens -> zygote crashes INSIDE Honor's own libheif.so static
  # constructor (linker dlsym deref of a kernel-looking address) -> Honor's
  # bootfail logic sees "Critical Process: zygote Crashed"
  # (BOOTERRORNO 0x50000003, kmsg tag proc_upper_bf) -> try_to_recovery ->
  # whole-device reboot, which throws the loaded module away.
  #
  # ro.sys.ping_bf_dorecovery is the property gating that recovery (default
  # "true"). It is an ro.* property, so property_service refuses writes - use
  # `resetprop -n` (force direct property-area mmap), which KSU's ksud ships.
  # ★ 2026-10-15 修：这里原来用 $KSUD，而 KSUD 要到第 363 行才赋值
  #   ⇒ 展开成裸 resetprop（rc=127）⇒ Honor 的 bootfail do-recovery 开关永远关不掉，
  #   第 1c 步本该防住的重启就一直armed。改用 $RD/ksud（与 kit:54 的写法一致）。
  echo "bootfail switch before: $($RD/ksud resetprop ro.sys.ping_bf_dorecovery 2>&1)"
  $RD/ksud resetprop -n ro.sys.ping_bf_dorecovery false 2>&1
  echo "bootfail switch after : $($RD/ksud resetprop ro.sys.ping_bf_dorecovery 2>&1)"

  # Insurance, so a blocked task or a wedged subsystem cannot panic the kernel
  # out from under us while we work:
  # ★★ 2.51 吸收 PPG 5.0.7：直接关 Honor 两个看门狗模块参数 ★★
  #   PPG 原作者注：「否则模块装上后 30~60s 会被整机复位（软重启也扛不住）」。
  #   我们此前只在 resetprop 层关 ro.sys.ping_bf_dorecovery，管不到 core_hang_detect
  #   这条（内核线程挂住 → 直接 panic）。两条都写 0，日志留证。
  #   ★ 2.57 实测路径修正 ★
  #   /sys/module/core_hang_detect/parameters/enable 是 **0444 只读**，写它必然失败
  #   （不是 SELinux，是 DAC）。真正可写的是设备节点：
  #     /sys/devices/system/cpu/hang_detect_core/{enable,threshold,pmu_event_sel}  0644 root
  #   本机现值：enable=1  threshold=0xb0101d  pmu_event_sel=0x0
  #   它是高通 MSM Core Hang Detect：PMU 计数器不涨 → 通过 qcom-scm 直接复位平台，
  #   **不经过 panic**，所以 oops/pstore/ramoops 全空 —— 与我们此前"黑屏重启没日志"吻合。
  _wd_off=""
  for _w in /sys/module/bootfail/parameters/boot_detector_enabled \
            /sys/devices/system/cpu/hang_detect_core/enable; do
    if [ -e "$_w" ]; then
      _before=$(cat "$_w" 2>/dev/null | tr -d '\n')
      if echo 0 > "$_w" 2>/dev/null; then
        _after=$(cat "$_w" 2>/dev/null | tr -d '\n')
        echo "  [wd] watchdog_off=$_w（原值 $_before → 现值 $_after）"
        _wd_off="$_wd_off $_w=$_after"
      else
        echo "  [wd] watchdog_write_fail=$_w（原值 $_before；权限 $(ls -l "$_w" 2>/dev/null | cut -c1-10)）"
      fi
    else
      echo "  [wd] 无 $_w（本内核没有这个开关）"
    fi
  done
  # 只读参数单独列出来报个现状（不写，写了也是 EACCES）
  for _r in /sys/module/core_hang_detect/parameters/enable; do
    [ -e "$_r" ] && echo "  [wd] 只读参数 $_r=$(cat "$_r" 2>/dev/null || echo '?')（要改走 hang_detect_core/enable）"
  done
  if [ -w /proc/sys/kernel/hung_task_panic ]; then
    echo 0 > /proc/sys/kernel/hung_task_panic 2>/dev/null && echo "hung_task_panic=0 (was 1)"
  fi
  if [ -w /proc/sys/kernel/sysrq ]; then
    echo 1 > /proc/sys/kernel/sysrq 2>/dev/null && echo "sysrq=1 (was 0 - enables stack dumps)"
  fi

  # ---- 1c. TURN OFF HONOR'S BOOTFAIL DETECTOR. This is the real fix for the
  #          10-60s post-load device reset, and it is a one-word sysfs write.
  #
  # Full chain, read out of Honor's own driver source
  # (kernel_src/drivers/bootfail, present in this workspace):
  #   init sees its child go down and reports it:
  #     [1:init]bootfail: bootfail_errno: 0x50000003, detail_info:
  #     Critical Process: zygote Crashed
  #   -> ioctl(PROCESS_BOOTFAIL=...) on the misc device /dev/hw_bfm ("hw_bfm")
  #   -> process_upper_bootfail -> kthread "proc_upper_bf"
  #   -> __boot_fail_error -> do_recovery
  #        select_method_for_kernel(): errno 0x50000003 is NOT in the hardware
  #        range, so method = RECOVERY_METHOD_UNKNOWN = 400999999 - exactly the
  #        "selected method: 400999999" in our kmsg captures.
  #   -> post_proc_kernel_bootfail: is_do_nothing_fault(400999999) is FALSE
  #        (boot_recovery.h:258 - only the five *_DO_NOTHING codes count), so it
  #        writes the bootfail record and calls
  #   -> qcom_reboot() (adapter_qcom.c:371) = PANIC("Critical Process: ...").
  # That is why vetoing the reboot() syscall never helped (supercall.c): the
  # reset comes from a kernel panic, not from a syscall - it only looked like a
  # PMIC hard reset (AP_S_PANIC / reason [panic] in the panic dump).
  #
  # The entry gate is a module parameter, and 0644 means we can write it
  # (bootfail_common.c:836):
  #     case PROCESS_BOOTFAIL:
  #         if (!is_boot_detector_enabled()) return -EPERM;
  # With it off, init's report is refused, no bootfail is ever processed, and
  # the device simply keeps running - KSU stays resident and root keeps working
  # even if the framework crashes. NOTE: do NOT use boot_recovery_enabled for
  # this - do_recovery() turns that state into method=KERNEL_REBOOT, which is
  # also not a do-nothing code, so it still panics.
  # Marker $RD/KEEP_BFM restores the old behaviour (A/B control for this lever).
  BFM=/sys/module/bootfail/parameters
  rm -f $RD/bfm_watch.log
  if [ -f $RD/KEEP_BFM ]; then
    echo "bootfail detector LEFT ENABLED (KEEP_BFM marker) -> expect a panic+reset"
  else
    echo "bootfail detector before: boot_detector_enabled=$(cat $BFM/boot_detector_enabled 2>&1)"
    if echo 0 > $BFM/boot_detector_enabled 2>/dev/null; then
      echo "bootfail detector DISABLED: boot_detector_enabled=$(cat $BFM/boot_detector_enabled 2>&1) (init's PROCESS_BOOTFAIL ioctl now returns -EPERM)"
    else
      echo "bootfail detector write FAILED ($BFM/boot_detector_enabled)"
    fi
    # init could in principle re-enable it through BOOT_DETECTOR_ENABLE_CTRL
    # (boot_detector_ctl), so keep it off from a detached guard and record any
    # flip: a re-enable right before the crash would explain a surviving panic.
        # ★ 2026-10-16（修刷屏）：原来**每次**重开都写一行 ⇒ 真机实测 15 分钟写了 508 行，
    #   而 App 的日志 glob `*.log` 把这个 watch 文件也当"套件日志"显示 ⇒ 界面持续重复。
    #   现在只记：首次 3 次 + 之后每 300 次一行（行为不变，只是不再刷屏）。
    # ★ 2.72：原来这条守护每秒 fork 三个外部命令（cat/echo/echo）——
    #   实测占掉**半个核**（2s 采样 495 tick ≈ 49% of one core），
    #   对 exploit 的时序影响很大（KernelSnitch 靠 CPU 计数器精度）。
    #   改成：内建 read 取值（0 fork）+ 每 5 秒一轮 + 最长跑 BFM_WATCH_MAX 轮后自退。
    #   仍然"够用"：boot_detector_enabled 被 init 改回来的窗口是开机几秒内，
    #   而模块装载本身在几十秒内完成，之后这个守护只是保险。
    #   想让它长跑：export BFM_WATCH_MAX=<轮数>（每轮 5s）。
    #   注意：单引号里的 $1/$2 由内层 shell 展开（外层传参，避免依赖 export）
    setsid sh -c 'RD="$1"; M="${2:-360}"; L="$RD/bfm_watch.log"; i=0; n=0
      while [ "$i" -lt "$M" ]; do
        i=$((i+1))
        v=""
        { read -r v < /sys/module/bootfail/parameters/boot_detector_enabled; } 2>/dev/null
        case "$v" in
          0|N|n|"") ;;
          *) n=$((n+1))
             [ "$n" -le 3 ] && echo "re-enable x$n (v=$v) -> forcing 0" >> "$L"
             : > /sys/module/bootfail/parameters/boot_detector_enabled 2>/dev/null ;;
        esac
        [ -f "$RD/BFM_WATCH_STOP" ] && break
        sleep 5
      done' _ "$RD" "${BFM_WATCH_MAX:-360}" >/dev/null 2>&1 </dev/null &
    echo "bootfail detector watchdog detached -> $RD/bfm_watch.log（每 5s 一轮，${BFM_WATCH_MAX:-360} 轮后自退）"
  fi

  # ---- 1c2. BVL-AN16-ONLY core hang detector (never mentioned in the
  # MagicPad3 write-up, so it was never in our kit until now).
  # Device-verified 2026-09-21: /sys/module/core_hang_detect/parameters/enable
  # exists (mode 0444 -> root can still write it), and the module is resident.
  # This is the first candidate that actually explains the observed failure
  # signature: a SILENT hard reset ~128s after load, with
  #   panic=-1  hung_task_panic=0  panic_on_oops=0
  # i.e. the kernel is configured to NEVER reboot on panic/oops/hung, yet the
  # device resets anyway -> the reset comes from a vendor watchdog that feeds
  # its own path, not from panic(). A "core hang detect" driver is exactly that.
  # Marker $RD/KEEP_CHD restores the old behaviour (A/B control for this lever).
  CHD=/sys/module/core_hang_detect/parameters
  if [ -d "$CHD" ]; then
    if [ -f $RD/KEEP_CHD ]; then
      echo "core_hang_detect LEFT ENABLED (KEEP_CHD marker) -> A/B control"
    else
      echo "core_hang_detect before: enable=$(cat $CHD/enable 2>&1)"
      # ★ fix2-20261017：写不进去就别起守护。run-20261017-155727 的 ksu_load.log 里
      #   6 次 `can't create .../enable: Permission denied`，而守护进程照样被拉起，
      #   之后整场都在空转（chd_watch.log 累积到 1.4 MB / 3.3 万行）。
      CHD_OK=0
      if echo 0 > $CHD/enable 2>/dev/null; then
        CHD_OK=1
        echo "core_hang_detect DISABLED: enable=$(cat $CHD/enable 2>&1)"
      else
        echo "core_hang_detect write of '0' FAILED - trying N/n/false"
        for v in 0 N n false; do
          if echo $v > $CHD/enable 2>/dev/null; then
            CHD_OK=1
            echo "core_hang_detect DISABLED with '$v': enable=$(cat $CHD/enable 2>&1)"
            break
          fi
        done
        echo "core_hang_detect after retries: enable=$(cat $CHD/enable 2>&1)"
      fi
      # same guard idea as bootfail: hold it off for the whole session
            # ★ 2026-10-16（修刷屏）：同 bootfail —— 只记首次 3 次 + 每 300 次一行
      if [ "$CHD_OK" = "1" ]; then
        setsid sh -c 'n=0; while :; do v=$(cat /sys/module/core_hang_detect/parameters/enable 2>/dev/null); case "$v" in 0|N|n|false) ;; *) n=$((n+1)); if [ $n -le 3 ] || [ $((n % 300)) -eq 0 ]; then echo "re-enable x$n (v=$v) - forcing 0 (后续静默)" >> /data/local/tmp/ksu/chd_watch.log; fi; echo 0 > /sys/module/core_hang_detect/parameters/enable 2>/dev/null;; esac; sleep 2; done' >/dev/null 2>&1 </dev/null &
        echo "core_hang_detect watchdog detached -> $RD/chd_watch.log"
      else
        echo "core_hang_detect：参数只读（0444）⇒ **不起守护**（起了也只会空转刷 chd_watch.log）"
      fi
    fi
  else
    echo "core_hang_detect: module not present (nothing to shut)"
  fi

  # ---- 1d. Hunt the fake-rb_node poison in the exploit's own address space.
  # Device-verified 2026-09-19: every fresh zygote dies with
  #   signal 11 SIGSEGV fault addr = <poison word> + 0x200
  #   pc = linker64 soinfo::get_primary_namespace()+0
  # and 16/16 zygote crashes used the SAME word, so the source is one live
  # shared page (the exploit forges struct file_operations in a memfd page and
  # overwrites ashmem_miscs.fops with it - see src/fops.c and
  # targets/cga-w00-6.1.157/target.h), not a randomly recycled one.
  # poison_hunt walks the exploit tree's writable/shared mappings looking for
  # words shaped like a kernel heap pointer with rbtree colour bits, at the
  # 0x200 stride the forged nodes use, and reports the owning VMA/file/offset.
  # Marker $RD/SCRUB_POISON additionally zeroes every hit (off by default: the
  # kernel's PI tree can still reference those nodes).
  rm -f $RD/poison_hunt.log
  if [ -x $RD/poison_hunt ]; then
# ★ 用法：adb shell touch /data/local/tmp/ksu/SCRUB_POISON   （把 poison_hunt 命中的槽位归零（清理内核残留））
    if [ -f $RD/SCRUB_POISON ]; then
      timeout 120 $RD/poison_hunt --scrub > $RD/poison_hunt.log 2>&1
      echo "poison_hunt (SCRUB_POISON): $(tail -1 $RD/poison_hunt.log 2>/dev/null)"
    else
      timeout 120 $RD/poison_hunt > $RD/poison_hunt.log 2>&1
      echo "poison_hunt: $(tail -1 $RD/poison_hunt.log 2>/dev/null)"
    fi
    grep -c 'pid=' $RD/poison_hunt.log 2>/dev/null | sed 's/^/poison_hunt hit lines: /'
  else
    echo "poison_hunt binary missing - skipping the poison hunt"
  fi

  # ---- 1e. Find the poisoned FILE itself. Reading a file goes through the page
  #          cache, so if a page cache page was corrupted by the write primitive
  #          a plain read returns the poison. Shape mode needs no prior knowledge
  #          of this boot's KASLR slide. Detached, because a full sweep of
  #          /system/lib64 takes tens of seconds and the crash window is ~100 s.
  rm -f $RD/file_hunt.log $RD/ph_all.log
  # NOTE: a blind `file_hunt --shape` sweep of /system/lib64 + /vendor/lib64 is
  # NOT useful: bare "kernel word 0xffffff80..bf" matched 1772 of 1904 files
  # (965 KB of log, all noise) because libraries legitimately contain 8-byte
  # values in that range. The value-based hunt in poison_trap.sh (step 1f) is the
  # one that works, because it uses the poison word harvested from this boot's
  # own crash. Marker $RD/SHAPE_SCAN brings the blind sweep back for reference.
  if [ -f $RD/SHAPE_SCAN ] && [ -x $RD/file_hunt ]; then
    setsid sh -c 'RD=/data/local/tmp/ksu
      { echo "file_hunt --shape start uptime=$(cut -d. -f1 /proc/uptime)"
        for d in /system/lib64 /vendor/lib64 /odm/lib64; do
          [ -d "$d" ] || continue
          echo "--- $d"
          $RD/file_hunt --shape "$d"
        done
        echo "file_hunt --shape end uptime=$(cut -d. -f1 /proc/uptime)"
      } >> $RD/file_hunt.log 2>&1' >/dev/null 2>&1 </dev/null &
    echo "blind file_hunt --shape sweep started (SHAPE_SCAN marker)"
  fi
  if [ -x $RD/poison_hunt ]; then
    setsid sh -c 'RD=/data/local/tmp/ksu; $RD/poison_hunt --all-procs >> $RD/ph_all.log 2>&1' >/dev/null 2>&1 </dev/null &
  fi

  # ---- 1f. Poison trap: wait for the first zygote SIGSEGV tombstone, harvest
  #          the poison word from its x0 (per-boot KASLR value, so it can only be
  #          read from THIS boot's crash), then search exactly the files that
  #          process had mapped. See poison_trap.sh for the reasoning.
  rm -f $RD/poison_trap.log
  if [ -f $RD/poison_trap.sh ]; then
    chmod 755 $RD/poison_trap.sh
    setsid sh $RD/poison_trap.sh >/dev/null 2>&1 </dev/null &
    echo "poison trap armed -> $RD/poison_trap.log"
  fi

  # ---- 2. Freeze Honor's anti-root daemon for the load window only.
  # ---- 2. hisecd: Honor's OWN vendor security daemon
  #         (/vendor/bin/hisecd, started by /vendor/etc/init/hisecd.rc, label
  #         u:object_r:hisecd_exec:s0) - not a Huawei leftover; Honor kept the
  #         EMUI-derived vendor security stack.
  #
  # NOT frozen by default any more. Control experiment B (2026-09-19) loaded a
  # trivial unsigned module and let hisecd do its WHOLE anti-root reaction -
  # StaticCheckPolicy risk=1, static check, "upload threat succeed name:mod-sign
  # stat:RISK" - and the device still survived 300s+. Freezing it therefore buys
  # nothing and costs a lot: a hisecd left in state T wedges Honor's periodic
  # root scan AND makes `adb reboot` a silent no-op, so only a physical power
  # cycle recovers the device (which we hit twice).
  # Marker $RD/FREEZE_HISECD restores the old freeze behaviour if ever needed.
  hp=""
  if [ -f $RD/FREEZE_HISECD ]; then
    hp=$(pidof hisecd 2>/dev/null)
    if [ -n "$hp" ]; then kill -STOP $hp && echo "hisecd FROZEN pid=$hp (FREEZE_HISECD marker)"; else echo "hisecd not running"; fi
  else
    echo "hisecd left running (harmless: its anti-root reaction does not reboot this device - control B)"
  fi
  # ALWAYS thaw on exit, in case the marker above froze it. A hisecd left in
  # state T must never outlive this script.
  trap '[ -n "$hp" ] && kill -CONT $hp 2>/dev/null; echo "hisecd thawed by EXIT trap"' 0

  # ══════════════════════════════════════════════════════════════════════════
  # ★★ 2.62：清 exploit 孤儿进程 ★★
  #   实测（2026-10-26 20:23 的 kmsg2.txt）：
  #     rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks: { 0-.... }
  #     Task dump for CPU 0:
  #     task:cve-2026-43499-  state:R running  pid:1894 ppid:1
  #   即 exploit 成功后**父进程退出、子线程被 init 收养，然后在 CPU0 上空转**，
  #   把 RCU expedited grace period 拖死 → 灭屏 suspend 时卡在冻结阶段 →
  #   PMIC 硬件看门狗掉电复位（所以 pstore 全空、没有 panic）。
  #   只读 /proc/*/comm + 内建 kill，**不 fork/exec** ⇒ 装载后（execve 全废）也能跑。
  # ══════════════════════════════════════════════════════════════════════════
  # ── 采样一遍 exploit 残留进程：stdout "pid comm cpu_ticks state" ────────────
  #   只用 /proc + 内建 read + 变量展开；不需要 fork（调用处若用 $(...) 才 fork）
  _orph_pass() {
    for _pp in /proc/[0-9]*; do
      [ -d "$_pp" ] || continue
      _pn=${_pp#/proc/}
      [ "$_pn" = "$$" ] && continue
      _pc=""
      { read -r _pc < "$_pp/comm"; } 2>/dev/null
      [ -n "$_pc" ] || continue
      case "$_pc" in
        cve-2026-43499*|cve43499*|kaslr_leak*|poison_hunt*|poison_trap*) ;;
        *) continue ;;
      esac
      _ln=""
      { read -r _ln < "$_pp/stat"; } 2>/dev/null
      [ -n "$_ln" ] || continue
      _rest=${_ln##*) }              # comm 可能含空格/括号 ⇒ 从最后一个 ") " 切
      set -- $_rest                  # $1=state … ${12}=utime ${13}=stime
      echo "$_pn $_pc $(( ${12:-0} + ${13:-0} )) $1"
    done
  }

  # ══════════════════════════════════════════════════════════════════════════
  #  ★ 2.66：按「CPU 增量」抓自旋，而不是按 state=R
  #  教训（2.65 实测）：那个 4 线程的残留进程主线程挂在 `pause()`（wchan=
  #  __arm64_sys_rt_sigsuspend），采样瞬间 state=S，但整进程 utime+stime 每秒涨
  #  ~100 tick —— 另一个线程在烧 CPU。只看 state 会漏掉它。
  #  所以：装载前采两次（间隔 1s），delta ≥ ORPHAN_CPU_DELTA(默认15 tick≈150ms/s)
  #  即判定「在烧 CPU」→ SIGSTOP（保留地址空间，钉页仍有效）。
  #  装载后 /proc 读不到（access 被打断），那几次采样退化成尽力而为。
  # ══════════════════════════════════════════════════════════════════════════
  # ── 2.72：清理旧版载荷留下的常驻守护 ──────────────────────────────────────
  #   实测（2026-10-26 23:0x）：旧版本 spawn 的 bfm_watch 循环
  #     sh -c 'while :; do v=$(cat .../boot_detector_enabled); ...; sleep 1; done'
  #   每秒 fork 3 个外部命令，2 秒采样吃掉 **495 tick ≈ 半个核**。
  #   它对 exploit 的时序是纯干扰（KernelSnitch 靠 CPU 计数器精度）。
  #   只匹配守护特征串，**不要**用 route/m6（会把 dc_ksu_run.sh 自己杀掉）。
  _reap_legacy_daemons() {
    _rl=0
    for _pp in /proc/[0-9]*; do
      [ -d "$_pp" ] || continue
      _pn=${_pp#/proc/}
      [ "$_pn" = "$$" ] && continue
      [ "$_pn" = "$PPID" ] && continue
      _cl=$(tr '\0' ' ' < "$_pp/cmdline" 2>/dev/null)
      [ -n "$_cl" ] || continue
      case "$_cl" in
        *boot_detector_enabled*|*bfm_watch*|*proc_upper_bf*)
          _cm=""
          { read -r _cm < "$_pp/comm"; } 2>/dev/null
          case "$_cm" in
            sh|ash|dash|toybox)
              kill -9 "$_pn" 2>/dev/null && { echo "  [reap] kill -9 $_pn ($_cm)"; _rl=$((_rl+1)); } ;;
          esac ;;
      esac
    done
    echo "  [reap] 旧守护清理 $_rl 个"
  }

  _sweep_orphans() {
    _diag="$1"
    _n_stop=0; _n_kill=0; _n_left=0; _n_seen=0
    _cpu_ticks="${ORPHAN_CPU_TICKS:-100}"    # 绝对阈值（仅用于非 diag 的粗判）
    _delta_min="${ORPHAN_CPU_DELTA:-15}"     # 每秒增长 tick 阈值（1 tick = 10ms）

    if [ "$_diag" = "diag" ]; then
      _s1=$(_orph_pass)
      _n_seen=$(printf '%s\n' "$_s1" | grep -c . )
      [ "$_n_seen" -gt 0 ] && sleep 1
      _s2=$(_orph_pass)
      _rows=$(printf '%s\n' "$_s2" | while read -r _p _c _c2 _st; do
                _c1=$(printf '%s\n' "$_s1" | awk -v P="$_p" '$1==P{print $3; exit}')
                echo "$_p $_c ${_c1:-0} $_c2 $_st"
              done)
      while read -r _p _c _c1 _c2 _st; do
        [ -z "$_p" ] && continue
        _delta=$(( _c2 - _c1 ))
        if [ "$_st" = "T" ] || [ "$_st" = "t" ]; then
          _n_left=$((_n_left+1)); continue
        fi
        # ★ 2.68：默认 SIGKILL。实测 2.66（默认 SIGSTOP）在灭了这个自旋进程之后，
        #   紧接着的 insmod **卡死在 module init**（loadko_result.log 停在
        #   "=== load_ko 调用（第 N 次） ==="，随后硬件看门狗复位）。
        #   推测：被 STOP 的任务仍握着内核侧的对象/锁（它的映射正是被钉住的
        #   reclaim 页），module init 去碰它 ⇒ 死等。SIGKILL 反而干净（2.62 实测能装载）。
        #   想再试验 SIGSTOP：touch $RD/ORPHAN_STOP
        if [ -f "$RD/ORPHAN_STOP" ]; then
          _sig=19; _label=SIGSTOP
        elif [ "$_delta" -ge "$_delta_min" ] || { [ "$_st" = "R" ] && [ "$_c2" -ge "$_cpu_ticks" ]; }; then
          _sig=9; _label=SIGKILL
        else
          _n_left=$((_n_left+1)); continue
        fi
        echo "  [clean] $_label $_p ($_c cpu=${_c2}t Δ=${_delta}t/s state=$_st)"
        case "$_sig" in 9) _n_kill=$((_n_kill+1));; *) _n_stop=$((_n_stop+1));; esac
        kill -s "$_sig" "$_p" 2>/dev/null || echo "  [clean] !! kill 失败 pid=$_p"
      done <<EOF
$_rows
EOF
    else
      # 装载后：/proc 基本读不到，这一轮只做「能读就读」的粗判，不 sleep
      while read -r _p _c _c2 _st; do
        [ -z "$_p" ] && continue
        case "$_st" in T|t) _n_left=$((_n_left+1)); continue ;; esac
        if [ -f "$RD/ORPHAN_STOP" ]; then _sig=19; _label=SIGSTOP
        elif [ "$_st" = "R" ] && [ "$_c2" -ge "$_cpu_ticks" ]; then _sig=9; _label=SIGKILL
        else _n_left=$((_n_left+1)); continue; fi
        echo "  [clean] $_label $_p ($_c cpu=${_c2}t state=$_st)"
        case "$_sig" in 9) _n_kill=$((_n_kill+1));; *) _n_stop=$((_n_stop+1));; esac
        kill -s "$_sig" "$_p" 2>/dev/null || echo "  [clean] !! kill 失败 pid=$_p"
      done <<EOF
$(_orph_pass)
EOF
    fi
    echo "  [clean] 本轮：停止 $_n_stop / 杀掉 $_n_kill / 留活 $_n_left（Δ阈值 ${_delta_min}t/s）"
  }

  # ── 2.71：管道页配额 —— 只有拿到 root 的这一刻才能读到真实值 ──────────────
  #   exploit 里 resize_pipe_slots 的失败行是
  #     soft-fail slots=32 want=131072 errno=1(EPERM) cur=8192
  #   反汇编确认：cur 是 **这个管道自己的 F_GETPIPE_SZ（字节）**，不是整用户用量 ——
  #   所以 cur=8192 只说明"它当时是 2 页"，不能用来推断配额。
  #   真正的判据是 fs.pipe-user-pages-soft 与 user->pipe_bufs；后者不可见，
  #   前者 0600（shell 读不到），**但现在是 root**，能读也能改。
  #   读到之后：如果值很小（< 16384）就把它设 0（内核文档：0 = 关闭软限制）。
  #   本轮 exploit 已经跑完，改它是为了「同 boot 再来一发」和排障留证据。
  echo "--- 管道页配额（root 视角）---"
  _ps_soft=""; { read -r _ps_soft < /proc/sys/fs/pipe-user-pages-soft; } 2>/dev/null
  echo "  [pipeq] pipe-user-pages-soft=${_ps_soft:-读不到}"
  case "$_ps_soft" in
    ""|0) echo "  [pipeq] 无需调整（空或 0=无软限制）" ;;
    *)
      if [ "$_ps_soft" -lt 16384 ] 2>/dev/null; then
        echo 0 > /proc/sys/fs/pipe-user-pages-soft 2>/dev/null
        _ps_new=""; { read -r _ps_new < /proc/sys/fs/pipe-user-pages-soft; } 2>/dev/null
        echo "  [pipeq] 值偏小(${_ps_soft} < 16384) ⇒ 已写 0 关闭软限制（现值=${_ps_new:-?}）"
        echo "  [pipeq] ⚠ 这解释了 exploit 的 resize_pipe_slots soft-fail errno=1"
      else
        echo "  [pipeq] 值正常(${_ps_soft} ≥ 16384) ⇒ soft-fail 另有原因（另有用量被占）"
      fi ;;
  esac

  # ---- 3. sig_enforce must already be 0 (exploit-side pipe write).
  sv=$(cat /sys/module/module/parameters/sig_enforce 2>/dev/null)
  echo "sig_enforce=$sv"
  case "$sv" in
    0|N) echo "sig_enforce clear -> unsigned module may load" ;;
    *)   echo "ABORT: sig_enforce still '$sv' (EKEYREJECTED would follow)"
         echo "$KR" > /proc/sys/kernel/kptr_restrict 2>/dev/null
         [ -n "$hp" ] && kill -CONT $hp 2>/dev/null && echo "hisecd thawed on abort"
         echo KSU_LOAD_DONE; exit 1 ;;
  esac

  # ---- 4. Snapshot the PRISTINE policy BEFORE any rule is injected: the .ko
  #         installs it as the selinux_hide backup (it cannot build one itself
  #         on this device - see selinux-hide-backup.patch).
  cat /sys/fs/selinux/policy > $RD/pristine_policy 2>/dev/null \
    && echo "pristine policy snapshot: $(wc -c < $RD/pristine_policy) bytes"

  # ---- 5. Inject the KernelSU policy through the kernel's own
  #         security_load_policy path (keeps running SIDs valid).
  $RD/magiskpolicy --apply $RD/ksu_rules --live 2>&1
  echo "magiskpolicy exit=$?"
  # ★★ 2.77：`permissive shell` 改成**显式开关**，默认不做。
  #
  #   这条是 2026-09-23 从旧 kit 带过来的 "root-every-shell" 配套：把 shell 域
  #   整域设成 permissive，宽容一直保持到本 boot 结束。后果是：
  #     · `getenforce` 仍然显示 Enforcing（全局开关没动），但 shell 域**不受策略约束**
  #     · 任何 App 只要拿到 shell 域（adb / Shizuku / 本套件的提权前 shell）就可以为所欲为
  #     · 用户看到的现象就是"selinux 没有严格"
  #
  #   我们现在的 su 通路是 /dev/su + su_cred=2（escape_with_root_profile 换到
  #   u:r:ksu:s0），**不需要** shell 域宽容；装载后的所有收尾动作都在 root 子进程
  #   （u:r:kernel:s0）里做。所以默认关掉。
  #
  #   排障需要时：touch $RD/SHELL_PERMISSIVE
  if [ -f $RD/SHELL_PERMISSIVE ]; then
    $RD/magiskpolicy --live "permissive shell" 2>&1
    echo "permissive-shell exit=$? **（SHELL_PERMISSIVE 已建 ⇒ shell 域本 boot 为 permissive）**"
  else
    echo "permissive-shell SKIPPED（默认不做；要开就 touch $RD/SHELL_PERMISSIVE）"
  fi
  ctx=$(cat /proc/self/attr/current 2>/dev/null)
  if [ -z "$ctx" ]; then
    echo "HEALTH GATE FAILED after injection (attr/current unreadable) - ABORT before module load"
    echo "$KR" > /proc/sys/kernel/kptr_restrict 2>/dev/null
    [ -n "$hp" ] && kill -CONT $hp 2>/dev/null && echo "hisecd thawed on abort"
    echo KSU_LOAD_DONE; exit 1
  fi
  echo "policy injected OK (ctx=$ctx)"

  # ---- 6. Module params.
  #         random_table and sysctl_bootid are statics, absent from ksymtab but
  #         present in kallsyms. random_table[4] (boot_id) entry sits at
  #         random_table+0x100 and struct ctl_table.data is at +8. The image
  #         offset of random_table is 0x24f5f70, so the entry's low 16 bits are
  #         always 0x6070 - no 64-bit arithmetic needed (this shell is 32-bit).
  #         Values MUST carry a 0x prefix: the params are `ulong`, parsed with
  #         kstrtoul(val, 0, ...) - a bare hex string is read as decimal and
  #         rejected with "invalid for parameter" (observed 2026-09-19 run 1).
  RT=$(grep -w random_table /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
  # 十三改（审计修复）：全零地址不是有效地址，不能靠"长度 16"过关
  case "$RT" in 0000000000000000|"") RT="";; esac
  SB=$(grep -w sysctl_bootid /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
  # ★ 十五改（审计修复）：上面只给 RT 加了全零防护，SB 漏了 —— 补齐。
  #   kallsyms 全零时 SB 仍是 16 个 '0'，会被当合法 ulong 传进内核。
  case "$SB" in 0000000000000000|"") SB="";; esac
  BP=""
  case "${#RT}" in
    16) case "$SB" in
          ????????????????) BC="${RT%????}6070"
                            BP="bootid_ctl=0x$BC bootid_buf=0x$SB"
                            echo "bootid params: random_table=$RT -> ctl=0x$BC buf=0x$SB" ;;
          *) echo "sysctl_bootid not in kallsyms - skipping bootid params (exploit already restored it)" ;;
        esac ;;
    *)  echo "random_table not in kallsyms - skipping bootid params (exploit already restored it)" ;;
  esac

  [ "$(cat /proc/sys/kernel/panic_on_oops 2>/dev/null)" = "1" ] && { echo 0 > /proc/sys/kernel/panic_on_oops 2>/dev/null; echo "panic_on_oops cleared for the load"; }

  # ---- 7. Load the module.
  #
  # Marker $RD/TEST_MOD - DECISIVE DISCRIMINATOR (2026-09-19). Loads a TRIVIAL
  # module (offset_probe.ko: one pr_info, no hooks, no KSU code) instead of
  # kernelsu.ko. If the device still hard-resets in 10-60s, the trigger is
  # Honor's reaction to ANY unsigned module load (mod-sign uevent ->
  # HISEC/kernel_stp_uploader), not KernelSU's code - which changes the whole
  # strategy (no LKM activation; KDP-style kernel data patching instead).
  if [ -f $RD/TEST_MOD ]; then
    echo "=== TEST_MOD marker: loading the trivial probe module instead of kernelsu.ko ==="
    $RD/kmsg_dumper $RD/kmsg_cap.txt &
    KMSG_PID=$!
    sleep 1
    if [ ! -f $RD/test_mod.ko ]; then
      echo "!! TEST_MOD 请求了，但 $RD/test_mod.ko 不存在 —— 终止（别把'没加载'当成阴性结果）"
      exit 1
    fi
    timeout 120 $RD/load_ko $RD/test_mod.ko "" > $RD/loadko_result.log 2>&1
    echo "load_ko_exit=$?"
    sync; sleep 1   # ★ 2026-10-16：2s→1s，崩死窗口里少等一秒
    echo "=== loadko_result.log ==="; cat $RD/loadko_result.log 2>&1
    timeout 10 grep -iE 'offset_probe|kernelsu' /proc/modules 2>/dev/null || echo "(no test module in /proc/modules)"
    echo "=== trivial module left loaded - watching for a hard reset ==="
    exit 0
  fi
  #
  # Marker $RD/NO_LOAD - DECISIVE CONTROL EXPERIMENT (2026-09-19). Every
  # successful load panics the kernel within ~30-60s and neither freezing hisecd
  # (FREEZE_HISECD_LONG) nor skipping the ksud stages (SKIP_STAGES) prevents it.
  # This marker stops the flow BEFORE init_module: if the device still panics,
  # the trigger is the exploit's own residual PI-tree damage, not our module.
  #
  # 【v4 fix 2026-09-22】post_root hook 前移：原 hook 在文件末尾（KSU_LOAD_DONE 之后），
  # NO_LOAD 在此 exit 0 永远走不到。uid0 (u:r:kernel:s0) 在 marker 之前已就绪
  # （magiskpolicy 注入完成），故在 gate 之前调用 post_root.sh。
  if [ -f $RD/post_root.sh ]; then
    echo "=== post_root.sh (custom root tasks, pre-NO_LOAD-exit) uid=$(id -u) ==="
    timeout 600 sh $RD/post_root.sh 2>&1
    echo "=== post_root.sh done rc=$? ==="
  else
    echo "(post_root.sh not present - hook idle)"
  fi
  # ★★ 2.77：NO_LOAD 现在是**双确认**才生效（必须同时有 CONTROL_OK）。
  #   事故现场：12:39 那次对照实验留下的 NO_LOAD 一直没删，14:57 直接开跑
  #   ⇒ 装载被静默跳过 ⇒ 管理器"没加载成功"、SELinux 停在 Permissive，
  #   而判定还写着 M6_VERDICT: ROOT。一个陈旧的实验标记不该能悄悄废掉一次真提权。
  if [ -f $RD/NO_LOAD ] && [ ! -f $RD/CONTROL_OK ]; then
    echo "=== !! 发现 NO_LOAD 但没有 CONTROL_OK ⇒ 视为陈旧标记，**忽略并继续正常装载** ==="
    echo "===    （确实要做对照实验：touch $RD/CONTROL_OK）==="
  fi
  if [ -f $RD/NO_LOAD ] && [ -f $RD/CONTROL_OK ]; then
    echo "=== NO_LOAD + CONTROL_OK: stopping BEFORE init_module (control experiment) ==="
    echo "policy was injected; module NOT loaded; leaving Permissive"
    echo "kmsg_dumper left running (pid ${KMSG_PID:-none})"
    # ★ 十改：allowlist 诊断（只读，确认授权有没有落进内核）
    echo "=== allowlist 诊断 ==="
    if [ -x /data/adb/ksud ]; then
      /data/adb/ksud allowlist list 2>&1 | head -20
    elif [ -f $RD/ksud_resukisu ]; then
      chmod 755 $RD/ksud_resukisu 2>/dev/null
      $RD/ksud_resukisu allowlist list 2>&1 | head -20
    fi
    echo "--- 管理器 uid ---"
    dumpsys package com.resukisu.resukisu 2>/dev/null | grep -m1 -E 'userId=' || echo '(取不到)'
    echo "=== final ==="
    timeout 10 grep -i kernelsu /proc/modules 2>/dev/null || echo "(no kernelsu - expected)"
    # ★ 2.77：对照实验也不许把设备留在 Permissive —— 之前那条路径直接 exit 0，
    #   SELINUX 就一直是宽容的。这里显式切回严格（没有模块，不存在自锁风险）。
    if [ ! -f $RD/KEEP_PERMISSIVE ]; then
      _e=""; { read -r _e < /sys/fs/selinux/enforce; } 2>/dev/null
      if [ "$_e" != "1" ]; then
        printf '1' > /sys/fs/selinux/enforce 2>/dev/null
        _e2=""; { read -r _e2 < /sys/fs/selinux/enforce; } 2>/dev/null
        echo "SELinux restore: ${_e:-?} -> ${_e2:-?}（对照实验退出前强制回 Enforcing）"
      else
        echo "SELinux 已是 Enforcing"
      fi
    fi
    echo "M6_VERDICT: ROOT_NO_MODULE（对照实验：只有 root，没有模块 ⇒ 管理器不可用）"
    exit 4
  fi
  $RD/kmsg_dumper $RD/kmsg_cap.txt &
  KMSG_PID=$!
  sleep 1
  # ★ 2026-10-16 整合（目标③：**参数组装单点化**）
  #   原来 KSU_PARAMS 在 6 处被拼接（本行 / grant_apps / veto×2 / sc×2），
  #   任何人改一处都看不到全局，顺序还依赖书写位置 —— 这正是"每次重审都出新问题"的温床。
  #   现在：各分支只**置标志**（P_ 前缀），字符串**只在 build_ksu_params() 里生成一次**。
  P_ALLOW_SHELL=1
  P_LOG_REBOOT=1
  P_GRANT_APPS=0
  P_VETO_REBOOT=0
  P_VETO_COMM=""
  P_SC_ENABLED=0
  P_SC_TABLE=""


# 2026-10-21: su 重定向目标。App 的 execvp 会去碰 /system/bin/su（不存在），
# 内核 kprobe 把它换成我们放在 App 自己 lib 目录里的 ksud 副本 —— 该路径标签是
# apk_data_file，SELinux 的 "allow untrusted_app apk_data_file:file execute" 是类型级规则，
# 所以任何 App 都能 exec 它，不需要 permissive、不需要 overlay。
SU_PATH_RUNTIME=""
# ★ 2026-10-24：取本 App 的 APK 路径（三个来源，pm 忙时也不至于空手）
# ★★ 2.35：这几个函数必须在 su 段落之前定义 ——
#   su 段落是**顶层代码**（约 949 行），而它们原来定义在 1318 行以后，
#   bash 顺序执行 ⇒ 顶层调用时函数还不存在 ⇒ 静默失败（2>/dev/null 吞了），
#   于是 /dev/su 一直用随包的 ksud_resukisu(5.7MB) 而不是管理器自带的 ksud。

_self_apk_path() {
  for _sp in io.github.knowlily.m6shell com.dsh.ppgroot; do
    _pv=$(pm path "$_sp" 2>/dev/null | sed -n 's/^package://p' | head -1)
    if [ -z "$_pv" ]; then
      _pv=$(cmd package path "$_sp" 2>/dev/null | sed -n 's/^package://p' | head -1)
    fi
    if [ -z "$_pv" ]; then
      _pv=$(dumpsys package "$_sp" 2>/dev/null | sed -n 's/^ *codePath=//p' | head -1)
    fi
    if [ -z "$_pv" ]; then
      # ★ 2.13（跟 3.16.35 对齐）：kernel 域里 pm/cmd/dumpsys 全空，
      #   /data/app 目录名就是包名，直接 glob —— 不依赖 PackageManager。
      _pv=$(ls -d /data/app/*/"$_sp"-*/base.apk 2>/dev/null | head -1)
      [ -n "$_pv" ] && echo "  [su] pm 取不到 ⇒ glob 定位到 $_pv" >&2
    fi
    [ -n "$_pv" ] && { echo "$_pv"; return 0; }
  done
  return 1
}

_su_setup_apk() {
  # ★★★ 2026-10-24 修：这里原来写死 `pm path com.dsh.ppgroot` 且**取不到就整体 return**，
  #   于是 /dev/su 不生成、su_path 不进 insmod 参数 ⇒ 所有 App 的 `su` 直接不可用
  #   （boot 0f264e73 12:13 实测：`[su] 取不到本包路径，跳过` → /dev/su 不存在 →
  #    `su: inaccessible or not found`）。而 /dev/su 分支其实**不需要**本包路径。
  # App 部署时会把 SELF_LIB / SELF_APK 写进 RD —— 本进程在 kernel 域里跑 pm 拿不到结果，
  # 这两个文件是唯一可靠来源（boot 4bfe983c 实测 pm/cmd/dumpsys 全空）。
  # ★ 2026-10-24（2.9）：上一轮的内核参数 su_path 可能已经指向死路径
  #   （装了新 APK ⇒ /data/app 下旧安装目录被 Installer 清掉）。这里先如实报出来，
  #   免得又变成"能重定向但拿不到 root"的哑谜。
  _prev_sp=$(tr -d '\r\n' < /sys/module/kernelsu/parameters/su_path 2>/dev/null)
  if [ -n "$_prev_sp" ] && [ ! -f "$_prev_sp" ]; then
    echo "  [su] 上轮 su_path=$_prev_sp 已不存在（多为换 APK 后旧安装目录被清）⇒ 本轮重建"
  fi
  _lib=$(tr -d ' \r\n' < "$RD/SELF_LIB" 2>/dev/null)
  _apk=$(tr -d ' \r\n' < "$RD/SELF_APK" 2>/dev/null)
  [ -n "$_lib" ] || {
    _apk=$(_self_apk_path)
    if [ -n "$_apk" ]; then _lib=$(dirname "$_apk")/lib/arm64; fi
  }
  [ -n "$_lib" ] || _lib=$(dirname "${_apk:-/nonexistent}" 2>/dev/null)/lib/arm64
  if [ ! -d "$_lib" ]; then
    _lib=$(ls -d /data/app/*/io.github.knowlily.m6shell-*/lib/arm64 2>/dev/null | head -1)
    [ -n "$_lib" ] && echo "  [su] SELF_LIB 不可用 ⇒ glob 定位到 $_lib"
  fi
  [ -n "$_apk" ] || echo "  [su] 取不到本包路径（/dev/su 分支不依赖它，继续）"
  # ★ ksud 必须与 ko 同源（CVE-2026-64560 报告 §7.5 的教训）：
  #   KernelSU Next 的 ksud 配官方 ko 会 "os error 2"，还会把 /data/adb/ksud 搞坏。
  #   优先用从「用户选中的那个管理器 APK」里抽出来的 ksud_mgr（版本天然对齐）。
  # ★ 2.34：无条件抽一次（自带「同包就跳过」判断）。原来只在 `! -x ksud_mgr` 时才抽，
  #   而老 ksud_mgr 是 0755（历史手工 chmod 遗产）⇒ 永远不重抽 ⇒
  #   /dev/su 用成 assets 里的 ksud_resukisu（uapi4, 5.7MB）而不是管理器自带的 ksud（7.45MB）。
  _extract_mgr_ksud >/dev/null 2>&1
  _susrc=""
  for _c in "$RD/ksud_mgr" "$RD/ksud_resukisu" "$RD/ksud_success"; do
    [ -f "$_c" ] || continue
    # ★★ 2.19（真机：清空 RD 后 ksud 全 rc=127）★★
    #   App 从 assets 推上来的文件是 0644，原来的 `[ -x ]` 判据直接跳过 ⇒
    #   "没有可执行的 ksud ⇒ 跳过加冕 / /dev/su 无法生成" ⇒ su 无实权。
    #   以前 RD 里那些文件带 +x 是历史上手工 chmod 留下的，一清目录就全废。
    chmod 755 "$_c" 2>/dev/null
    [ -x "$_c" ] && { _susrc="$_c"; break; }
  done
  [ -n "$_susrc" ] || { echo "  [su] 找不到可用 ksud，跳过"; return 0; }
  # ★★★ 2026-10-23（第三次修，前两次都错）：
  #   落点不能放 /data/app —— PackageManager 独占那个目录，开机/软重启会清掉
  #   不属于任何已安装包的目录。实测：19:42 建好 /data/app/.ksu-payload，
  #   19:45 软重启，19:47 目录已不存在 ⇒ su 重定向目标丢失 ⇒ 只重定向不换域。
  #
  #   改用 /dev/su：tmpfs，软重启不清（完整重启才清，而那时本来就要重新越狱）；
  #   标签 u:object_r:ksu_file:s0 正是 KSU 自家的 su 落点类型，App 域执行它
  #   属于 KSU 的授权模型，不依赖我们自创的目录。
  #   退路：marker SU_PATH_APKDIR ⇒ 退回旧行为（App 安装目录）。
  if [ ! -f "$RD/SU_PATH_APKDIR" ]; then
    cp -f "$_susrc" /dev/su.new 2>/dev/null && \
      chmod 755 /dev/su.new 2>/dev/null && \
      chcon u:object_r:ksu_file:s0 /dev/su.new 2>/dev/null
    _dsz=$(wc -c < /dev/su.new 2>/dev/null | tr -d ' ')
    _ssz=$(wc -c < "$_susrc" 2>/dev/null | tr -d ' ')
    [ "$_dsz" = "$_ssz" ] || echo "  [su] !! /dev/su.new 大小 $_dsz ≠ 源 $_ssz（复制不完整，本轮 su 会不可用）"
    _dlbl=$(ls -Z /dev/su.new 2>/dev/null | awk '{print $1}')
    case "$_dlbl" in
      *ksu_file*)
        mv -f /dev/su.new /dev/su 2>/dev/null
        if [ -x /dev/su ]; then
          echo "  [su] 源=$_susrc 落点=/dev/su 标签=$_dlbl 大小=$(wc -c < /dev/su 2>/dev/null)（tmpfs，软重启不丢）"
          SU_PATH_RUNTIME=/dev/su
          return 0
        fi
        ;;
      *) echo "  [su] ksu_file 标签打不上（${_dlbl:-?}）—— 装载前该类型还没注入，正常" ;;
    esac
    # ★★ 2.20（真机：MINIMAL + 2.19 之后 su 彻底没实权）★★
    #   装载前 ksu_file 一定打不上（policy 还没注入），而装载后本进程 exec 已坏
    #   （`[probe] 加载后: exec 失败(rc=139)`）⇒ 后补 chcon 也做不到。
    #   ⇒ 装载前就用 **apk_data_file** 顶上：这个类型开机就有，App 域执行它本来就是允许的
    #     （所有 App 的原生库都是这个标签）。sucompat 只认 su_path 这个**路径**，
    #     不要求标签必须是 ksu_file。
    if [ -f /dev/su.new ]; then
      chcon u:object_r:apk_data_file:s0 /dev/su.new 2>/dev/null
      _dlbl2=$(ls -Z /dev/su.new 2>/dev/null | awk '{print $1}')
      case "$_dlbl2" in
        *apk_data_file*|*ksu_file*)
          mv -f /dev/su.new /dev/su 2>/dev/null
          if [ -x /dev/su ]; then
            echo "  [su] 源=$_susrc 落点=/dev/su 标签=$_dlbl2 大小=$(wc -c < /dev/su 2>/dev/null)（装载前用 apk_data_file 顶上）"
            SU_PATH_RUNTIME=/dev/su
            return 0
          fi
          ;;
        *) echo "  [su] /dev/su 标签仍异常（${_dlbl2:-?}）⇒ 退回安装目录" ;;
      esac
    fi
    rm -f /dev/su.new 2>/dev/null
  else
    echo "  [su] SU_PATH_APKDIR ⇒ 按旧行为用安装目录落点"
  fi
  # ★ 2026-10-24（2.12，对齐老壳 3.16.35）：**不要**用 /data/app/.ksu-payload。
  #   3.16.34 曾把它当"固定目录"落点，3.16.35 实测后回退了，原话：
  #     「19:42 建好 /data/app/.ksu-payload，19:45 软重启，19:47 目录已不存在」
  #   —— PackageManager 独占 /data/app，会清掉不属于任何已装包的目录。
  #   所以落点只有两级：/dev/su（标签必须是 ksu_file，否则跳过）→ App 安装目录（apk_data_file）。
  if [ -z "$_lib" ]; then
    # ★ 2.20：m6-shell 的 APK 里**没有 lib/arm64**（纯 Kotlin），所以「退到安装目录」这条
    #   路根本不存在 ⇒ 之前直接放弃 su 目标 ⇒ su_path 不进参数 ⇒ su 无实权。
    #   只要 /dev/su 文件本身在，就仍然拿它当落点（标签未确认也比没有强）。
    if [ -x /dev/su ]; then
      echo "  [su] 无安装目录（APK 无 lib/arm64）⇒ 仍用 /dev/su（标签=${_dlbl2:-?}）"
      SU_PATH_RUNTIME=/dev/su
      return 0
    fi
    echo "  [su] /dev/su 不可用且没有安装目录 ⇒ 本轮 su 目标放弃"; return 0
  fi
  mkdir -p "$_lib" 2>/dev/null
  # ★ 先写临时名再 rename：上一轮 su 进程还占着 libksu_su.so 时，直接 cp 覆盖会 ETXTBSY
  #   （CVE-2026-64560 报告 §6.5：旧二进制仍在执行时重新部署 → ETXTBSY/EPIPE）
  cp -f "$_susrc" "$_lib/libksu_su.so.new" 2>/dev/null || { echo "  [su] 复制失败"; return 0; }
  chmod 755 "$_lib/libksu_su.so.new" 2>/dev/null
  mv -f "$_lib/libksu_su.so.new" "$_lib/libksu_su.so" 2>/dev/null || { echo "  [su] rename 失败"; return 0; }
  _lbl=$(ls -Z "$_lib/libksu_su.so" 2>/dev/null | awk '{print $1}')
  echo "  [su] 源=$_susrc 目标=$_lib/libksu_su.so 标签=${_lbl:-?} 大小=$(wc -c < "$_lib/libksu_su.so" 2>/dev/null)（不稳定落点）"
  SU_PATH_RUNTIME="$_lib/libksu_su.so"
}
  _su_setup_apk

  # ★ 2.76：装载前把 /dev/su 与 su 落点的"可用性"记下来。
  #   为什么必须在这里记：装载后本进程的 open/stat/access/exec 都不可靠
  #   （2.54 那次 `[suovl] 缺件` 就是假阴性）。而 _selinux_finalize 里用
  #   `[ -s /dev/su ]` / `[ -x ... ]` 判断，于是**明明铺好了却报
  #   "没有可用的 ksud ⇒ 为防自锁，本次不切严格"**（2026-10-27 00:38 实测：
  #   /dev/su 7,459,328 B 就在那儿，标签 apk_data_file:s0，enforce=1）。
  #   ⇒ 装载前记事实，装载后只信这份记录。
  DEV_SU_BYTES=0
  { _sz=$(wc -c < /dev/su 2>/dev/null); [ -n "$_sz" ] && DEV_SU_BYTES=$_sz; } 2>/dev/null
  [ -n "$SU_PATH_RUNTIME" ] && [ -x "$SU_PATH_RUNTIME" ] && DEV_SU_RUNTIME=1 || DEV_SU_RUNTIME=0
  echo "  [su] 装载前记录：/dev/su=${DEV_SU_BYTES}B 落点=${SU_PATH_RUNTIME:-无}(x=${DEV_SU_RUNTIME})"

  # ★ 2026-10-24：/data/adb/ksud 也在**装载前**铺好（装载后本进程就没权限写了，
  #   管理器的 "OS error / 未安装" 大多就是缺这个文件）。
  for _c in "$RD/ksud_mgr" "$RD/ksud_resukisu" "$RD/ksud_success"; do
    [ -x "$_c" ] || continue
    mkdir -p /data/adb 2>/dev/null
    cp -f "$_c" /data/adb/ksud.new 2>/dev/null && chmod 755 /data/adb/ksud.new 2>/dev/null \
      && mv -f /data/adb/ksud.new /data/adb/ksud 2>/dev/null || continue
    echo "  [ksud] /data/adb/ksud ← $_c（$(wc -c < /data/adb/ksud 2>/dev/null || echo ?) B）"
    break
  done

  # ══════════════ 唯一组装点 ══════════════
  #   顺序（与改动前逐字一致，勿改）：
  #     allow_shell log_reboot [bootid…] [grant_apps] [veto_reboot [veto_comm]] [sc_enabled [sc_table]]
  build_ksu_params() {
    _kp=""
    DEFER_SUCOMPAT=0
    [ "$P_ALLOW_SHELL" = "1" ] && _kp="$_kp allow_shell=1"
    [ "$P_LOG_REBOOT" = "1" ] && _kp="$_kp log_reboot=1"
    [ -n "$BP" ] && _kp="$_kp $BP"
    # ★★★ fix6-20261018：**显式传 grant_apps=N**（不传时 ko 的默认值是 Y）
    #   Y 的效果（2026-10-18 真机实测）：
    #     · `BVL rootshell: granted init_cred to 127 tasks (shells+granted apps)`
    #       —— 每 3 秒扫 100+ 个 task 换 cred，本身就在烧 CPU；
    #     · 已授权 App（含管理器自己）的进程被换成 uid0/kernel 域 ⇒ 它写自己的
    #       datastore 就变成 root:root 600 ⇒ 下次启动读不回来 EACCES ⇒ 闪退。
    #   改成 N 后同一日志掉到 `to 1 tasks`，只剩 shell 通道。
    #   需要「给 App 授权 root」时照旧：touch $RD/ADD_GRANT_APPS
    if [ "$P_GRANT_APPS" = "1" ]; then _kp="$_kp grant_apps=Y"; else _kp="$_kp grant_apps=N"; fi
    if [ "$P_VETO_REBOOT" = "1" ]; then
      _kp="$_kp veto_reboot=1"
      [ -n "$P_VETO_COMM" ] && _kp="$_kp veto_comm=$P_VETO_COMM"
    fi
    if [ "$P_SC_ENABLED" = "1" ]; then
      _kp="$_kp sc_enabled=1"
      [ -n "$P_SC_TABLE" ] && _kp="$_kp sc_table=0x$P_SC_TABLE"
    fi
    # ★★★ 2026-10-20 诊断：默认关掉 KSU 的 su_compat 功能（feature id 0）★★★
    #   现象：自编 ko 一加载，全系统 execve 立刻返回 ENOSYS（/system/bin/sh 都起不来）
    #   ⇒ 计划下一轮确认是不是 su_compat 的 hook 造成的：
    #        · 关了以后 exec 恢复  ⇒ 问题在 sucompat 处理链
    #        · 关了以后 exec 还是坏 ⇒ 问题在 KSU 的 sys_enter dispatcher 本身
    #   想恢复 su 功能：touch $RD/SUCOMPAT_ON
    # ★★★ 2026-10-20：自编 uapi5 ko 必须注入 sys_call_table / ni_syscall 地址 ★★★
    #   为什么：内核里按名解析这两个符号会失败 ⇒ 调度器装不上（dispatcher_nr 保持 -1）
    #   而 tracepoint 照样把 syscallno 改写成 -1 ⇒ do_ni_syscall ⇒ 全系统 ENOSYS。
    #   地址从 /proc/kallsyms 现算（KASLR 每次开机都变），由我们新加的模块参数注入。
    case "$(basename "$KSU_MODULE")" in
      kernelsu_custom.ko|kernelsu_ksu331.ko|kernelsu_next.ko)
        _sct=$(grep -m1 -w "sys_call_table" /proc/kallsyms 2>/dev/null | cut -d' ' -f1)
        _sni=$(grep -m1 -w "__arm64_sys_ni_syscall" /proc/kallsyms 2>/dev/null | cut -d' ' -f1)
        # 坑：kptr_restrict=2 时 kallsyms 给的是 0000000000000000，长度同样是 16
        case "$_sct" in ""|0000000000000000|ffffffffffffffff) _sct="";; esac
        case "$_sni" in ""|0000000000000000|ffffffffffffffff) _sni="";; esac
        if [ "$P_SC_ENABLED" = "1" ]; then
          echo "  [注入] 已有 sc_enabled 配置，跳过（避免 sc_table 重复传参）"
        elif [ ${#_sct} = 16 ] && [ ${#_sni} = 16 ]; then
          # kimage_voffset 的「符号地址」（不是值）：内核里解引用即得 image 的 VA→PA 偏移
          _kv=$(grep -m1 -w "kimage_voffset" /proc/kallsyms | cut -d' ' -f1)
          case "$_kv" in ""|0000000000000000|ffffffffffffffff) _kv="";; esac
          _kp="$_kp sc_table=0x$_sct sc_ni=0x$_sni${_kv:+ kimg_voff=0x$_kv}"
          echo "  [注入] sys_call_table=0x$_sct  ni_syscall=0x$_sni"
        else
          echo "  [注入] ⚠ 取不到 sys_call_table/ni 地址（_sct=${#_sct} _sni=${#_sni}）—— 调度器可能装不上"
        fi
        ;;
    esac

    # 2026-10-20 改：诊断期结束了 —— 默认**打开** su_compat（原来默认 0:0 等于把 su 关死）
    # ★★ 2.24：force_feature 支持**按名字**关单个特性（FinaSU policy/feature.c:32-79）。
    #   `echo "mount_view_filter:0,su_compat:0" > $RD/FORCE_FEATURE` ⇒ 原样拼进参数。
    #   可用的名字（fsu10/kernel/include/uapi/feature.h）：
    #     su_compat kernel_umount sulog adb_root selinux_hide avc_spoof
    #     shell_su_adb_only dynamic_manager_grants uts_view mount_view_filter
    if [ -f $RD/FORCE_FEATURE ]; then
      _ff=$(tr -d ' \r\n' < "$RD/FORCE_FEATURE" 2>/dev/null)
      if [ -n "$_ff" ]; then
        _kp="$_kp force_feature=$_ff"
        echo "  [诊断] FORCE_FEATURE=$_ff"
      fi
    elif [ -f $RD/WANT_SUCOMPAT ]; then
      # ★★ 2.55 回退到「装载时就开」★★
      #   2.51 试过 PPG 的「装载时关、收尾再开」，本机不成立：
      #   insmod 之后 loader 进程连 stat/access 都不行（不只 exec），
      #   `[ -x $RD/ksud_mgr ]` 都返回假 ⇒ "没有可执行 ksud" ⇒ 收尾根本跑不到。
      #   既然装载后什么都做不了，所有准备工作都必须在**装载前**完成，
      #   sucompat 只能靠 insmod 参数一次性打开（管理器加冕同理，走 ksu_debug_manager_appid）。
      echo "  [su] WANT_SUCOMPAT ⇒ 装载时直接打开 sucompat（装载后已无法再改）"
    else
      # ★★ 2.25（默认值变更）：默认**关闭** su_compat ★★
      #   为什么：sucompat 直接改 pt_regs 再跳 execveat，本机（荣耀 6.1.157 + CFI +
      #   patch_hn overlay）上会打成满屏 SIGSEGV（`exec 失败(rc=139)`），
      #   上次 panic 就发生在装载后 27 分钟。而我们的 su 根本不需要它 ——
      #   ko 已经把 su_path（/dev/su）注入成真实文件 /system/bin/su（7,452,064 B，
      #   overlay on /system/bin），App 直接 execve 那个文件就能跑，走普通路径。
      #   实测：sucompat 关掉，aShell 里 `su -c id` 正常，模块 Live 27.6 分钟无 panic。
      #   要恢复老行为：touch $RD/WANT_SUCOMPAT（或写 FORCE_FEATURE=su_compat:1）
      _kp="$_kp force_feature=su_compat:0"
      echo "  [su] 默认关闭 su_compat（su 走 /system/bin/su 真实文件；要开 touch $RD/WANT_SUCOMPAT）"
    fi
    # 2026-10-22: 多管理器包名，交给模块内的 track_throne 认（首选在前）
    # 一份 ko 同时认官方 / Next / BakaSU 等，不用各编一份；留空则模块退回编译期常量。
    _mgrs=""
    _pref2=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
    [ -z "$_pref2" ] && _pref2=$(cat /data/data/io.github.knowlily.m6shell/files/manager_pkg /data/data/com.dsh.ppgroot/files/manager_pkg 2>/dev/null | tr -d ' \r\n' | head -1)
    for _p in $_pref2 com.resukisu.resukisu me.weishu.kernelsu com.bakasu.bakasu com.resukisu.ksu kqvdie.zeykvw.hpbcyd com.sukisu.ultra me.yuki.fina; do
      [ -n "$_p" ] || continue
      case ",$_mgrs," in *",$_p,"*) continue ;; esac
      _mgrs="${_mgrs:+$_mgrs,}$_p"
    done
    [ -n "$_mgrs" ] && _kp="$_kp mgr_pkgs=$_mgrs" && echo "  [mgr] mgr_pkgs=$_mgrs"
    # 动态管理器：新管理器（改过签名/包名）要顶掉旧的那一个，内核必须能作废旧 uid。
    # 我们默认关掉了 invalidate（防自动扫描把手工加冕的管理器清掉），这里按需打开。
    if [ -f "$RD/DYNAMIC_MGR" ]; then
      _kp="$_kp mgr_dont_invalidate=0"
      echo "  [mgr] DYNAMIC_MGR ⇒ mgr_dont_invalidate=0（允许内核按签名重新加冕）"
    fi
    # ★ 2026-10-22：把"用户选中的管理器的 uid"直接当参数传下去，
    #   模块里 su 重定向用它放行管理器自身（BakaSU 没有 ksu_manager_appid 这个全局，
    #   引用它会变成未解析外部符号 ⇒ ko_patch2 整链 ABORT，真机踩过）。
    _mpk=$(printf '%s' "$_mgrs" | cut -d, -f1)
    _muid=""
    [ -n "$_mpk" ] && _muid=$(awk -v p="$_mpk" '$1==p{print $2; exit}' /data/system/packages.list 2>/dev/null)
    case "$_muid" in ''|*[!0-9]*) _muid="" ;; esac
    if [ -n "$_muid" ]; then
      # ★★★★ 2.47：内核里**还有**一个 ksu_debug_manager_appid ★★★★
      #   实测：装载后 `ls /sys/module/kernelsu/parameters/` 里有
      #     kimg_voff ksu_debug_manager_appid mgr_dont_invalidate mgr_pkgs
      #     sc_ni sc_table su_check su_cred su_dbg su_dbg_uid su_mgr_appid su_path
      #   而 `su_mgr_appid` 只管「su 放行哪家管理器」，**认管理器**看的是
      #   ksu_debug_manager_appid（内核用它直接指定 manager uid，不依赖签名扫描/ksud）。
      #   我们一直只传前一个 ⇒ 内核 appid=0 ⇒ 管理器 prctl 被拒 ⇒「未检测到内核」。
      #   现在两个都传，让 ko 在 insmod 那一刻就把管理器加冕好（不依赖装载后的 ksud）。
      _kp="$_kp su_mgr_appid=$_muid ksu_debug_manager_appid=$_muid"
      echo "  [mgr] su_mgr_appid=$_muid + ksu_debug_manager_appid=$_muid（$_mpk）"
    else
      echo "  [mgr] 取不到 $_mpk 的 uid ⇒ su_mgr_appid 不传（管理器自身 su 不放行）"
    fi
    # 2026-10-22：A/B 开关 —— touch $RD/NO_SUCRED 就只做"文件名改写"不改 cred，
    # 用来把 panic 定位到具体哪一步（步骤② 改 bprm->cred 目前只在代码层验证过）。
    # 2026-10-23：默认 2（换域）。NO_SUCRED→0（只重定向）、SU_CRED_PLAIN→1（旧行为）。
    if [ -f "$RD/NO_SUCRED" ]; then
      _kp="$_kp su_cred=0"
      echo "  [diagn] 按 marker 关闭 su_cred（只重定向、不改 cred）"
    elif [ -f "$RD/SU_CRED_PLAIN" ]; then
      _kp="$_kp su_cred=1"
      echo "  [diagn] 按 marker 走 su_cred=1（手工改 cred，uid=0 但域不变）"
    else
      _kp="$_kp su_cred=2"
      echo "  [su] 默认 su_cred=2（task_work + escape_with_root_profile，换 SELinux 域）"

  # ★★ 2.42（21:32 实证）：模块终于 Live 了（kernelsu 544768 Live），
  #   但**装载之后**本进程 open/exec 全废（`exec 失败 rc=127`、`/sys/module/...:
  #   Permission denied`），于是 ksud post-fs-data / install / 加冕 全部 rc=127，
  #   /system/bin/su 压根没生成 ⇒ `[probe] su: /dev/su 不可执行`。
  #   ⇒ 把 ksud 的三步**挪到装载之前**跑一遍（此进程这时还是真 root、exec 正常）。
  #   能成就白赚；不成也只是多两行 rc，不影响后面。
  if [ -x "$RD/ksud" ] && [ ! -f "$RD/NO_PRELOAD_KSUD" ]; then
    # ★★★★ 2.43（22:1x 定案：模块 Live 但 SukiSU 仍"未检测到内核"）★★★★
  #   ko 内部把 marker 路径**写死**成了 /data/local/tmp/ksu/HOOKS_ON
  #   （ko 字符串里能直接看到），而我们的 RD 是 /data/local/tmp/route/m6 ——
  #   所以无论 $RD 里放什么都永远不会生效，ko 一直按 "no HOOKS_ON marker"
  #   把 hook_manager / syscall hooks 全关掉。
  #   关掉钩子 = 管理器 prctl supercall 没人接 = 「有 root 权限但未检测到内核」。
  #   ⇒ 装载前在 ko 认的那个路径上建 marker（两个路径都建，保险）。
  _KSUDIR=/data/local/tmp/ksu
  mkdir -p "$_KSUDIR" 2>/dev/null
  if [ ! -f "$RD/NO_HOOKS" ]; then
    : > "$_KSUDIR/HOOKS_ON" 2>/dev/null
    : > "$RD/HOOKS_ON" 2>/dev/null
    chmod 666 "$_KSUDIR/HOOKS_ON" "$RD/HOOKS_ON" 2>/dev/null
    echo "  [hooks] HOOKS_ON 已建（$_KSUDIR/HOOKS_ON + $RD/HOOKS_ON）⇒ ko 会装 hook_manager/syscall hooks"
  else
    rm -f "$_KSUDIR/HOOKS_ON" "$RD/HOOKS_ON" 2>/dev/null
    echo "  [hooks] marker NO_HOOKS ⇒ 不装钩子（管理器会显示未检测到内核）"
  fi

  # ★ 2.44：SukiSU/ksud 内部到处引用 /data/adb/ksu/bin/ksud、/data/adb/ksu/lib/…
  #   只写 /data/adb/ksud（旧行为）不够，管理器的某些检查会因为这个路径缺失而判定内核异常。
  if [ -f "$RD/ksud" ]; then
    mkdir -p /data/adb/ksu/bin /data/adb/ksu/log /data/adb/ksu/module_configs 2>/dev/null
    cp -f "$RD/ksud" /data/adb/ksu/bin/ksud 2>/dev/null && chmod 755 /data/adb/ksu/bin/ksud 2>/dev/null
    ln -sf /data/adb/ksu/bin/ksud /data/adb/ksud 2>/dev/null
    cp -f "$RD/ksud" /data/adb/ksud 2>/dev/null; chmod 755 /data/adb/ksud 2>/dev/null
    # ★ 2.51（吸收 PPG 5.0.7）：管理器/旧脚本会去 /data/adb/ksu/bin/su 找 su
    ln -sf /data/adb/ksud /data/adb/ksu/bin/su 2>/dev/null
    echo "  [ksuddir] /data/adb/ksu/bin/ksud=$(wc -c < /data/adb/ksu/bin/ksud 2>/dev/null || echo 0)B /data/adb/ksud=$(wc -c < /data/adb/ksud 2>/dev/null || echo 0)B"
  fi

  # ══════════════════════════════════════════════════════════════════════════
  # ★★ 2.55（吸收 MagicRoot 1.0.3）su overlay —— 必须在**装载前**做 ★★
  #   实测：insmod 之后本进程连 stat/access 都失败（不只是 exec），
  #   所以 overlay 挂载、ksud 调用、加冕这些统统只能放在装载前。
  #   挂载本身是持久的（tmpfs + setns 进 zygote ns），装载后 App 就能看到 su。
  #   关掉：touch $RD/NO_SU_OVERLAY
  # ══════════════════════════════════════════════════════════════════════════
  # ★★ 2.58：改成「按需挂」，默认不挂 ★★
  #   理由：/system_ext/bin/su 是 PATH 里的一个真实文件，原生 KernelSU 机器没有，
  #   检测类 App 一眼就能看出来（挂载记录能靠 mount_hide 藏，文件藏不了）。
  #   绝大多数 root 应用用 libsu，直接 execve("/system/bin/su")，路径不需要存在，
  #   sucompat 会把它改写成 /data/adb/ksud ⇒ 不挂也能 su。
  #   真遇到"先 stat 再 exec"的老应用，再 touch $RD/SU_OVERLAY 打开。
  if [ -f "$RD/NO_SU_OVERLAY" ]; then
    echo "  [suovl] NO_SU_OVERLAY ⇒ 禁用"
  elif [ ! -f "$RD/SU_OVERLAY" ]; then
    echo "  [suovl] 默认不挂（隐藏性优先）；需要时 touch $RD/SU_OVERLAY"
  elif [ -x "$RD/su_overlay_helper" ] && [ -f "$RD/su_optional.sh" ]; then
    echo "=== su overlay（装载前，setns + tmpfs upper → /system_ext/bin） ==="
    chmod 755 "$RD/su_optional.sh" "$RD/su_overlay_helper" "$RD/su_forward" 2>/dev/null
    sh "$RD/su_optional.sh" enable 2>&1 | sed 's/^/  /'
    echo "  [suovl] rc=$?"
    if [ -x /system_ext/bin/su ]; then
      echo "  [suovl] /system_ext/bin/su 已就位（$(wc -c < /system_ext/bin/su 2>/dev/null || echo 0)B）"
    else
      echo "  [suovl] !! /system_ext/bin/su 仍未出现"
    fi
  else
    echo "  [suovl] 缺 su_overlay_helper / su_optional.sh ⇒ 跳过"
  fi

  echo "=== 装载前预跑 ksud（进程此时还有真 root/exec） ==="
    for _k in post-fs-data install services; do
      _t0=$(date +%s 2>/dev/null)
      timeout 20 "$RD/ksud" "$_k" >/dev/null 2>&1
      echo "  [ksud-pre] $_k rc=$? ($(( $(date +%s 2>/dev/null) - ${_t0:-0} ))s)"
    done
    ls -l /system/bin/su 2>&1 | sed 's/^/  [ksud-pre] /'
    [ -f /system/bin/su ] && echo "  [ksud-pre] ✓ /system/bin/su 已存在" || echo "  [ksud-pre] ✗ 仍然没有 /system/bin/su"
  fi
    fi
    [ -n "$SU_PATH_RUNTIME" ] && _kp="$_kp su_path=$SU_PATH_RUNTIME"
    KSU_PARAMS="${_kp# }"     # 去掉前导空格
  }
  build_ksu_params
  # ---- 3.9 模块三轨（2026-09-22）----
  # 实测结论：官方 3.3.0 LKM 符号/CRC 全过（205/205）但 init_module 内 CPU 挂死
  # （APPS_NON_SECURE_WDT，02:17:50 实锤）→ Honor 内核结构漂移，官方路关死。
  # 现默认 CGA 双补丁版（faccessat+execve 两炸点入口已 movz+ret 摘除）：
  # 模块能加载、管理器/su 的挂死触发器不存在，管理器 UI 走 ioctl/supercall。
  # 官方路保留但需显式 marker USE_330。
  # ========================================================================
  # ★★★ 最高优先级：BVL-AN16 真机一发成功的原始路线 ★★★
  #   来源：Magic6pro170_BVL175修改版.zip 的 BVL175_ksu_deliver/final
  #         = 2026-09-21 真机成功那一套（boot 542cd198）
  #   md5 = 4f04e51e70b29aca1061c10c59c36654
  #   成功证据（包内 root-成功报告.md）：
  #     kernelsu 192512 2 - Live 0x0000000000000000 (OE)
  #     ksud (pid 18899) 运行中
  #     /system/bin/su (root:root, 4556352 bytes) 已部署
  #     load_ko_exit=0（221 符号全解析）
  #   原路线就是最朴素的：
  #     timeout 180 $RD/load_ko $RD/kernelsu.ko "$KSU_PARAMS" > $RD/loadko_result.log 2>&1
  #   **不套用** ko_patch2 / next_sym_addr（成功包没套，符号本来就全解析）。
  #
  #   为什么要置顶：项目后来加了 bvl16/bvl_tp/bvl_dp/os9-selx11 一堆分支，
  #   把原本成功的 kernelsu.ko 挤到了最后的 else ⇒ 永远走不到。
  #   而 BVL175 的 README 反过来明确警告：
  #     「别用 GhostLock APP 的 os9-selx11 / CGA-W00 路线 —— 作者标注成功率非常低，
  #       且 os9 模块面向 MagicOS 9，与你的 MagicOS 10 不符」
  #   标记 $RD/NO_SUCCESS_KO 可跳过本分支（回退到旧行为，用于 A/B 对照）。
  # ========================================================================
  # ========================================================================
  # ★★ 2026-10-16：按作者配方改回 —— **os9-selx11 是唯一正确的选择** ★★
  #
  #  核实过的事实（读 ko 的 modinfo + 作者脚本）：
  #    kernelsu-os9-selx11.ko  5,533,360 B
  #        vermagic = 6.1.157-android14-11-g7d3922fade43   ← 唯一与设备内核逐字匹配的
  #        参数 24 个，独有：grant_apps / grant_log / sc_enabled / sc_table /
  #                          sc_execve_{now,want} / sc_faccessat_{now,want} /
  #                          sc_newfstatat_{now,want} / sc_n_*
  #    kernelsu_success.ko / kernelsu_cga.ko / kernelsu.ko  全是 6.1.128、参数仅 11 个、
  #        **没有 grant_apps、没有 sc_***  ⇒ 既会崩（版本不匹配）又缺授权能力
  #
  #  作者的配方（phone_load.sh:50,63 与 load_selx11_full.sh:21,28）：
  #      KO=kernelsu-os9-selx11.ko
  #      $RD/ko_patch2 $RD/$KO $IT $RD/next_sym_addr.txt
  #      timeout 180 $RD/load_ko $RD/$KO "allow_shell=1 log_reboot=1 grant_apps=Y"
  #    然后 "打开 ReSukiSU 管理器 → 首页应显示「工作中」→ 超级用户 → 授权 App"
  #
  #  标记 $RD/TRY_MISMATCHED_KO 可切回旧的 6.1.128 ko（仅 A/B 对照，会崩）
  # ========================================================================
  # ★★★ 2026-10-16 四改：首选 = kernelsu-os9-selx11.ko ★★★
  #   理由（硬数据）：
  #     设备真实内核 = 6.1.157-android14-11-g7d3922fade43（9 份日志一致）
  #     全 APK 里**唯一** vermagic 与它逐字匹配的就是 kernelsu-os9-selx11.ko
  #     而 kernelsu.ko / kernelsu_success.ko 都是 6.1.128（差 29 个补丁版）
  #       ⇒ load_ko 用 flags-only 宽松校验能加载，但模块内部偏移错 ⇒ 挂死重启
  #     00:12 日志证明 os9-selx11 提权成功（post_root uid=0 → load_ko_exit=0
  #       → ★ kernelsu 已进 /proc/modules），且 BakaSU 认出「工作中 [LKM][越狱模式]」
  #
  #   历史记录（曾一度换回 6.1.128 的 success ko，现已改回）：
  #     那 5 份成功日志（21:57 / 22:13 / 22:19 / 22:47 / 23:51）走的都是
  #     kernelsu_success.ko（6.1.128）。它能提权成功，但与设备内核差 29 个补丁版，
  #     模块内部偏移错 ⇒ 每次都在 10~60 秒 ~ 3 分钟内挂死重启。
  #     ⇒ 命中率不能只看"能不能命中"，还要看"命中之后能不能活"。
  #
  #   ★ 关于"管理器不认"：那很可能不是 ko 的问题，而是**管理器选错了**。
  #     BakaSU（=ReSukiSU）官网明说：
  #       "supports KernelSU/MKSU/RKSU/SukiSU Ultra's manager by default"
  #     而 YG 的 BakaSU 首页对 os9-selx11 显示「工作中 [LKM][越狱模式]」
  #       ⇒ 换 BakaSU 管理器后，success ko 也可能被认。
  #
  #   标记 $RD/FORCE_SUCCESS_KO 可强制用 6.1.128 那两个（A/B 对照）
  # ★ 与 KSUD_DEPLOY 同一原则：ksud 也优先用与管理器同代的那份
  if [ -f $RD/ksud_resukisu ]; then KSUD_BEST=$RD/ksud_resukisu
  elif [ -f $RD/ksud_success ]; then KSUD_BEST=$RD/ksud_success
  else KSUD_BEST=$RD/ksud; fi

# ═══════════════════════════════════════════════════════════════════════════
# ★★★ 2026-10-19 合并自官方 3.13.2：**用户自备 ko 优先通道** ★★★
#   官方 3.13.2：$RD/kernelsu_custom.ko 或 $RD/kernelsu.ko 存在就直接用，无任何校验。
#   风险实测：6.1.128 的 ko 在本机（6.1.157）也能"装载成功、显示 Live"
#   （load_ko 是 flags-only 宽松校验），但模块内部结构体偏移按旧内核算
#   ⇒ execve 时跪 ⇒ 表现为"提权成功后 10~60 秒复位"。
#   本版保留通道，加三道门，默认拒绝并回退内置候选：
#     ① 文件 ≥ 16 KB（防 3.13.2 注释里 touch 建占位后忘了覆盖，留 0 字节）
#     ② 前 4 字节必须是 ELF magic（7f 45 4c 46）
#     ③ vermagic 首段必须与 `uname -r` **逐字相同**（-4k / -dirty 都算差异）
#   强制使用不匹配的 ko（仅 A/B，预期复位）：touch $RD/ALLOW_FOREIGN_KO
#   回退：删掉 kernelsu_custom.ko / kernelsu.ko 即可
# ═══════════════════════════════════════════════════════════════════════════
# ★ 2.67：装载后每一步都打一个 stage 标记（纯内建 touch/echo，不 fork/exec）。
#   目的：装载后 exec 会坏，卡住时日志常常只停在上一行 —— 有了 stage 就能精确定位
#   是 selfcheck / probe_su / selinux_finalize / final 哪一步卡住。
_stage() {
  echo "  [stage] $1"
  # ★ 2.78：另外往一个**预开的 fd** 写一行台账（`exec 9>>` 在装载前就打开）。
  #   事故：15:22/16:50 两次成功装载之后 ksu_load.log 直接停在装载前的 sweep，
  #   后面 su_cred/mgr_selfheal/selinux_finalize 有没有跑**完全看不到** ——
  #   主日志那条路在 insmod 之后断了（不是权限，是进程/写通道的问题）。
  #   预开的 fd 不依赖路径查找，能把"最后走到哪一步"留下来。
  { printf '[stage] %s\n' "$1" >&9; } 2>/dev/null || true
  # ★★ 2.73：**绝对不要用 `:` 做这个重定向**。
  #   `:` 是 POSIX **特殊内建**：非交互 shell 里一旦重定向失败（装载后变成非 root、
  #   $RD 写不进去 ⇒ "can't create ...: Permission denied"），**shell 直接退出**。
  #   实测后果：日志停在 `[stage] su_cred_apply`，后面的 mgr_selfheal /
  #   selinux_finalize / fresh_selfcheck 全部没跑（2.67~2.72 一直如此）。
  #   改用 printf（普通内建）+ `|| true`：失败只跳过这一条。
  { printf '' > "$RD/.stage_$1"; } 2>/dev/null || true
}

_probe_exec() {
  # 2026-10-20 诊断：判断 exec 什么时候开始坏（加载后？切 Enforcing 后？）
  if timeout 5 /system/bin/sh -c 'exit 0' >/dev/null 2>&1; then
    echo "  [probe] $1: exec 正常"
  else
    echo "  [probe] $1: exec 失败(rc=$?) ⇒ 全系统 execve 已被打成 ENOSYS"
  fi
}

_probe_su() {
  # 2026-10-20：直接验证「su 有没有真权」——之前所有轮次都只看模块 Live，
  # 从没在日志里落过一条 su 的实际结果，导致"提权成功但没 su"分辨不出来。
  # ★ 2.14：内核里的 su 前端是 **按 argv[0] 的 basename 判**的（basename=="su" ⇒ su 模式，
  #   否则走 ksud 的 CLI 子命令解析）。原来直接跑 `/dev/su -c id`，basename 恰好是 "su"，
  #   但某些 ksud 构建仍然按 CLI 走 → 打印 "Usage: su <COMMAND>"，
  #   于是 probe 误报「不是 su 而是 ksud 本体（uapi 不匹配）」——真机 2.13 实测这条是假的
  #   （同一轮 App 域里 su 完全正常）。现在用**目录里名为 su 的软链**再跑，
  #   保证 argv[0] 是 "su"，并且把三种结果分开报：
  #     rc=0 + 数字      ⇒ su 真的放大成了 root
  #     rc=0 + 非数字    ⇒ 前端能跑但没换权（多半是调用者不在 allowlist）
  #     打印用法/ENOSYS  ⇒ 前端没接通
  _su_probe=${SU_PATH_RUNTIME:-/dev/su}
  if [ ! -x "$_su_probe" ]; then echo "  [probe] su: $_su_probe 不可执行"; return 0; fi
  _pd="$RD/.su_probe"; mkdir -p "$_pd" 2>/dev/null
  ln -sf "$_su_probe" "$_pd/su" 2>/dev/null
  _su_out=$(timeout 8 "$_pd/su" -c 'id -u' 2>&1 | tr -d '\r\n')
  _su_rc=$?
  rm -f "$_pd/su" 2>/dev/null; rmdir "$_pd" 2>/dev/null
  case "$_su_out" in
    *"Usage:"*|*"unexpected argument"*)
      echo "  [probe] su: 前端按 CLI 走（打印用法）rc=$_su_rc ⇒ sucompat 未接通或 argv[0] 未被识别"; return 0 ;;
  esac
  case "$_su_out" in
    0) echo "  [probe] su: rc=0 uid=0 ⇒ su 已提权（本进程域）" ;;
    "") echo "  [probe] su: rc=$_su_rc 无输出 ⇒ 前端执行失败" ;;
    *[!0-9]*) echo "  [probe] su: rc=$_su_rc out=$_su_out（前端能跑但未换权：调用者不在 allowlist 属正常）" ;;
    *) echo "  [probe] su: rc=$_su_rc uid=$_su_out" ;;
  esac
}

# ★ 2.29：从 ksud_mgr 里读管理器版本串（"4.2.0-rc3-81-g…" / "4.2.1-r2" / "1.0.10"）。
#   为什么需要：SukiSU 的「隐藏包名」版 APK 包名是随机的（实测 rqglxo.qzizju.uholjr），
#   没法靠包名映射 ko；而 ksud 里一定带版本串，按版本映射才是稳的。

_pick_custom_ko() {
  CUSTOM_KO=""
  # ★ 2026-10-20：自编 uapi5 ko 有两份（BakaSU main / 官方 v3.3.1），按用户选的管理器挑
  _cko_pkg=$(tr -d ' \r\n' < "$RD/MANAGER_PKG" 2>/dev/null)
  [ -z "$_cko_pkg" ] && _cko_pkg=$(cat /data/data/io.github.knowlily.m6shell/files/manager_pkg /data/data/com.dsh.ppgroot/files/manager_pkg 2>/dev/null | tr -d ' \r\n' | head -1)
  _cko_inst=0
  if [ -n "$_cko_pkg" ]; then
    pm list packages 2>/dev/null | tr -d '\r' | grep -qx "package:$_cko_pkg" && _cko_inst=1
    [ "$_cko_inst" = "0" ] && { ls -d /data/app/*/"$_cko_pkg"-*/ >/dev/null 2>&1 && _cko_inst=1; }
  fi
  if [ -z "$_cko_pkg" ] || [ "$_cko_inst" = "0" ]; then
    _auto=$(_detect_mgr_pkg)
    if [ -n "$_auto" ]; then
      echo "  [自编ko] 未指定管理器 ⇒ 自动识别到已装 $_auto"
      _cko_pkg=$_auto
    fi
  fi
  _cko_first="$RD/kernelsu_custom.ko"
  if [ "$_cko_pkg" = "me.weishu.kernelsu" ] && [ -f "$RD/kernelsu_ksu331.ko" ]; then
    _cko_first="$RD/kernelsu_ksu331.ko"
  fi
  # KernelSU-Next（v3.4.2，包名被伪装）⇒ 用 Next 的 ko
  if [ "$_cko_pkg" = "kqvdie.zeykvw.hpbcyd" ] && [ -f "$RD/kernelsu_next.ko" ]; then
    _cko_first="$RD/kernelsu_next.ko"
  fi
  # SukiSU / FinaSU（uapi 6）⇒ 各有自己的 ko，uapi 对不上会「需要更新内核」
  if [ "$_cko_pkg" = "com.sukisu.ultra" ] && [ -f "$RD/kernelsu_sukisu.ko" ]; then
    _cko_first="$RD/kernelsu_sukisu.ko"
  fi
  if [ "$_cko_pkg" = "me.yuki.fina" ]; then
    # ★★★ 2.15（适配 FinaSU v1.0.10）：v1.0.10 相对 v1.0.9 只改了三处内核代码，其中两处正好
    #   落在"关屏 panic"的嫌疑区 —— 上游自己写成了修复：
    #     ① mount_view_filter.c: ksu_mvf_has_root_marker() 开头补 `!mnt || !mnt->mnt_root ||
    #        IS_ROOT(...)` 空判（原来直接 dentry_path_raw 解引用）
    #     ② mount_view_filter.c: show 回调里 `down_read(&mount_list_lock)` 改 `down_read_trylock()`，
    #        注释原文：show 回调跑在 namespace_sem(R) 下，而 umount 路径是
    #        mount_list_lock(R) → namespace_sem(W)，阻塞读会把这个环补全 = ABBA 死锁。
    #        锁环在挂载表刷新（关屏/解冻/卸载）时最容易触发。
    #     ③ ksud_integration.c: input_hook_stopped 改 READ_ONCE/WRITE_ONCE（音量键钩子的数据竞争）
    #   ⇒ 默认用 v1.0.10 的 ko。没有就退回 v1.0.8（无 mount_view_filter，最保守）。
    #   强制回旧版：touch $RD/USE_FINASU_108
    # ★★ 2.59（适配 FinaSU v1.2.1 / 33074）★★
    #   uapi 仍是 6（uapi/supercall.h: KERNEL_SU_UAPI_VERSION = 6），ko 侧只需换版本对齐。
    #   优先级：finasu121 > finasu110 > finasu(v1.0.8)
    #   强制回 v1.0.10：touch $RD/USE_FINASU_110
    _cko_first=""
    if [ -f "$RD/kernelsu_finasu121.ko" ] && [ ! -f "$RD/USE_FINASU_110" ]; then
      _cko_first="$RD/kernelsu_finasu121.ko"
      echo "  [版本] 有 v1.2.1 的 ko ⇒ kernelsu_finasu121.ko（uapi6，与管理器 v1.2.1 对齐）"
    fi
    [ -z "$_cko_first" ] && _cko_first="$RD/kernelsu_finasu110.ko"
    if [ ! -f "$_cko_first" ]; then
      _cko_first="$RD/kernelsu_finasu.ko"
      [ -f "$_cko_first" ] && echo "  [版本] 包里没有 v1.0.10 的 ko ⇒ 退回 v1.0.8（无 mount_view_filter）"
    fi
    if [ -f "$RD/USE_FINASU_108" ] && [ -f "$RD/kernelsu_finasu.ko" ]; then
      _cko_first="$RD/kernelsu_finasu.ko"
      echo "  [版本] USE_FINASU_108 ⇒ 用 v1.0.8（无 mount_view_filter）"
    fi
    [ -f "$RD/PREFER_STABLE_KO" ] && [ -f "$RD/kernelsu_sukisu.ko" ] && \
      { _cko_first="$RD/kernelsu_sukisu.ko"; echo "  [稳定性] PREFER_STABLE_KO ⇒ 改用 SukiSU ko（管理器请切到 SukiSU）"; }
  fi
  # ★★ 2.29（适配 BakaSU v4.2.0-rc3 / SukiSU v4.2.1-r2）★★
  #   为什么不用包名映射：SukiSU 的「隐藏包名」发行版包名是随机的
  #   （实测 `rqglxo.qzizju.uholjr`，ksud 的 .so 也被改名成 libscibhqvpso.so），
  #   包名白名单永远追不上。改成读 ksud_mgr 里的**版本串**：
  #     4.2.0-rc3-81-gd5e9e025 → BakaSU（APK 35252）—— 注意：v4.2.0-rc3 **tag** 是 uapi4，
  #        但这版 APK 是 tag 之后 81 个提交（d5e9e025, main），main 的 uapi 是 **6**，
  #        管理器界面上也显示 6 ⇒ 必须用 main 编的 ko。
  #     4.2.1-r2              → SukiSU v4.2.1-r2，uapi 6
  _mver=$(_mgr_ver)
  case "$_mver" in
    4.2.0*)
      # ★★ 2.49：BakaSU 临时禁用（等上游）★★
      #   实测 kernelsu_basu420.ko（main@d5e9e025, uapi6）装载成功但管理器「无活跃管理器」：
      #   BakaSU 的加冕是 crown_manager() 扫 /data/system/packages.list + 校验 APK 签名，
      #   不认 mgr_pkgs / ksu_debug_manager_appid，而我们的装载后进程树连 exec 都没有，
      #   扫描跑不起来。uapi5 老 ko 同理（管理器侧 uapi6，双向都卡）。
      #   等上游支持「直接指定管理器 uid」再放开：touch $RD/ENABLE_BASU
      if [ -f "$RD/ENABLE_BASU" ]; then
        if [ -f "$RD/kernelsu_basu420.ko" ]; then
          _cko_first="$RD/kernelsu_basu420.ko"
          echo "  [版本] 管理器 ksud=$_mver（BakaSU, uapi6）⇒ kernelsu_basu420.ko（ENABLE_BASU 已开，实验）"
        fi
      else
        echo "  [版本] ⚠ 检测到 BakaSU（ksud=$_mver）—— 本版**临时禁用**"
        echo "  [版本]   原因：BakaSU 靠签名扫描加冕，装载后跑不起来 ⇒ 管理器会显示「无活跃管理器」"
        echo "  [版本]   建议：设置里改用 SukiSU（r1 ko）或 FinaSU；想强行试：touch $RD/ENABLE_BASU"
        echo "  [版本]   已跳过装载，避免白跑一发；本次不做任何提权动作"
        exit 0
      fi
      ;;
    4.2.1*)
      # ★★ 2.48：SukiSU 默认退回 r1（41057）★★
      #   实测 r2（41074）与 r1（41057）的钩子机制/符号解析/syscall 处理**二进制层面完全一致**，
      #   r2 只多了一个 feature/avc_spoof.c（往 slow_avc_audit 挂 kprobe + 解析 SELinux SID）。
      #   本机 r2 装载成功但管理器查不到内核、r1 正常 ⇒ 先默认 r1。
      #   想让 r2 回来做对照：touch $RD/KO_SUKI421
      if [ -f "$RD/KO_SUKI421" ] && [ -f "$RD/kernelsu_suki421.ko" ]; then
        _cko_first="$RD/kernelsu_suki421.ko"
        echo "  [版本] 管理器 ksud=$_mver（SukiSU v4.2.1-r2, uapi6）⇒ kernelsu_suki421.ko（KO_SUKI421 强制）"
      elif [ -f "$RD/kernelsu_sukisu.ko" ]; then
        _cko_first="$RD/kernelsu_sukisu.ko"
        echo "  [版本] 管理器 ksud=$_mver ⇒ kernelsu_sukisu.ko（v4.2.1-r1, uapi6；r2 有 avc_spoof 问题，默认退回）"
      elif [ -f "$RD/kernelsu_suki421.ko" ]; then
        _cko_first="$RD/kernelsu_suki421.ko"
        echo "  [版本] 管理器 ksud=$_mver ⇒ 没有 r1，退回 kernelsu_suki421.ko（v4.2.1-r2）"
      fi
      ;;
  esac
  echo "  [自编ko] 管理器=${_cko_pkg:-自动}（${_mver:-未知版本}）⇒ 首选 $(basename "$_cko_first")"
  for _cko_cand in "$_cko_first" "$RD/kernelsu_basu420.ko" "$RD/kernelsu_suki421.ko" "$RD/kernelsu_sukisu.ko" \
                   "$RD/kernelsu_custom.ko" "$RD/kernelsu_sukisu.ko" \
                   "$RD/kernelsu_finasu110.ko" "$RD/kernelsu_finasu.ko" "$RD/kernelsu.ko"; do
    [ -f "$_cko_cand" ] || continue
    if ! _ko_is_bundled "$_cko_cand"; then
      if [ -f "$RD/ALLOW_FOREIGN_KO" ]; then
        echo "  ⚠ 自备 ko（不在打包清单）：$(basename "$_cko_cand") ⇒ ALLOW_FOREIGN_KO 存在，照用"
      else
        echo "  ⚠ 跳过自备 ko：$(basename "$_cko_cand")（md5/大小与打包清单不符）"
        echo "     ⇒ 默认只用 APK 自带的 ko；要用自备的：touch $RD/ALLOW_FOREIGN_KO"
        continue
      fi
    fi
    CUSTOM_KO=$_cko_cand
    break
  done
  [ -z "$CUSTOM_KO" ] && return 1

  _cko_sz=$(wc -c < "$CUSTOM_KO" 2>/dev/null | tr -d ' \t')
  _cko_magic=$(head -c 4 "$CUSTOM_KO" 2>/dev/null | od -An -tx1 | tr -d ' \n')
  # 取 vermagic：grep -a 优先（toybox/busybox 都有），strings 兜底
  _cko_ver=$(grep -a -m1 -o 'vermagic=[^ ]*' "$CUSTOM_KO" 2>/dev/null | head -1 | sed 's/^vermagic=//')
  if [ -z "$_cko_ver" ]; then
    _cko_ver=$(strings "$CUSTOM_KO" 2>/dev/null | grep -m1 '^vermagic=' | sed 's/^vermagic=//; s/ .*//')
  fi
  _cko_krel=$(uname -r 2>/dev/null)

  _cko_rej=""
  case "$_cko_sz" in
    ''|*[!0-9]*) _cko_rej="读不到文件大小" ;;
  esac
  if [ -z "$_cko_rej" ] && [ "$_cko_sz" -lt 16384 ]; then
    _cko_rej="只有 ${_cko_sz}B，像占位空文件（touch 之后忘了覆盖？）"
  fi
  if [ -z "$_cko_rej" ] && [ "$_cko_magic" != "7f454c46" ]; then
    _cko_rej="不是 ELF 模块（前 4 字节=${_cko_magic:-空}）"
  fi
  if [ -z "$_cko_rej" ] && [ -z "$_cko_ver" ]; then
    _cko_rej="读不到 vermagic（不是标准 .ko？）"
  fi
  if [ -z "$_cko_rej" ] && [ "$_cko_ver" != "$_cko_krel" ]; then
    if [ -f "$RD/ALLOW_FOREIGN_KO" ]; then
      echo "  ⚠ 自备 ko vermagic=$_cko_ver ≠ 内核 $_cko_krel"
      echo "    但 $RD/ALLOW_FOREIGN_KO 存在 ⇒ 强制装载（预期不稳定，仅 A/B）"
    else
      _cko_rej="vermagic 不匹配（ko=$_cko_ver / 内核=$_cko_krel）"
    fi
  fi

  if [ -n "$_cko_rej" ]; then
    echo "  ⚠ 拒绝自备 ko：$CUSTOM_KO"
    echo "     原因：$_cko_rej"
    echo "     ⇒ 回退到内置候选；要强制使用：touch $RD/ALLOW_FOREIGN_KO 再打一发"
    CUSTOM_KO=""
    return 1
  fi
  return 0
}
# ── 自备 ko 通道（合并自 3.13.2）结束 ──────────────────────────────────────

  # ════════════════════════════════════════════════════════════════════════
  # ★★★★ 2026-10-16 八改（YG 要求）：走 ksud 的 late-load ★★★★
  #
  #  为什么：我们手工 load_ko 的那些 ko 都是**旧接口**，
  #    · os9-selx11        → UAPI **4**（管理器要 5 ⇒ 报"需要更新内核" + 闪退）
  #    · success/cga/kernelsu.ko → UAPI 5 但 vermagic 6.1.128
  #  而 **ksud 自己内嵌着一份 UAPI 5 的 android14-6.1_kernelsu.ko**：
  #    · 源码 late_load/mod.rs:
  #        let ko_name = format!("{kmi}_kernelsu.ko");
  #        let ko_data = assets::get_asset(&ko_name)?;
  #        ksuinit::load_module(&ko_data, cstr!("allow_shell=1"))?;
  #    · 它是 **ksuinit 内存加载 + 符号重定位**，比我们手工 load_ko 更正规
  #    · 管理器"更新内核"走的是 ksud boot-patch --kmi（会刷镜像，HONOR 上禁用）
  #      ⇒ 我们改走 late-load（同一条加载路径，**不碰镜像**）
  #
  #  标记 $RD/NO_LATE_LOAD 可回到手工 load_ko（A/B 对照）
  # ════════════════════════════════════════════════════════════════════════
  # ★ 2026-10-16 九改（YG 要求）：**默认关闭** late-load，回到手工 load_ko。
  #   理由（YG 的实测 + 我的时序核对）：
  #     · 命中那一轮（14:38:51）走的是手工 load_ko os9-selx11，loader 70,932 B
  #     · 开 late-load 之后的三轮（15:06/15:10/15:13）都没命中
  #     · 而且那三轮**从未执行到 late-load**（没 uid=0、无 mode=LATE-LOAD、无 KMI 列表）
  #       ⇒ 失败发生在 exploit 阶段，与 ko 无关
  #     · 但 late-load 确实是个"重"操作（ksuinit 内存加载 + 8 个内嵌 KMI 解析 +
  #       install/handle_updated_modules/prune_modules/post-fs-data/services）
  #       —— 它跑的时候内核已在崩死边缘，**不该默认开**
  #   ⇒ 默认 USE_LATE_LOAD=0（= 回到验证过的那条路）
  #      想试 ksud 内嵌的 UAPI5 ko 时：touch /data/local/tmp/ksu/TRY_LATE_LOAD
  USE_LATE_LOAD=0
  [ -f $RD/TRY_LATE_LOAD ] && USE_LATE_LOAD=1
  [ -f $RD/NO_LATE_LOAD ] && USE_LATE_LOAD=0     # 十三改：NO_LATE_LOAD 现在有实现
  if [ "$USE_LATE_LOAD" = "1" ]; then
    echo "mode=LATE-LOAD-KSUD (跳过手工 load_ko；由 ksud 取内嵌的 android14-6.1 UAPI5 ko 加载)"
    KSU_MODULE=""
    KSU_PARAMS=""
  fi

  # ★★★★ 2026-10-16 六改（YG 最终确认）：首选 = kernelsu-os9-selx11.ko ★★★★
  #
  # 为什么要它（两条都是硬证据）：
  #
  #  ① vermagic 与设备内核**逐字匹配**
  #       设备 : 6.1.157-android14-11-g7d3922fade43
  #       os9-selx11 : 6.1.157-android14-11-g7d3922fade43   ← 唯一匹配的
  #       success / kernelsu.ko / cga : 6.1.128              ← 差 29 个补丁版
  #     6.1.128 那两个虽然也能加载（load_ko 用 flags-only 宽松校验），但模块内部
  #     按 6.1.128 算出来的结构体偏移/内联补丁在 6.1.157 上是错的
  #     ⇒ 每次 execve 都在赌 ⇒ 真机实测 5/5 提权成功后复位。
  #
  #  ② 它是唯一 BakaSU(=ReSukiSU) 线的构建
  #       参数 24 个，独有 sc_enabled / sc_table / sc_execve_now|want /
  #       sc_faccessat_now|want / sc_newfstatat_now|want / sc_n_* / grant_apps / grant_log
  #       而 success / cga 只有 11 个参数（官方 KernelSU 3.2.5 线，无 sc_*）
  #     ⇒ YG 的 BakaSU 管理器对 os9-selx11 实测显示「工作中 [LKM] [越狱模式]」
  #       （内核驱动 v4.1.0 (30701/5) ↔ 管理器 v4.2.0-rc3 (35229/5)，UAPI 都是 5）
  #
  #  标记 $RD/FORCE_SUCCESS_KO 可切回 6.1.128 那两个做 A/B 对照（预期会复位）
#  ⚠️ 2026-10-16 修正：原写 PREFER_SUCCESS_KO，实际读的是 FORCE_SUCCESS_KO
  # ★★★★ 2026-10-16 十一改（YG 要求）：**锁定 os9-selx11** ★★★★
  #   锁定内核号：6.1.157-android14-11-g7d3922fade43
  #     vermagic = 6.1.157-android14-11-g7d3922fade43 SMP preempt mod_unload modversions aarch64
  #     md5      = f024ab980d591cc44388fc4eccf9d191
  #     UAPI     = 4（与 ReSukiSU 35171 管理器一致 ⇒ 无「需要更新内核」红条）
  #   为什么锁：这是**唯一**与真机内核逐字匹配的 ko，也是唯一实测能稳住的。
  #     · kernelsu_success.ko / kernelsu.ko / kernelsu_cga.ko → vermagic 6.1.128（差 29 补丁版）
  #     · 上面那几个只在"os9-selx11 缺失"时才作为兜底，不再作为首选。
  #   要临时切走做 A/B：touch /data/local/tmp/ksu/FORCE_SUCCESS_KO
  # ★ 十三改（审计修复）：让 A/B marker 真正生效 —— 之前 PREFER/FORCE 都被 os9 分支屏蔽
  # ★ 合并自 3.13.2：自备 ko 优先（kernelsu_custom.ko > kernelsu.ko），带 vermagic 硬校验
  if _pick_custom_ko; then
    KSU_MODULE=$CUSTOM_KO
    KSUD=$KSUD_BEST
    echo "mode=CUSTOM-OVERRIDE (module=$(basename $CUSTOM_KO))"
    echo "                  vermagic=${_cko_ver} 与内核 ${_cko_krel} 一致, size=${_cko_sz}B"
    echo "                  ⇒ 用户自备 ko 优先；删除该文件即回退内置首选"
  elif [ -f $RD/FORCE_SUCCESS_KO ] && [ -f $RD/kernelsu_success.ko ]; then
    KSU_MODULE=$RD/kernelsu_success.ko
    KSUD=$KSUD_BEST
    echo "mode=BVL175-SUCCESS-FORCED (marker FORCE_SUCCESS_KO; 6.1.128, A/B 对照)"
  elif [ -f $RD/NO_SUCCESS_KO ] && [ -f $RD/kernelsu_cga.ko ]; then
    KSU_MODULE=$RD/kernelsu_cga.ko
    KSUD=$KSUD_BEST
    echo "mode=CGA-FORCED (marker NO_SUCCESS_KO; 6.1.128, A/B 对照)"
  elif [ -f $RD/kernelsu-os9-selx11.ko ]; then
    KSU_MODULE=$RD/kernelsu-os9-selx11.ko
    KSUD=$KSUD_BEST
    _komd5=$(md5sum "$KSU_MODULE" 2>/dev/null | cut -d' ' -f1)
    echo "mode=OS9-SELX11 (module=kernelsu-os9-selx11.ko, md5=${_komd5:-unknown},"
    echo "                  vermagic 6.1.157-android14-11-g7d3922fade43 逐字匹配, UAPI 4, 锁定首选)"
  elif [ -f $RD/TRY_MISMATCHED_KO ] && [ -f $RD/kernelsu_success.ko ]; then
    KSU_MODULE=$RD/kernelsu_success.ko
    KSUD=$KSUD_BEST
    echo "mode=BVL175-SUCCESS-FORCED (module=kernelsu_success.ko, 6.1.128 A/B 对照, 预期复位)"
  elif [ -f $RD/kernelsu_success.ko ]; then
    KSU_MODULE=$RD/kernelsu_success.ko
    KSUD=$KSUD_BEST
    echo "mode=BVL175-SUCCESS (module=kernelsu_success.ko, 6.1.128 fallback)"
  else
    KSU_MODULE=$RD/kernelsu_success.ko
    KSUD=$RD/ksud
    echo "mode=CGA-3.2.5 (module=kernelsu.ko)"
  fi
  # ★ uapi 对不上就是管理器那句「需要更新内核」的全部原因：
  #   requiresNewKernel = managerUAPIVersion > kernelUAPIVersion
  #   选了 SukiSU/FinaSU（uapi6）却因为自动识别挑到别的 ko（uapi5）时最常见。
  # ★ 2.16：按**文件名通配**判 uapi，别再逐条枚举 —— 2.15 只写了 kernelsu_finasu.ko，
  #   新加的 kernelsu_finasu110.ko 掉进 `*) uapi=5` 分支，于是对着 FinaSU(uapi6)
  #   误报「uapi 不匹配，管理器会提示需要更新内核」。真机 v1.0.10 的 ko 实测
  #   KERNEL_SU_UAPI_VERSION = 6（CI 日志里 grep 得到），跟我们编的源码一致。
  case "$(basename "$KSU_MODULE")" in
    kernelsu_finasu*.ko|kernelsu_sukisu*.ko|kernelsu_suki421.ko) _kuapi=6 ;;
    kernelsu_basu420.ko)                     _kuapi=6 ;;
    kernelsu-os9-selx11.ko)                  _kuapi=4 ;;
    kernelsu_success.ko)                   _kuapi=2 ;;
    *)                                     _kuapi=5 ;;
  esac
  # 管理器 uapi：优先按 ksud 版本串判（隐藏包名的发行版靠不了包名）
  case "$(_mgr_ver)" in
    4.2.0*) _muapi=6 ;;   # 35252 = rc3 tag+81 (main)，main 的 uapi 是 6
    4.2.1*) _muapi=6 ;;
    *)
      case "$_cko_pkg" in
        com.sukisu.ultra|me.yuki.fina) _muapi=6 ;;
        com.resukisu.resukisu)         _muapi=4 ;;
        *)                             _muapi=5 ;;
      esac
      ;;
  esac
  if [ "$_kuapi" != "$_muapi" ]; then
    echo "  ⚠ uapi 不匹配：ko=$(basename "$KSU_MODULE")(uapi$_kuapi) / 管理器=${_cko_pkg:-自动}(uapi$_muapi)"
    echo "    ⇒ 管理器会提示「需要更新内核」。去 App 里手动选对管理器，别用自动识别"
  else
    echo "  [uapi] ko=$(basename "$KSU_MODULE") uapi=$_kuapi / 管理器=${_cko_pkg:-自动} uapi=$_muapi ✓"
  fi

  _extract_mgr_ksud
  # ★ grant_apps=Y —— BakaSU 的「越狱模式」（给应用授权 root）
  #   注：success ko 的 modinfo 里没有 grant_apps 这个 parmtype，
  #   但 v3.9.44 真机日志证明**内核会静默忽略不认识的参数**
  #   （那轮给 cga 传了 veto_reboot/veto_comm，它也没有这些参数，照样 load_ko_exit=0）
  #   ⇒ 对 success ko 传 grant_apps 是安全的；能生效就生效，不生效也不报错。
  # ★ 2026-10-16 三改：grant_apps 也**默认不加** —— 成功那 5 次里没有它。
  #   需要 BakaSU「越狱模式」时显式建 marker：
  #        touch $RD/ADD_GRANT_APPS
  # ★★★ 2026-10-16 十改（YG 实测反馈）：**默认打开 grant_apps=Y** ★★★
  #   为什么改回来：
  #     · 作者原始配方就是带它的（phone_load.sh:63 / load_selx11_full.sh:28）：
  #         load_ko kernelsu-os9-selx11.ko "allow_shell=1 log_reboot=1 grant_apps=Y"
  #     · 真机现象（2026-10-16 14:51 截图）：
  #         管理器显示「工作中 [LKM][越狱模式]」「1 个超级用户」
  #         但 **超级用户权限无法正常开启**
  #       ⇒ 这正对得上 grant_apps 的职责 —— 它把 App 自己加进内核 allowlist，
  #         是 BakaSU「越狱模式」给应用授权 root 的前提。
  #     · 之前"默认关掉"是因为成功那 5 次没传它 —— 但那 5 次我们从未验证过
  #       "超级用户能不能用"，只验证了"提权成功、模块 Live"。判据不足。
  #   要打开：touch /data/local/tmp/ksu/ADD_GRANT_APPS
#   ⚠️ 2026-10-16 修正：这里原写 NO_GRANT_APPS，但逻辑早已改成
#     "默认关 + ADD_GRANT_APPS 才开" ⇒ 旧注释是错的，已更正。
  # ★ 2026-10-16 十二改（撤回十一改的错误）：**默认关闭** grant_apps。
  #   反证（设备日志取证，successful run 143851 实测）：
  #     成功轮 ksu params = [allow_shell=1 log_reboot=1 bootid_ctl=0x… bootid_buf=0x…]
  #       ⇒ **4 个参数，没有 grant_apps**
  #     同一轮日志里那行："grant_apps: OFF by default (复原第一版；需要就建 ADD_GRANT_APPS)"
  #   另外：BakaSU 当前源码里**根本没有 grant_apps 这个参数**
  #     （源码搜 grant_apps = 0 处；只有 allow_shell，见 kernel/core/init.c:334）
  #     ⇒ grant_apps 只是老 ko（os9-selx11 那代）残留的、当前管理器不用的参数
  #   ⇒ 它既不必要、又可能引入副作用 ⇒ 默认关。
  #   要 A/B 试验：touch /data/local/tmp/ksu/ADD_GRANT_APPS
  USE_GRANT_APPS=0
  [ -f $RD/ADD_GRANT_APPS ] && USE_GRANT_APPS=1
  if [ "$USE_GRANT_APPS" = "1" ]; then
    P_GRANT_APPS=1    # 组装点会据此加 grant_apps=Y
    echo "grant_apps=Y 已加入（默认开启，BakaSU 越狱模式给应用授权 root）"
  else
    echo "grant_apps: OFF by default (复原第一版；需要就建 ADD_GRANT_APPS)"
  fi
  # ========================================================================
  # ★★ 2026-10-15：直接把 ksud 装到 /data/adb（**不调 ksud install**）★★
  #   为什么：加载带 su_compat 的模块后设备只活约 3 分钟就崩重启；而
  #     /data/adb 是持久分区 ⇒ 只要这一发把 ksud 拷进去，**下次提权后
  #     管理器就可能直接认**，不必再抢那 3 分钟窗口。
  #   为什么不用 `ksud install`：实测它会把 /data/adb/ksud 覆盖成
  #     154,248 B 的 bootctl（写坏）。这里只做幂等的 cp + 软链。
  #   标记 $RD/NO_KSUSDEPLOY 可跳过（A/B 对照）。
  # ========================================================================
  # ★ 优先用与模块配套的老 ksud（4,556,352 B，成功交付包那份）；没有才用 $RD/ksud
  # ★ 2026-10-16：优先用**与 4.2.0-rc3 管理器同代**的 ksud_resukisu
  #   （它就是从 ReSukiSU_v4.2.0-rc3_arm64.apk 的 lib/arm64-v8a/libksud.so 抽出来的，
  #     ELF e_type=3 DYN/PIE，有入口点，依赖 /system/bin/linker64 ⇒ 可直接执行）
  #   版本串 4.2.0 + 含 resukisu 字样 ⇒ 与管理器对齐，避免"旧代 ksud"的不一致。
  if [ -f $RD/ksud_resukisu ]; then KSUD_DEPLOY=$RD/ksud_resukisu
  elif [ -f $RD/ksud_success ]; then KSUD_DEPLOY=$RD/ksud_success
  else KSUD_DEPLOY=$RD/ksud; fi
  # ★★★ 2026-10-16 改：默认**不跑** ★★★
  #   cp 4.5MB + 建 3 个软链 + cp /dev/su + fsync 全在崩死窗口里 ⇒ 重 IO。
  #   需要"让管理器认"时：adb shell touch /data/local/tmp/ksu/KSUSDEPLOY
  # ★★ 2026-10-16（修「检测链路值没填」）★★
  #   App 的 awaitKsudResult() 读的是 **$RD/ksu_install.log** 的末尾行，
  #   并检查 `rc=124`（判断 ksud install 是否被 timeout 杀掉）。
  #   但本文件**从来不创建 ksu_install.log** —— 四阶段的 rc 只打到了 stdout。
  #   ⇒ 那个判定永远不成立，App 里 `rc-timeout` 那套分支是死的。
  #   现在：先把它建成"本轮已开始"的标记，下面每个结局都追加进去。
  : > $RD/ksu_install.log
  echo "=== ksud deploy @ boot=$BOOT ts=$(date +%H:%M:%S) ===" >> $RD/ksu_install.log
  if [ ! -f $RD/KSUSDEPLOY ]; then
    echo "ksud deploy: SKIPPED by default (重 IO；要让管理器认就 touch $RD/KSUSDEPLOY)"
    echo "action=skipped reason=default-off rc=0" >> $RD/ksu_install.log
  elif [ -f $RD/NO_KSUSDEPLOY ]; then
    echo "ksud deploy: SKIPPED (NO_KSUSDEPLOY marker)"
    echo "action=skipped reason=NO_KSUSDEPLOY rc=0" >> $RD/ksu_install.log
  elif [ -f "$KSUD_DEPLOY" ]; then
    mkdir -p /data/adb/ksu/bin /data/adb/ksu/log 2>/dev/null
    cp -f "$KSUD_DEPLOY" /data/adb/ksud 2>&1 && chmod 755 /data/adb/ksud 2>/dev/null
    ln -sfn /data/adb/ksud /data/adb/ksu/bin/ksud 2>/dev/null
    ln -sfn /data/adb/ksud /data/adb/ksu/bin/resetprop 2>/dev/null
    ln -sfn /data/adb/ksud /data/adb/ksud.ko 2>/dev/null || true
    cp -f "$KSUD_DEPLOY" /dev/su 2>/dev/null && chmod 755 /dev/su 2>/dev/null
        # ★ 十五改（审计修复）：cp 到 /dev/su 是 sucompat 的重定向目标，
        #   失败必须可见（原来 2>/dev/null + 只 ls 一次，可能显示旧文件）。
        if [ -x /dev/su ]; then
          echo "  /dev/su 就绪: $(wc -c < /dev/su 2>/dev/null) B"
        else
          echo "  !! /dev/su 落地失败 —— sucompat 将无法重定向到 ksud"
        fi
    echo "ksud deploy: /data/adb/ksud <- $KSUD_DEPLOY"
    echo "ksud deploy result:"; ls -l /data/adb/ksud 2>&1
    echo "ksud deploy bin:"; ls -l /data/adb/ksu/bin/ 2>&1 | head -8
    echo "ksud deploy /dev/su:"; ls -l /dev/su 2>&1
    # ★ 结局写进 App 会读的那个文件（App 用 tail -n 6 看最后几行）
    {
      echo "action=deploy src=$KSUD_DEPLOY"
      ls -l /data/adb/ksud 2>&1 | head -1
      ls -l /dev/su 2>&1 | head -1
      echo "rc=0"
    } >> $RD/ksu_install.log
  else
    echo "ksud deploy: 找不到 ksud_success / ksud，跳过"
    echo "action=skipped reason=no-ksud-binary rc=0" >> $RD/ksu_install.log
  fi
  # Reboot diagnostics / veto (kernel/supercall/supercall.c). The module logs
  # EVERY reboot() call (comm/pid/magic/cmd/arg) and can refuse one by breaking
  # its magic. Honor's bootfail logic (proc_upper_bf -> try_to_recovery) reboots
  # the whole device ~30-60s after a successful load, which throws the module
  # away - this is the one place that reboot can be stopped.
  # ★★ 2026-10-15：**默认开启** reboot veto（只挡 Honor 的 bootfail 恢复调用者）★★
  #   真机现象（用户报告，3 次）：提权成功后 10~60 秒**自动重启**；
  #     · 不打开任何 App，它过会自己重启
  #     · 甚至点「越狱」转圈时就重启
  #   这正是本节注释描述的那条链：
  #     模块加载成功 → 框架重启 → zygote 崩在 Honor 的 libheif.so 静态构造
  #     → bootfail 判 "Critical Process: zygote Crashed"（proc_upper_bf）
  #     → try_to_recovery → 整机重启（模块被丢掉）
  #   而阻止这个重启的**唯一**位置就是模块的 veto_reboot 参数。
  #
  #   为什么用 veto_comm=proc_upper_bf 而不是 veto_reboot=1：
  #     全拒会把 `adb reboot` / 正常重启也挡掉，出问题只能物理断电；
  #     按调用者过滤只挡 bootfail 那一个 comm，正常重启仍然可用。
  #
  #   ⚠ 想关掉（A/B 对照）：touch $RD/NO_VETO_REBOOT
  #   下列两个 marker 仍然可用，且优先级更高（可覆盖默认值）：
  #     marker VETO_REBOOT      -> refuse ALL reboots (device stays up, module kept;
  #                                note `adb reboot` stops working too, so recovery
  #                                from here needs a physical power cycle)
  #     marker VETO_REBOOT_COMM -> refuse only that caller's reboots (keeps
  #                                adb reboot working) - e.g. "proc_upper_bf"
  # ★★★ 2026-10-16 三改：**默认关闭 veto**，复原"第一版 100% 成功"的配置 ★★★
  #   真机证据（5 次成功的日志，参数一字不差）：
  #     ksu params: [allow_shell=1 log_reboot=1 bootid_ctl=0x… bootid_buf=0x…]
  #   ⇒ 成功那一版**根本没有** veto_reboot/veto_comm。
  #   而加了 veto 之后（v3.9.43 起）命中率掉到 0 —— 它虽然是内核参数，
  #   但会给 init_module 多传两个参数、改变内核参数解析路径与时间窗。
  #   ⇒ 默认不再加；需要挡 bootfail 重启时，显式建 marker：
  #        touch $RD/VETO_REBOOT_COMM   (内容写 proc_upper_bf)
  #     或 touch $RD/VETO_REBOOT        (全拒所有重启)
  if [ -f $RD/VETO_REBOOT ] && [ ! -f $RD/NO_VETO_REBOOT ]; then
    P_VETO_REBOOT=1    # 组装点会据此加 veto_reboot=1
    echo "reboot veto: enabled for ALL callers (marker VETO_REBOOT)"
  fi
  if [ -f $RD/VETO_REBOOT_COMM ]; then
    VC=$(cat $RD/VETO_REBOOT_COMM 2>/dev/null | tr -d ' \r\n')
    if [ -n "$VC" ]; then
      P_VETO_REBOOT=1; P_VETO_COMM="$VC"    # 组装点会据此加 veto_reboot=1 veto_comm=…
      echo "reboot veto: enabled for comm=$VC (marker VETO_REBOOT_COMM)"
    fi
  fi
  echo "reboot veto: OFF by default (复原第一版；需要就建 VETO_REBOOT_COMM)"
  # NOTE: we deliberately do NOT pass pristine_policy= any more.
  # selinux-hide-backup.patch's ksu_install_backup_sepolicy() then skips its
  # policydb_read()+policydb_load_isids() of the 1.97MB blob, and the only
  # consumer of that backup (selinux_hide) is disabled on CGA-W00 anyway.
  # Rationale: device-verified 2026-09-19 - with the module NOT loaded the device
  # survives 300s+ on the same boot, while every module load dies in 10-60s with
  # no oops; after disabling the syscall hooks and selinux_hide it still died, so
  # the remaining module-only init work (this policy parse and the reboot kprobe)
  # is what is being bisected.
  # ---- 2026-10-15 清理：原来这里有一段 bvl16 专用的 ko_patch 分支，★
  #   但它引用的 $RD/ko_patch 不在 APK 里（全仓库只有注释提到），条件恒假 ——
  #   已删除。bvl16 那条 ko 分支本身也一并删了（kernelsu_bvl16.ko 同样不存在）。
  # ---- 符号供给修复（2026-09-22 v3：泛化清单模式）----
  # Honor 从运行时 kallsyms 删了 commit_creds 等符号 → load_ko 只信
  # /proc/kallsyms 会 abort。ko_patch2 读符号地址清单（静态地址），把 ko 的
  # UND 符号全部 patch 成 SHN_ABS（+ 本 boot slide，live init_task 现算）。
  case "$KSU_MODULE" in
    *kernelsu-os9-selx11.ko)
      # ★ 作者配方（load_selx11_full.sh:21 / phone_load.sh:50）也给 os9-selx11 补符号。
      #   虽然它的 .symtab 未定义符号数为 0，但 ko_patch2 把符号 patch 成 SHN_ABS
      #   还能**绕开版本校验**，这是作者验证过的步骤。
      if [ -x $RD/ko_patch2 ] && [ -f $RD/next_sym_addr.txt ]; then
        IT=$(grep -w init_task /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
        # kptr_restrict=2 时给的是 0000000000000000（长度同样是 16）⇒ 必须排掉，否则 slide 全错
        case "$IT" in ""|0000000000000000|ffffffffffffffff) IT="";; esac
        if [ ${#IT} = 16 ]; then
          if $RD/ko_patch2 "$KSU_MODULE" "$IT" $RD/next_sym_addr.txt >> $RD/loadko_result.log 2>&1; then
            echo "ko_patch2: SHN_ABS applied for OS9-SELX11 (init_task=0x$IT)"
          else
            echo "ko_patch2: FAILED for OS9-SELX11 (see loadko_result.log)"
          fi
        else
          echo "ko_patch2: init_task not visible (len=${#IT}), skip"
        fi
      else
        echo "!! OS9-SELX11 需要 ko_patch2 + next_sym_addr.txt（作者配方步骤）"
      fi
      ;;
    *kernelsu_cga.ko)
      # ★★ 2026-10-16 修（关键）★★ **cga 必须套补丁**，不能跳过！
      #   证据：cga 未定义 221 个，比 success 多要 3 个：
      #     commit_creds / __change_memory_common / tracepoint_probe_register_prio
      #   而 commit_creds 被 Honor 从**运行时 kallsyms 删除**（项目注释实证），
      #   load_ko 只信 /proc/kallsyms ⇒ 必然 unresolved ⇒ **主动 abort**。
      #   这三个符号在 next_sym_addr.txt 里都有静态地址（精确匹配已确认）
      #   ⇒ 必须走 ko_patch2 把它们 patch 成 SHN_ABS。
      #   （success 那份不用 commit_creds，所以它才真的不需要补。）
      if [ -x $RD/ko_patch2 ] && [ -f $RD/next_sym_addr.txt ]; then
        IT=$(grep -w init_task /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
        # kptr_restrict=2 时给的是 0000000000000000（长度同样是 16）⇒ 必须排掉，否则 slide 全错
        case "$IT" in ""|0000000000000000|ffffffffffffffff) IT="";; esac
        if [ ${#IT} = 16 ]; then
          if $RD/ko_patch2 "$KSU_MODULE" "$IT" $RD/next_sym_addr.txt >> $RD/loadko_result.log 2>&1; then
            echo "ko_patch2: SHN_ABS applied for CGA-DP-TRY (init_task=0x$IT)"
          else
            echo "ko_patch2: FAILED for CGA-DP-TRY (see loadko_result.log)"
          fi
        else
          echo "ko_patch2: init_task not visible (len=${#IT}), skip"
        fi
      else
        echo "!! CGA-DP-TRY 需要 ko_patch2 + next_sym_addr.txt（补 commit_creds），"
        echo "!! 但缺件 ⇒ load_ko 会因 unresolved 主动 abort"
      fi
      ;;
    *kernelsu_success.ko)
      echo "ko_patch2: SKIPPED for BVL175-SUCCESS (它不需要 commit_creds，符号本来就全解析)"
      ;;
    *)
      # ── 自编 uapi5 ko（2026-10-20）──────────────────────────────────────
      #  设备内核只导出 kallsyms_lookup_name / register_kprobe，这两个 ko 各有
      #  226~228 个「有但没导出」的符号（path_umount / selinux_state / alloc_uid …）
      #  ⇒ 不补符号必然 Unknown symbol；补了以后内核看到的是 SHN_ABS 绝对地址，
      #     连 __versions 校验也一并绕过（作者配方）。
      #  清单必须用「标准基准」(0xffffffc008000000)：ko_patch2 的 slide 是拿
      #  硬编码 init_task 0xffffffc00a2017c0 跟 live init_task 比出来的。
      _self_ko=0
      # ★ 2.16（真机踩到）：这里原来是**逐条枚举**文件名，新加的 kernelsu_finasu110.ko
      #   不在表里 ⇒ _self_ko=0 ⇒ ko_patch2 被跳过 ⇒ load_ko 只剩 /proc/kallsyms 可查，
      #   而荣耀把 commit_creds 从运行时 kallsyms 删了（本机 grep 只有 override_creds /
      #   revert_creds / prepare_creds，没有 commit_creds）⇒ UNRESOLVED ⇒ 主动 abort，
      #   日志表现就是 modules=0 但 M6_VERDICT: ROOT。改成通配，加新 ko 不会再漏。
      case "$(basename "$KSU_MODULE")" in
        # ★★ 2.40：kernelsu_suki421.ko / kernelsu_basu420.ko 原来**不在**白名单里 ★★
        #   ⇒ _self_ko=0 ⇒ 不打 ko_patch2 ⇒ ko 的 UND 符号（Honor 从运行时 kallsyms 删了
        #   commit_creds 等）全是 0 地址 ⇒ insmod 直接 exit=3（实测 21:07 那轮：
        #   load_ko_exit=3、/proc/modules 里没有 kernelsu、管理器说"有 root 但没有内核"）。
        #   现在按前缀通配，以后再加新 ko 不会重踩。
        kernelsu_custom.ko|kernelsu_ksu331.ko|kernelsu_next.ko|\
        kernelsu_suk*.ko|kernelsu_finasu*.ko|kernelsu_basu*.ko) _self_ko=1 ;;
      esac
      _symlist=$RD/next_sym_addr.txt
      if [ "$_self_ko" = "1" ] && [ -f $RD/next_sym_addr_uapi5.txt ]; then
        _symlist=$RD/next_sym_addr_uapi5.txt
      fi
      _do_patch=0
      [ "$_self_ko" = "1" ] && _do_patch=1
      [ -f $RD/PATCH_CUSTOM_KO ] && _do_patch=1
      if [ "$_do_patch" = "1" ] && [ -x $RD/ko_patch2 ] && [ -f "$_symlist" ]; then
        IT=$(grep -w init_task /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
        # kptr_restrict=2 时给的是 0000000000000000（长度同样是 16）⇒ 必须排掉，否则 slide 全错
        case "$IT" in ""|0000000000000000|ffffffffffffffff) IT="";; esac
        if [ ${#IT} = 16 ]; then
          # ★ 2026-10-24：ko_patch2 是**就地**改（symtab 写 SHN_ABS + 本 boot slide）。
          #   若直接改 $RD 里那份，下次启动再 patch 就会在已加过 slide 的值上再加一次
          #   ⇒ 地址全错。所以每轮都从原件复制一份 .run_<name> 去 patch，原件保持干净。
          _pcopy="$RD/.run_$(basename "$KSU_MODULE")"
          # ★★ 2.53（吸收 MagicRoot 1.0.3）patch 结果缓存 ★★
          #   key = boot_id + live init_task(slide) + uname -r + ko 名/size/mtime
          #        + 符号清单 mtime + ko_patch2 mtime
          #   boot_id 变了（真重启）或 slide 变了（不同一发）都会自动失效；
          #   同一发里重复点提权不再重复 patch（原来每次 cp 7MB + 改 symtab）。
          _bid=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '-')
          _key="$_bid|$IT|$(uname -r 2>/dev/null)|$(basename "$KSU_MODULE")|$(stat -c '%s:%Y' "$KSU_MODULE" 2>/dev/null)|$(stat -c '%Y' "$_symlist" 2>/dev/null)|$(stat -c '%Y' "$RD/ko_patch2" 2>/dev/null)"
          if [ -s "$_pcopy" ] && [ -f "$RD/.kopatch_key" ] && \
             [ "$(cat "$RD/.kopatch_key" 2>/dev/null)" = "$_key" ]; then
            KSU_MODULE="$_pcopy"
            echo "ko_patch2: 缓存命中（同 boot 同 slide）⇒ 跳过 $(basename "$_pcopy")"
          elif cp -f "$KSU_MODULE" "$_pcopy" 2>/dev/null; then
            chmod 644 "$_pcopy" 2>/dev/null
            if $RD/ko_patch2 "$_pcopy" "$IT" "$_symlist" >> $RD/loadko_result.log 2>&1; then
              KSU_MODULE="$_pcopy"
              printf '%s' "$_key" > "$RD/.kopatch_key" 2>/dev/null
              echo "ko_patch2: SHN_ABS applied for $(basename "$_pcopy") (init_task=0x$IT, 清单=$(basename "$_symlist"))"
            else
              rm -f "$_pcopy"
              echo "ko_patch2: FAILED for $(basename "$KSU_MODULE") (see loadko_result.log)"
            fi
          else
            echo "ko_patch2: 复制失败 ⇒ 跳过（$KSU_MODULE）"
          fi
        else
          echo "ko_patch2: init_task not visible (len=${#IT}), skip"
        fi
      else
        echo "ko_patch2: SKIPPED (marker 未开或缺件)"
      fi
      ;;
  esac
  if [ "$USE_LATE_LOAD" != "1" ]; then
    # ══════════════════════════════════════════════════════════════════════════
  # ★★★★ 2026-10-16 十四改（第 3 路调研的决定性发现）：创建 HOOKS_ON ★★★★
  #
  #  ko 里的实测字符串（kernelsu-os9-selx11.ko, md5 f024ab980d591cc4…）：
  #    @0x1c378  "/data/local/tmp/ksu/HOOKS_ON"
  #    @0x1f278  "hook_manager: DISABLED (CGA-W00, no HOOKS_ON marker),
  #                no syscall hooks registered"
  #    @0x201c0  "syscall hooks DISABLED (CGA-W00): no HOOKS_ON marker,
  #                dispatcher not installed"
  #    @0x20705  "syscall hooks ENABLED (HOOKS_ON marker)"
  #    @0x1d02e  "sucompat: direct syscall-table hooks installed
  #                (execve/faccessat/newfstatat)"
  #
  #  ⇒ **没有这个 marker，ko 就不装 syscall hook** ⇒ sucompat 失效
  #    ⇒ su 不会被重定向到 ksud ⇒ **授权写进去了也拿不到 root**
  #    （这正对得上「管理器显示 1 个超级用户，但权限无法开启」）
  #
  #  ⚠️ 注意：RouteKit 的 marker 清理清单里**绝对不能有 HOOKS_ON**
  #     —— 它是要"存在"的，不是要清理的。
  # ══════════════════════════════════════════════════════════════════════════
  # ★★★ fix2-20261017（真机日志定案，run-20261017-155727）：HOOKS_ON **不再默认创建** ★★★
  #
  #  那一轮的事实（m6.zip 里的 kmsg_cap.txt）：
  #    KernelSU: sucompat: enabled (no SUCOMPAT_OFF marker)
  #    KernelSU: sucompat: direct syscall-table hooks installed (execve/faccessat/newfstatat)
  #    KernelSU: hook_manager: ksu_hook_manager_init called (HOOKS_ON marker)
  #  而同一轮的 dc_ksu.log 是 **M6_VERDICT: ROOT**、load_ko_exit=0、模块 Live ——
  #  提权完全成功；可是 App 的 Shizuku shell 从 15:59:35 起每次 spawn 都 7 秒超时
  #  （日志里 96 轮 `mod=""`，没有任何一行 [套件] 输出），8 分钟后判「观察超时」。
  #  ⇒ 装上 execve/faccessat/newfstatat 的 syscall 钩子之后，**App 的 shell 通道被拖死**，
  #    管理器也因为自己 exec 被钩住而一直「Searching manager / got magic」但从不 Crowning，
  #    于是 sucompat 永远等不到授权 ⇒ 死锁。内核成了 root，App 以为失败。
  #
  #  为什么关掉是安全的：BVL 那套「rootshell 每 3s 给 shell/granted app 发 init_cred」
  #  与这个 marker 无关（2026-10-16 那台没有 HOOKS_ON 的 boot 里，adb shell 6 秒就 uid=0）；
  #  给 App 用的 su 走用户态垫片（enable_su.sh / install-su.sh），不依赖 sucompat。
  #
  #  真要用 sucompat（/system/bin/su 重定向）：touch $RD/WANT_SUCOMPAT。
  if [ -f $RD/WANT_SUCOMPAT ]; then
    touch $RD/HOOKS_ON 2>/dev/null; rm -f $RD/SUCOMPAT_OFF 2>/dev/null
    echo "HOOKS_ON 已创建（WANT_SUCOMPAT）—— ⚠ 会装 execve 钩子，App 的 shell 通道可能被拖死"
  else
    rm -f $RD/HOOKS_ON 2>/dev/null
    touch $RD/SUCOMPAT_OFF 2>/dev/null
    echo "syscall hooks: OFF（默认）· SUCOMPAT_OFF 已建 —— shell 通道保持可用，su 走用户态垫片"
  fi

  # ══════════════════════════════════════════════════════════════════════════
  # ★★★★ 2026-10-16 十五改：接入 sc_*（直接改 syscall 表那条路）★★★★
  #
  #  为什么：ko 里有第二套 su 机制，且有明确的失败串：
  #     "sucompat: direct syscall-table hooks installed (execve/faccessat/newfstatat)"  ← 成功
  #     "sucompat: sys_call_table not resolved, giving up"                              ← 失败
  #  参数（24 项里的私有组）：sc_enabled / sc_table / sc_execve_now|want /
  #     sc_faccessat_now|want / sc_newfstatat_now|want / sc_n_execve|faccessat|newfstatat
  #  符号佐证：patch_syscall_table / ksu_syscall_table / ksu_syscall_table_hook
  #
  #  ⇒ 它失败的核心原因就是解析不到 sys_call_table。
  #    而此刻我们**已经是 uid=0**（脚本开头有断言），能读 /proc/kallsyms
  #    ⇒ 把地址通过 sc_table 传给它，正好解这个结。
  #
  #  另：HOOKS_ON（十四改）管的是 kprobe/tracepoint 那条路；sc_* 是另一条。
  #     两条都开 = 双保险。
#   ★ 用法：adb shell touch /data/local/tmp/ksu/SC_HOOKS    （**开** sc_*，默认关）
#   ★ 用法：adb shell touch /data/local/tmp/ksu/NO_SC_HOOKS （**关** sc_*，冗余保险）
  # ══════════════════════════════════════════════════════════════════════════
  # ★★ 2026-10-16（关键修复）：**sc_* syscall hook 改为默认关** ★★
  #
  #   铁证（2026-10-16 21:30 那一轮）：
  #     提权**完全成功**（M6_VERDICT: ROOT / modules=1 root=1 physrw=1
  #     permissive=1），模块 Live，ksud 与 /dev/su 都铺好了 ——
  #     但**同一份 App 日志里**：
  #         Cannot run program "/system/bin/sh":
  #             **error=38, Function not implemented**   （38 = ENOSYS）
  #         状态卡：当前无 root（none）⇒ 界面报失败
  #         连「重启设备」都失败（同样 error=38）
  #
  #   原因：sc_enabled=1 给 ko 装上了 syscall 表 hook，而 ko 的
  #        ksu_hook_execve / ksu_hook_faccessat / ksu_hook_newfstatat
  #        对**未授权进程**返回 ENOSYS
  #        ⇒ App（untrusted_app）连一个 shell 进程都起不来
  #        ⇒ 整条 Shizuku/shell 通道死掉。
  #
  #   对照：历史上**唯一成功过**的那次（boot 1c1d4d16）用的是
  #        allow_shell=1 log_reboot=1 bootid_ctl=… bootid_buf=…
  #        —— **没有 sc_***。也就是说这一组属于"没验证过却默认开"。
  #
  #   ⇒ 改为 opt-in。默认**不加** sc_enabled / sc_table。
  USE_SC=0
  [ -f $RD/SC_HOOKS ] && USE_SC=1
  [ -f $RD/NO_SC_HOOKS ] && USE_SC=0
  if [ "$USE_SC" = "1" ]; then
    SCT=$(grep -w sys_call_table /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
    # ★ 十五改（审计修复）：原来只挡"恰好 16 个 0"，漏了 0x 前缀 / 8 位 / 低地址。
    #   sc_table 会被 ko 当真地址解引用（PTE-flip 写）⇒ 错值可致 panic。
    #   判据收紧：必须是 16 位十六进制、不含 0x、且像内核高地址（前 4 位 ffff 或 ffffff）。
    case "$SCT" in
      0x*|"") SCT="" ;;
      *[!0-9a-fA-F]*) SCT="" ;;
    esac
    if [ ${#SCT} = 16 ]; then
      case "$SCT" in
        0000000000000000|ffffffffffffffff) SCT="" ;;
        ffff*|ffffff*) : ;;
        *) echo "  sc_table 校验未过（不像内核地址）：$SCT ⇒ 不传"; SCT="" ;;
      esac
    else
      SCT=""
    fi
    if [ ${#SCT} = 16 ]; then
      P_SC_ENABLED=1; P_SC_TABLE="$SCT"    # 组装点会据此加 sc_enabled/sc_table
      echo "sc_* 已加入：sc_enabled=1 sc_table=0x$SCT（= kallsyms 里的 sys_call_table）"
    else
      P_SC_ENABLED=1    # 组装点会据此加 sc_enabled=1
      echo "sc_* 已加入：sc_enabled=1（但 kallsyms 里 sys_call_table 不可见 ⇒ 未传 sc_table）"
    fi
  else
    echo "sc_*：OFF（marker NO_SC_HOOKS）"
  fi

  echo "ksu params: [$KSU_PARAMS]"
    # 十三改（审计修复）：原来用 > 截断，把 ko_patch2 的诊断冲掉了；改成保留
  # ★ 整合：**在这里**（且只在这里）把标志组装成最终参数串
  build_ksu_params
  echo "  [组装点] KSU_PARAMS=[$KSU_PARAMS]"

  # ★ 2026-10-24：load_ko 曾经**不在载荷里**（老包 1.2 就是），只能靠设备上残留的旧文件，
  #   一旦 RD 被重建（root 属主自愈 rm -rf RD）就变成 "exec ... No such file or directory"，
  #   load_ko_exit=127，ko 永远装不进内核、却仍判 ROOT。现在缺件就直接说清楚。
  if [ ! -x "$RD/load_ko" ]; then
    echo "!! 缺 $RD/load_ko（载荷未推到或被清掉）⇒ 本轮 ko 不可能装进内核"
    echo "!! 处理：回 App 点「部署载荷」，或用完整 APK 重装后再提权"
  fi
  # ★★★ 2026-10-24：装载前先 fork 一个 root watcher ★★★
  #   实测（boot 0526cd90 / 前一 boot）：load_ko 成功后本进程会被模块踢出 root ——
  #   su_cred 的 task_work 回滚 cred + FinaSU 的 selinux_hide/policy 一装，
  #   exploit 塞给 cred 的伪造 SID 就失效 ⇒ 之后 open/exec/access 全线 Permission denied：
  #     can't open /proc/modules / can't create /data/local/tmp/xxx.tmp / getenforce 不可用
  #   于是 MOD 误判 0、ksud 部署与"切回 Enforcing"整段跳过、selfcheck 全空。
  #   ⇒ 趁现在还是 uid0，先 fork 一个后台子进程，等模块出现后由它做收尾。
  #   关掉：touch $RD/NO_POSTLOAD_WATCHER
  if [ ! -f "$RD/POSTLOAD_WATCHER" ]; then
    # ★ 2026-10-24（2.10 稳定性）：默认关闭。
    #   实测它是死代码（子进程继承同一份伪造 cred，模块一装一起失效，只写出第一行），
    #   但会在装载后留一个每秒读 /proc/modules 的后台循环最多 180s。
    #   老壳 3.16.34 完全没有这段。要复现旧行为：touch $RD/POSTLOAD_WATCHER
    echo "postload watcher: 默认关闭（要开：touch \$RD/POSTLOAD_WATCHER）"
  else
    _orig_enf=$(cat /sys/fs/selinux/enforce 2>/dev/null)
    [ -n "$_orig_enf" ] || _orig_enf=0
    RD="$RD" ORIG_ENF="$_orig_enf" setsid sh -c '
      PLOG="$RD/postload_root.log"
      : > "$PLOG" 2>/dev/null
      say() { echo "$@" >> "$PLOG" 2>/dev/null; echo "$@" >> "$RD/dc_ksu.log" 2>/dev/null; }
      say "=== postload watcher  uid=$(id -u 2>/dev/null) ctx=$(cat /proc/self/attr/current 2>/dev/null) ==="
      _n=0; _live=0
      while [ "$_n" -lt 180 ]; do
        _f=0
        while IFS= read -r _l; do
          case "$_l" in *[Kk]ernel[Ss][Uu]*) _f=1; break ;; esac
        done < /proc/modules 2>/dev/null
        if [ "$_f" = "1" ]; then _live=1; break; fi
        _n=$((_n + 1)); sleep 1
      done
      if [ "$_live" != "1" ]; then
        say "[watcher] module NOT LIVE（等 ${_n}s 放弃）⇒ 不做收尾"
        touch "$RD/POSTLOAD_FAIL" 2>/dev/null
        say "=== postload end ==="
        exit 0
      fi
      say "[watcher] module LIVE（等 ${_n}s）"
      for _p in su_cred su_check su_path mgr_pkgs; do
        say "[watcher]   $_p = $(cat /sys/module/kernelsu/parameters/$_p 2>/dev/null)"
      done
      if [ ! -s /dev/su ]; then
        for _c in "$RD/ksud_mgr" /data/adb/ksud "$RD/ksud_resukisu" "$RD/ksud_success" "$RD/ksud"; do
          [ -x "$_c" ] || continue
          cp -f "$_c" /dev/su 2>/dev/null && chmod 755 /dev/su 2>/dev/null || continue
          say "[watcher] /dev/su ← $_c（$(wc -c < /dev/su 2>/dev/null || echo ?) B）"
          break
        done
      else
        say "[watcher] /dev/su 已存在（$(wc -c < /dev/su 2>/dev/null || echo ?) B）"
      fi
      chcon u:object_r:ksu_file:s0 /dev/su 2>/dev/null
      _suctx=$(ls -Z /dev/su 2>/dev/null)
      case "$_suctx" in
        *ksu_file*) say "[watcher] /dev/su 标签 OK" ;;
        *)          say "[watcher] !! /dev/su 标签异常：${_suctx:-读不到}" ;;
      esac
      for _c in "$RD/ksud_mgr" "$RD/ksud_resukisu" "$RD/ksud_success"; do
        [ -x "$_c" ] || continue
        mkdir -p /data/adb 2>/dev/null
        cp -f "$_c" /data/adb/ksud.new 2>/dev/null && chmod 755 /data/adb/ksud.new 2>/dev/null || continue
        mv -f /data/adb/ksud.new /data/adb/ksud 2>/dev/null || continue
        say "[watcher] /data/adb/ksud ← $_c（$(wc -c < /data/adb/ksud 2>/dev/null || echo ?) B）"
        break
      done
      if [ "$ORIG_ENF" = "1" ]; then
        _cur=$(cat /sys/fs/selinux/enforce 2>/dev/null)
        case "$_suctx" in
          *ksu_file*)
            if [ "$_cur" != "1" ]; then
              setenforce 1 2>/dev/null || echo 1 > /sys/fs/selinux/enforce 2>/dev/null
              say "[watcher] SELinux $_cur → $(cat /sys/fs/selinux/enforce 2>/dev/null)"
            else
              say "[watcher] SELinux 已是 Enforcing"
            fi
            ;;
          *) say "[watcher] /dev/su 标签没确认 ⇒ 不切严（防自锁）" ;;
        esac
      else
        say "[watcher] 本轮开跑时是 Permissive（原值 0）⇒ 不动 SELinux"
      fi
      _sb=$(grep -c kernelsu /proc/modules 2>/dev/null)
      say "[watcher] /proc/modules kernelsu 行数=$_sb"
      touch "$RD/POSTLOAD_DONE" 2>/dev/null
      say "=== postload end ==="
    ' </dev/null >/dev/null 2>&1 &
    echo "postload watcher: started as root (pid=$!) — 装载后由它做收尾"
  fi

  { echo "=== load_ko 调用（第 N 次） ==="; } >> $RD/loadko_result.log
    # ★★★★ 2.45（22:38 实证：load_ko_exit=0、模块 Live，但装载后本进程 exec 全废）★★★★
    #   现象：`ksud post-fs-data/install/services rc=127`、`/system/bin/su` 没生成、
    #   内核侧 appid='0' 永远没被加冕 ⇒ SukiSU「有 root 权限但未检测到内核」。
    #   根因不是 ko，也不是参数 —— 是**跑 loader 的这个进程自己在装载后失权**
    #   （它被 exploit 改过 cred，insmod 之后 open/exec 都被 ko 的钩子挡掉）。
    #   ⇒ 装载**之前**先 fork 一个独立进程（setsid，自己的 cred 是干净的），
    #     它等几秒后替我们干装载后的活：ksud 三步 + set-manager 加冕 + 造 su。
    # ★ 2.50：helper 实测无效（子进程继承被 exploit 改坏的 cred，连日志都写不出来），改默认关
    if [ -x "$RD/ksud" ] && [ -f "$RD/POSTLOAD_HELPER" ]; then
      cat > "$RD/.postload_helper.sh" <<'EOS'
#!/system/bin/sh
RD=/data/local/tmp/route/m6
L=$RD/postload_helper.log
sleep "${1:-12}"
{
  echo "=== helper start $(date) uid=$(id -u 2>/dev/null) ctx=$(cat /proc/self/attr/current 2>/dev/null) ==="
  grep -c kernelsu /proc/modules 2>/dev/null | sed 's/^/  modules_line=/'
  for k in post-fs-data install services; do
    "$RD/ksud" "$k" >/dev/null 2>&1; echo "  ksud $k rc=$?"
  done
  "$RD/ksud" su --install >/dev/null 2>&1; echo "  ksud su --install rc=$?"
  [ -x /dev/su ] && { /dev/su debug set-manager com.sukisu.ultra >/dev/null 2>&1; echo "  set-manager rc=$?"; }
  echo "  --- 关键路径 ---"
  ls -l /dev/su /system/bin/su 2>&1 | sed 's/^/  /'
  echo "  id=$(id 2>&1 | head -1)"
  echo "=== helper end ==="
} >> "$L" 2>&1
EOS
      chmod 755 "$RD/.postload_helper.sh" 2>/dev/null
      chown 0:0 "$RD/.postload_helper.sh" 2>/dev/null
      setsid sh "$RD/.postload_helper.sh" 12 </dev/null >/dev/null 2>&1 &
      echo "postload helper: started as pid=$!（装载后由它跑 ksud/加冕，日志 $RD/postload_helper.log）"
    fi
    # ══════════════════════════════════════════════════════════════════════
    # ★★ 2.54（吸收 MagicRoot 1.0.3 的 MODULE_LIVE_FAST_REPAIR）★★
    #   同一个 boot 里第二次点提权时，kernelsu 已经 Live ⇒ insmod 必然 EEXIST，
    #   再跑一遍整条链只是白花几分钟（还可能把已活的模块搞崩）。
    #   这里直接走用户态修复：ksud 三阶段 + APK 路径 set-manager。
    #   修不好就明确告诉用户「模块已 Live，要换 ko 必须重启」，不再假装在装。
    #   想强制跑完整链路：touch $RD/FORCE_FULL
    # ══════════════════════════════════════════════════════════════════════
    if [ ! -f "$RD/FORCE_FULL" ] && grep -q kernelsu /proc/modules 2>/dev/null; then
      echo "=== 模块已 Live（同 boot 二次提权）⇒ 跳过 insmod，走用户态修复 ==="
      _rlk=""
      for _k in "$RD/ksud_mgr" /data/adb/ksu/bin/ksud /data/adb/ksud "$RD/ksud_resukisu"; do
        [ -x "$_k" ] && { _rlk=$_k; break; }
      done
      _rok=0
      if [ -n "$_rlk" ]; then
        echo "  [reuse] 用 $(basename "$_rlk") 做修复"
        for _s in post-fs-data install services; do
          timeout 30 "$_rlk" "$_s" >/dev/null 2>&1
          _r=$?; echo "  [reuse] ksud $_s rc=$_r"
          [ "$_r" = "0" ] && _rok=$((_rok+1))
        done
        _rapk=""
        if [ -n "${_mpk:-}" ]; then
          for _d in /data/app/*/"$_mpk"-*/base.apk /data/app/*/"$_mpk"*/base.apk; do
            [ -f "$_d" ] && { _rapk=$_d; break; }
          done
        fi
        if [ -n "$_rapk" ]; then
          timeout 20 "$_rlk" debug set-manager "$_rapk" >/dev/null 2>&1
          echo "  [reuse] debug set-manager($_rapk) rc=$?"
        fi
      else
        echo "  [reuse] 没有可执行 ksud ⇒ 只做状态汇报"
      fi
      echo "  [reuse] 模块行=$(grep kernelsu /proc/modules 2>/dev/null | head -1)"
      if [ "$_rok" -lt 1 ]; then
        echo "  [reuse] !! 修复全部失败（exec 已被装载后的钩子挡掉）"
        echo "  [reuse] ⇒ 要换 ko / 重装，必须重启后再来（同 boot 无法替换 Live 模块）"
      else
        echo "  [reuse] ✓ 修复完成；要换别的 ko 仍需重启"
      fi
      _sweep_orphans
      echo "=== 已 Live 复用链结束（未 insmod） ==="
      exit 0
    fi

    _reap_legacy_daemons
    _sweep_orphans diag
    timeout 180 $RD/load_ko "$KSU_MODULE" "$KSU_PARAMS" >> $RD/loadko_result.log 2>&1
    LOAD_RC=$?
    # ★ 2.67：装载后**不再**扫孤儿。
    #   /proc 对本进程树已不可读（access/stat 全废），扫也扫不到；
    #   而 2.66 用的是 `$(...)`（会 fork），在 syscall 钩子被打断的进程树里 fork
    #   风险太高 —— 实测出现过"切严格成功后卡住"。孤儿在装载前就已存在，
    #   所以只在 insmod 之前扫一次就够。
    echo "load_ko_exit=$LOAD_RC"

    # ★ 2.47 保险：万一 ksu_debug_manager_appid 不是这个 ko 认的 insmod 参数
    #   （insmod 会对未知参数直接 EINVAL），就把它剥掉重试一次 —— 不能因为
    #   一个调试参数把整发废掉。
    if [ "$LOAD_RC" != "0" ] && printf '%s' "$KSU_PARAMS" | grep -q ksu_debug_manager_appid; then
      echo "!! 带 ksu_debug_manager_appid 装载失败（rc=$LOAD_RC）⇒ 剥掉该参数重试一次"
      _kp2=$(printf '%s' "$KSU_PARAMS" | sed 's/ ksu_debug_manager_appid=[0-9]*//g')
      timeout 180 $RD/load_ko "$KSU_MODULE" "$_kp2" >> $RD/loadko_result.log 2>&1
      LOAD_RC=$?
      echo "   重试 load_ko_exit=$LOAD_RC"
      [ "$LOAD_RC" = "0" ] && KSU_PARAMS="$_kp2"
    fi
    # ★★ 2.41：失败时把 load_ko 自己的诊断打进主日志 ★★
    #   它才是唯一说真话的地方（`[-] module load failed: errno=%d (%s)` /
    #   `[-] N symbols unresolved` / `ENOEXEC: vermagic` / `EPERM: lockdown`）。
    #   以前只在 loadko_result.log 里，得单独 pull，排查全靠猜。
    # ★★ 2.44：**成功也要**抓 dmesg —— ko 初始化时会自己打印
    #   "syscall hooks ENABLED (HOOKS_ON marker)" / "DISABLED (no HOOKS_ON marker)"、
    #   "hook_manager: ..."，这是唯一能确认「钩子到底装没装」的地方。
    if [ "$LOAD_RC" = "0" ]; then
      echo "--- dmesg (kernelsu/ksu) ---"
      dmesg 2>/dev/null | grep -iE "kernelsu|ksu_|ksu-|hook_manager|syscall hooks|supercall|sucompat" \
        | tail -40 | sed 's/^/    /'
      echo "--- end dmesg ---"
    fi
    if [ "$LOAD_RC" != "0" ]; then
      echo "--- loadko_result.log tail ---"
      tail -25 "$RD/loadko_result.log" 2>/dev/null | sed 's/^/    /'
      echo "--- end loadko_result ---"
      echo "--- dmesg (module) tail ---"
      dmesg 2>/dev/null | grep -iE "kernelsu|module|vermagic|Unknown symbol|taint" | tail -15 | sed 's/^/    /'
      echo "--- end dmesg ---"
    fi

    # ★ 2026-10-20 诊断：抓内核侧 ksu-dbg 打印（这轮 ko 带调试打印）
    if [ "$LOAD_RC" = "0" ]; then
      sleep 2
      dmesg 2>/dev/null > $RD/kmsg_full.txt 2>/dev/null
      chmod 644 $RD/kmsg_full.txt $RD/ksu_dbg.log 2>/dev/null
      grep "ksu-dbg" $RD/kmsg_full.txt 2>/dev/null | head -60 > $RD/ksu_dbg_only.log 2>/dev/null
      grep -E "ksu-dbg|KernelSU" $RD/kmsg_full.txt 2>/dev/null | grep -v "tp_marker" | tail -60 > $RD/ksu_dbg.log 2>/dev/null
      _dn=$(wc -l < $RD/ksu_dbg_only.log 2>/dev/null || echo 0)
      echo "  [dmesg] ksu-dbg 打印 $_dn 行 → $RD/ksu_dbg_only.log（全量 dmesg 在 kmsg_full.txt）"
      _probe_exec "加载后"
      grep -E "ksu-dbg (ENTER|DISP)" $RD/ksu_dbg_only.log 2>/dev/null | head -8 | sed 's/^/    /'
    fi
  
    # ★★ 2026-10-16 新增：加载失败时**自动换 ko 重试** ★★
    #   为什么：load_ko 失败（unresolved / init_module 报错）本身不会换 ko，
    #   而首选的 os9-selx11 一旦失败，这一发就废了 —— 可每 boot 只能打一发。
    #   候选顺序：os9-selx11（首选）→ success → cga → kernelsu.ko
    # ★ 2026-10-16 四改：回退**默认开启** —— 只在"首选加载失败"时才跑，
    #   每 boot 只有一发，白白浪费太亏。想关掉就建 marker NO_RETRY_OTHER_KO。
    # ★★★ 2026-10-16 改：默认**不做**回退 ★★★
    #   它会在已经崩死边缘的内核上再跑最多 3 次 load_ko（每次 timeout 180）
    #   + ko_patch2 ⇒ 极重，且 6.1.128 的 ko 本来就会崩，回退没有意义。
    #   需要时：touch $RD/RETRY_OTHER_KO
    if [ ! -f $RD/MINIMAL ] && [ -f $RD/RETRY_OTHER_KO ] && [ ! -f $RD/NO_RETRY_OTHER_KO ] && [ "$LOAD_RC" != "0" ] \
       && ! grep -q kernelsu /proc/modules 2>/dev/null; then
      echo "!! 首选模块加载失败（rc=$LOAD_RC）—— 进入自动回退"
      for CAND in $RD/kernelsu_success.ko $RD/kernelsu_cga.ko; do
        [ -f "$CAND" ] || continue
        [ "$CAND" = "$KSU_MODULE" ] && continue
        echo "--- 回退尝试: $CAND ---"
        # 回退的 ko 都用 ko_patch2 补一遍（幂等）
        if [ -x $RD/ko_patch2 ] && [ -f $RD/next_sym_addr.txt ]; then
          IT2=$(grep -w init_task /proc/kallsyms 2>/dev/null | head -1 | cut -d' ' -f1)
          [ ${#IT2} = 16 ] && $RD/ko_patch2 "$CAND" "$IT2" $RD/next_sym_addr.txt >> $RD/loadko_result.log 2>&1
        fi
        timeout 180 $RD/load_ko "$CAND" "$KSU_PARAMS" >> $RD/loadko_result.log 2>&1
        RC2=$?
        echo "  回退 load_ko_exit=$RC2"
        if [ "$RC2" = "0" ] && grep -q kernelsu /proc/modules 2>/dev/null; then
          echo "  ★ 回退成功：$CAND"
          KSU_MODULE=$CAND
          break
        fi
      done
    fi
    else
    echo "--- 跳过手工 load_ko（USE_LATE_LOAD=1）---"
  fi

  sync; sleep 1   # 2026-10-16: 崩死窗口里少等一秒

  # ════════════════════════════════════════════════════════════════════════
  # ★★★ 2026-10-16 八改：ksud late-load（加载内嵌的 UAPI 5 ko）★★★
  #   · KSUD_LATE 优先用与管理器同代的 ksud_resukisu
  #   · late-load 内部：has_kernelsu() 为真就只装用户态；否则取内嵌 ko 并加载
  #   · 加 --kmi android14-6.1 显式指定（避免它去读 boot 镜像探测 KMI）
  #   · 不碰 boot 镜像（boot-patch 那条路在 HONOR 上是禁区，绝不用）
  # ════════════════════════════════════════════════════════════════════════
  if [ "$USE_LATE_LOAD" = "1" ]; then
    KSUD_LATE=""
    for c in $RD/ksud_resukisu $RD/ksud_success $RD/ksud; do
      [ -x "$c" ] && { KSUD_LATE="$c"; break; }
    done
    if [ -n "$KSUD_LATE" ]; then
      echo "=== late-load 前置：确认 uid=0 ==="
      id -u 2>/dev/null
      echo "=== late-load 前置：已加载? (has_kernelsu) ==="
      grep -c kernelsu /proc/modules 2>/dev/null
      echo "=== late-load 前置：ksud 支持的 KMI 列表 ==="
      timeout 30 "$KSUD_LATE" boot-info supported-kmis 2>&1 | head -20
      echo "=== late-load 前置：当前 KMI ==="
      timeout 30 "$KSUD_LATE" boot-info current-kmi 2>&1 | head -5
      echo "=== 执行 late-load（--kmi android14-6.1 --allow_shell）==="
      timeout 180 "$KSUD_LATE" late-load --kmi android14-6.1 --allow_shell > $RD/lateload_result.log 2>&1
      LL_RC=$?
      echo "late_load_exit=$LL_RC"
      echo "--- lateload_result.log ---"
      tail -40 $RD/lateload_result.log 2>/dev/null
      echo "--- 之后 /proc/modules 里的 kernelsu ---"
      # ★ 十四改：把 ko 的 hook 状态打出来（这是"授权能不能用"的直接证据）
  echo "=== hook / sucompat 状态（来自内核日志）==="
  dmesg 2>/dev/null | grep -iE 'hook_manager|syscall hooks|sucompat|HOOKS_ON|escape to root|sys_call_table|verify execve|mgr-fd|rootshell' | tail -30 || echo "(dmesg 取不到)"
  echo "=== /data/adb/ksu/.allowlist ==="
  ls -l /data/adb/ksu/.allowlist 2>&1 || echo "(不存在)"
  echo "=== /dev/su ==="
  ls -l /dev/su 2>&1 || echo "(不存在)"
  ls -l /data/adb/ksud 2>&1 || echo "(不存在)"
  grep -i kernelsu /proc/modules 2>/dev/null || echo "(still no kernelsu)"
    else
      echo "!! 找不到 ksud（ksud_resukisu/ksud_success/ksud 都没有）⇒ 无法 late-load"
    fi
  fi

  # ========================================================================
  # ★★★ 2026-10-16：复位检测埋点 ★★★
  #   目的：把"提权成功但设备随后复位"和"提权成功且不复位"区分开 ——
  #   之前的判据只看 "★ kernelsu 已进 /proc/modules"，那只能证明"提权成功"，
  #   证明不了"能持续用"。而 YG 的标准是后者。
  #   做法：此刻记 boot_id + 时间戳；App 下次启动时对比 boot_id，
  #   不同 ⇒ 复位过（附存活秒数）；相同 ⇒ 没复位 ⇒ 真成功。
  # ========================================================================
  # 十三改（审计修复）：原来 ksu_load_ok 全仓库无人创建 ⇒ 复位检测链是死的。
  #   现在：加载成功（rc=0 且 /proc/modules 命中）就自己创建它。
  # ★★ 2026-10-16（关键修复）：**在这里绝对不能再用外部命令** ★★
  #   这一段跑在**模块加载之后**，而模块自己的 syscall hook（HOOKS_ON）
  #   会拦截 execve/faccessat/newfstatat ⇒ grep / cat / cut / date / head
  #   全部报 "inaccessible or not found"（真机日志里已实测到）。
  #   原来的写法：
  #       if [ "$LOAD_RC" = "0" ] && grep -q kernelsu /proc/modules; then
  #   在 hook 生效后 grep 必然失败 ⇒ 条件恒假 ⇒ **ksu_load_ok 永远不创建**
  #   ⇒ 复位检测链（"提权成功且没复位"）是死的。
  #   ⇒ 现在：用 **shell 内建** 扫 /proc/modules，其余字段也全用内建取。
  MOD_HIT=0
  while IFS= read -r _ml; do
    case "$_ml" in *[Kk]ernel[Ss][Uu]*) MOD_HIT=1; MOD_LINE="$_ml"; break ;; esac
  done < /proc/modules 2>/dev/null
  if [ "$LOAD_RC" = "0" ] && [ "$MOD_HIT" = "1" ]; then
    touch $RD/ksu_load_ok 2>/dev/null
    echo "ksu_load_ok marker created (提权成功)"
    echo "（模块命中方式：shell 内建扫 /proc/modules，不依赖 grep）"
  fi
  if [ -f $RD/ksu_load_ok ]; then
    echo "=== 复位检测：写下本次提权成功的标记 ==="
    # 全部用内建取值（boot_id / uptime / 模块行都靠 read，不用 cat/cut/grep/date）
    _BID="?"; _UP="?"; _ML=""
    while IFS= read -r _b; do _BID="$_b"; break; done < /proc/sys/kernel/random/boot_id 2>/dev/null
    while IFS= read -r _u; do _UP="${_u%%.*}"; break; done < /proc/uptime 2>/dev/null
    _ML="$MOD_LINE"
    {
      echo "boot_id=$_BID"
      echo "uptime=$_UP"
      echo "module=$_ML"
    } > $RD/ksu_success_stamp.txt 2>&1
    chmod 644 $RD/ksu_success_stamp.txt 2>/dev/null
    while IFS= read -r _s; do echo "$_s"; done < $RD/ksu_success_stamp.txt 2>/dev/null
  fi

  # ========================================================================
  # ★★★ 2026-10-16：【MINIMAL 极致精简 IO】★★★
  #
  #  为什么需要它：内核从 load_ko 成功那一刻起就不健康（ko 与内核版本不匹配），
  #  崩死窗口只有 10~60 秒 ~ 3 分钟。而这个窗口里的**每一次额外 IO/CPU**
  #  都在加速它崩。原链路在这个窗口里要跑：ksud 4 个阶段（各 timeout 180）、
  #  sulog feature set + sleep 2、allowlist 导出、sulog tail、4 个文件健康检查、
  #  tombstones 检查、全 /proc 扫描数 exploit 进程、sync + drop_caches、
  #  dmesg 全量 dump、ksu_probe 全量 kallsyms×3、pstore 取证……
  #  ⇒ 全砍掉，只留"管理器能认 + su 通路能用"这两件必需品。
  #
  #  启用：adb shell touch /data/local/tmp/ksu/MINIMAL
  #  退出后仍是 Permissive（ENFORCE marker 才切 Enforcing，避免 zygote 崩）
  # ========================================================================
  # ★ 十五改（审计修复）：原来只看 MINIMAL，而 App 每次部署都无条件创建它
  #   ⇒ NO_MINIMAL 这个逃生门**永远无效**
#   ★ 用法：adb shell touch /data/local/tmp/ksu/NO_MINIMAL   （恢复完整链路），完整链路（ksud 四阶段/allowlist/
  #     健康检查/tombstone/keeper/drop_caches 还原）永久失效且无提示。
  #   现在：MINIMAL 且**没有** NO_MINIMAL 才走精简链路。
  if [ -f $RD/MINIMAL ] && [ ! -f $RD/NO_MINIMAL ]; then
    echo "=== MINIMAL 模式：只做必要的两件事，其余全跳 ==="
    # ★★ 2026-10-16（关键修复）：模块**已经加载**了 —— 它自己的 syscall hook
    #   会把 grep 变成 "inaccessible or not found"（真机与模拟都实测到）。
    #   原来这里写 `timeout 10 grep -qi kernelsu /proc/modules`：
    #       grep 失败 ⇒ MODM=0 ⇒ "MINIMAL: kernelsu Live=0"
    #       ⇒ **跳过铺 ksud + 铺 /dev/su 这两件必需品**
    #       ⇒ 管理器认不到、su 用不了 —— 就是"提权成功但用不了"。
    #   ⇒ 改成 shell 内建扫 /proc/modules（只用 read + case）。
    MODM=0
    while IFS= read -r _mm; do
      case "$_mm" in *[Kk]ernel[Ss][Uu]*) MODM=1; break ;; esac
    done < /proc/modules 2>/dev/null
    echo "MINIMAL: kernelsu Live=$MODM（内建扫，不依赖 grep）"
    if [ "$MODM" = "1" ]; then
      # ★ 2026-10-16 修：cp 源必须是**已部署的** $RD/ksud_success（回退 $RD/ksud），
      #   而不是 /data/adb/ksud —— 后者由本分支自己在下面 cp 铺（App 侧补装路径已移除）
      #   才会装，用户不点就根本不存在 ⇒ /dev/su 会铺不上。
      KS=$RD/ksud_success
      [ -f "$KS" ] || KS=$RD/ksud
      # 自编 uapi5 ko ⇒ /dev/su 用同版本管理器的 ksud（不然 supercall 字段错位）
      case "$(basename "$KSU_MODULE")" in
        kernelsu_custom.ko|kernelsu_ksu331.ko|kernelsu_next.ko)
          [ -x "$RD/ksud_mgr" ] && KS=$RD/ksud_mgr && echo "  [ksud] 使用管理器自带 ksud（uapi 对齐）"
          ;;
      esac
      echo "MINIMAL: ksud 源 = $KS ($(wc -c < $KS 2>/dev/null || echo ?) B)"
      if [ -f "$KS" ]; then
        # ① 装到 /data/adb（持久分区；ReSukiSU 管理器据此判「已安装」）
        mkdir -p /data/adb/ksu/bin 2>/dev/null
        cp -f "$KS" /data/adb/ksud 2>/dev/null && chmod 755 /data/adb/ksud 2>/dev/null
        ln -sfn /data/adb/ksud /data/adb/ksu/bin/ksud 2>/dev/null
        ln -sfn /data/adb/ksud /data/adb/ksu/bin/resetprop 2>/dev/null
        # ② /dev/su —— sucompat(kprobe) 会把 execve("/system/bin/su") 重定向到这里
        cp -f "$KS" /dev/su 2>/dev/null && chmod 755 /dev/su 2>/dev/null
        # ★ 十五改（审计修复）：cp 到 /dev/su 是 sucompat 的重定向目标，
        #   失败必须可见（原来 2>/dev/null + 只 ls 一次，可能显示旧文件）。
        if [ -x /dev/su ]; then
          echo "  /dev/su 就绪: $(wc -c < /dev/su 2>/dev/null) B"
        else
          echo "  !! /dev/su 落地失败 —— sucompat 将无法重定向到 ksud"
        fi
        echo "MINIMAL: /data/adb/ksud = $(wc -c < /data/adb/ksud 2>/dev/null || echo ?) B"
        echo "MINIMAL: /dev/su      = $(wc -c < /dev/su 2>/dev/null || echo ?) B"
      else
        echo "MINIMAL: !! 找不到 $RD/ksud_success / $RD/ksud —— 跳过安装"
      fi
    fi
    # ★ fix3-20261018：MINIMAL 分支原来永不切严格（App 每次部署都会建 MINIMAL）
    #   ⇒ 要让"最后切回严格"真正生效，必须在这个分支也走一遍收尾。
    # 顺序很重要：先加冕+重启管理器（此时还是 Permissive，binder 事务能过），
    # 再切 Enforcing。反过来会看到 ksud 报 "cmd: Failure calling service activity"。
    _su_cred_apply
    _mgr_selfheal "$MODM"
    _selinux_finalize "$MODM"
    _fresh_selfcheck
    _probe_su
  echo "=== MINIMAL 完成（跳过 ksud 阶段/诊断/取证/drop_caches）==="
    _probe_exec "MINIMAL 收尾"
    dmesg 2>/dev/null > $RD/kmsg_final.txt 2>/dev/null; chmod 644 $RD/kmsg_final.txt 2>/dev/null
    echo "=== final ==="
    timeout 10 grep -i kernelsu /proc/modules 2>/dev/null || echo "(no kernelsu)"
    getenforce
  else


  # ---- 7b. Keep hisecd FROZEN through the ksud stages (H80GT's design).
  # Thawing it right after the load lets it notice the unsigned module
  # (HISEC: [UEVENT] stp uevent ... mod-sign: ... result=-61) and hard-reset the
  # device: device-verified 2026-09-19 03:39, the kernel log ends with NO oops
  # and every AP_S_PANIC in faultdetect/history.log is followed by a PS_HOLD
  # NORMALBOOT. The EXIT trap above still guarantees a thaw if this script dies
  # early, so a failure can no longer leave hisecd stopped.
  if [ -n "$hp" ]; then
    echo "hisecd kept frozen through the load window (pid=$hp)"
  else
    echo "hisecd 没找到/没冻结（不阻塞装载）"
  fi

  echo "=== loadko_result.log ==="
  while IFS= read -r _kl; do echo "$_kl"; done < $RD/loadko_result.log 2>/dev/null
  # ★ 2026-10-16（同类修复）：这里的 grep 同样在模块加载**之后** ⇒ 已被 hook 打断。
  #   改成 shell 内建扫（否则会误报 "kernelsu NOT in /proc/modules"）。
  MOD=0
  while IFS= read -r _mm; do
    case "$_mm" in *[Kk]ernel[Ss][Uu]*) MOD=1; break ;; esac
  done < /proc/modules 2>/dev/null
  # ★ 2026-10-24：装载后本进程的 open/exec 可能被模块 hook 打断
  #   （实测日志：`can't open /proc/modules: Permission denied`、
  #    `sleep: inaccessible or not found`、`health: /system/bin/sh NOT accessible`），
  #   这时读不到 /proc/modules 是**自检残疾**，不是装载失败。
  #   load_ko 只在 init_module 成功后才打印 "module loaded OK!" 并返回 0 ⇒ 用退出码兜底。
  if [ "$MOD" = "0" ] && [ "$LOAD_RC" = "0" ]; then
    MOD=1
    echo "*** /proc/modules 读不到（本进程 access 路径被打断）⇒ 按 load_ko_exit=0 判定 kernelsu LIVE ***"
    echo "*** 提示：本进程后续 open/exec 大概率也会被拒，selfcheck 空属正常，别当装载失败 ***"
  fi
  if [ "$MOD" = "1" ]; then
    echo "*** kernelsu LIVE in /proc/modules ***"
  else
    echo "*** kernelsu NOT in /proc/modules ***"
  fi

  # ---- 7b2. POST-LOAD dmesg capture（2026-09-22 23:55 观测链修复）：
  #  post_root 的快照在装载前抓（0 条 KSU 日志，设计缺陷）——模块 init 的
  #  sucompat verify / VERIFIED 写路径判定 / su 触发后的 hook 行为只有此刻
  #  （uid0 + Permissive）能读。装载后立刻全量快照。
  # ★ 2026-10-16：dmesg 全量 dump（1 MB）也改成 marker 门控（默认关）
  if [ -f $RD/DUMP_DMESG ]; then
    dmesg > $RD/ksu_dmesg_postload.txt 2>/dev/null
    chmod 644 $RD/ksu_dmesg_postload.txt 2>/dev/null
    echo "dmesg postload: $(wc -c < $RD/ksu_dmesg_postload.txt 2>/dev/null) bytes"
  else
    echo "dmesg postload: SKIPPED by default (要抓就 touch $RD/DUMP_DMESG)"
  fi

  # ---- 7b3. KSU feasibility probe（2026-10-15 新增）
  #  为什么放这里：真机实测这台 Magic6 Pro 的 rootd 通道只在提权后很短时间
  #  内有效，之后就"无输出" —— 所有事后诊断都拿不到东西。
  #  而此刻 loader 自己是 uid=0、模块刚 Live，是做核对最可靠的位置。
  #  脚本只读（读 kallsyms / /proc/modules / ls），不加载任何模块。
  echo "=== ksu_probe.sh (uid=$(id -u)) ==="
  # ★★★ 2026-10-16 改：默认**不跑** ★★★
  #   它会把整个 /proc/kallsyms（6 万+ 行）解析 3 遍 + sort -u + 两次全量集合差，
  #   而此刻内核刚加载了 6.1.128 的 ko（与 6.1.157 内核不匹配）⇒ 正在崩死边缘。
  #   在这段窗口里抢 CPU/IO 只会让它更早崩。
  #   需要诊断时：adb shell touch /data/local/tmp/ksu/PROBE_KSU
  if [ -f $RD/PROBE_KSU ]; then
    if [ -f $RD/ksu_probe.sh ]; then
      timeout 300 sh $RD/ksu_probe.sh 2>&1
      echo "=== ksu_probe done rc=$? ==="
    else
      echo "(ksu_probe.sh not present - skip)"
    fi
  else
    echo "ksu_probe: SKIPPED by default (重 IO，会加速崩死；要诊断就 touch $RD/PROBE_KSU)"
  fi

  # ---- 7c. HEALTH CHECK. The 2026-09-19 run wedged userspace here: KSU's
  # syscall-hook dispatcher made access()/stat() return -ENOSYS, so init could
  # not exec service binaries and the shell could not find its own tools.
  # Verify the syscall path is intact before doing anything else.
  HC=1
  for t in /system/bin/sh /system/bin/cat /system/bin/getenforce; do
    [ -e "$t" ] || { echo "health: $t NOT accessible (access/stat broken)"; HC=0; }
  done
  timeout 5 cat /proc/uptime >/dev/null 2>&1 || { echo "health: basic cat FAILED"; HC=0; }
  timeout 5 /system/bin/id >/dev/null 2>&1 || { echo "health: exec id FAILED"; HC=0; }
  echo "health_check=$HC (1 = syscall path intact)"

  # ==========================================================================
  #  【本包新增】7d/7e — 崩溃取证（BVL-AN16 适配用，marker 门控）
  #
  #  背景：syst.resettype = abnormal:AP_S_PANIC，说明每次复位都是内核 panic；
  #  但 kmsg_dumper 抓到的 kmsg 在 uptime~297s 处戛然而止、没有 panic 横幅，
  #  所以"到底是谁 panic"一直看不到。pstore 里存着上一次崩溃的内核日志，
  #  但 /sys/fs/pstore 对 shell(uid 2000) 是 Permission denied —— 只有 root 能读。
  #  loader 每 boot 只有这一次 uid 0 窗口，所以就在这里抓。
  # ==========================================================================
  # ★ 2026-10-16：pstore 取证（cat 整个上次崩溃的内核日志，可能几 MB）
  #   也改成 marker 门控（默认关）—— 同属崩死窗口里的重 IO。
  #   需要时：touch $RD/COLLECT_PSTORE
  if [ -f $RD/COLLECT_PSTORE ] && [ ! -f $RD/NO_PSTORE ]; then
    rm -f $RD/pstore_*.txt $RD/pstore_list.txt $RD/crash_env.txt 2>/dev/null
    ls -la /sys/fs/pstore/ > $RD/pstore_list.txt 2>&1
    for f in /sys/fs/pstore/console-ramoops-0 /sys/fs/pstore/console-ramoops \
             /sys/fs/pstore/dmesg-ramoops-0 /proc/last_kmsg; do
      [ -e "$f" ] || continue
      b=$(basename $f)
      if cat "$f" > $RD/pstore_$b.txt 2>/dev/null; then
        echo "pstore: captured $f -> $RD/pstore_$b.txt ($(wc -c < $RD/pstore_$b.txt) bytes)"
      else
        echo "pstore: $f exists but UNREADABLE in this context"
      fi
    done
    {
      echo "resettype=$(getprop sys.resettype)"
      echo "init_fatal_panic=$(getprop ro.boot.init_fatal_panic)"
      echo "boot=$(cat /proc/sys/kernel/random/boot_id)"
      echo "uptime=$(cut -d. -f1 /proc/uptime)"
      echo "panic=$(cat /proc/sys/kernel/panic)"
      echo "panic_on_oops=$(cat /proc/sys/kernel/panic_on_oops)"
      echo "panic_print=$(cat /proc/sys/kernel/panic_print 2>/dev/null)"
      echo "hung_task_timeout_secs=$(cat /proc/sys/kernel/hung_task_timeout_secs 2>/dev/null)"
      echo "hung_task_panic=$(cat /proc/sys/kernel/hung_task_panic 2>/dev/null)"
      echo "--- /proc/modules ---"; cat /proc/modules
    } > $RD/crash_env.txt 2>&1
    echo "pstore: 目录清单与崩溃环境写入 $RD/pstore_list.txt / crash_env.txt"
  fi

  # 7e. 为本次会话"武装"panic 证据。marker PANIC_HANG 让内核在 panic 时
  #     不再重启而是原地死循环 —— 若设备这次变成"卡死"而不是"复位"，就
  #     证明杀它的是 panic()；若照旧复位，则 AP_S_PANIC 另有来源（硬件看门狗）。
  #     代价：卡死后需要长按电源键手动重启。
  if [ -f $RD/ARM_PANIC_PRINT ]; then
    echo 0x3f > /proc/sys/kernel/panic_print 2>/dev/null && echo "panic_print=0x3f armed"
  fi
  if [ -f $RD/PANIC_HANG ]; then
    echo 0 > /proc/sys/kernel/panic 2>/dev/null && echo "PANIC_HANG: panic 将【卡死】而非重启（需手动长按电源键）"
  else
    echo "panic=$(cat /proc/sys/kernel/panic 2>/dev/null) (panic 后重启；要改成卡死请 touch $RD/PANIC_HANG)"
  fi

  # ---- 8. ksud bring-up (only if the module is actually resident).
  #      Marker $RD/SKIP_STAGES: EXPERIMENT 2026-09-19 - every successful load so
  #      far panics the kernel within 30-60s (AP_S_PANIC), and freezing hisecd
  #      does not stop it. Skipping the ksud stages separates "the module itself"
  #      from "post-load userspace bring-up" as the trigger. Root does not need
  #      these stages to work (KSU_IOCTL_GRANT_ROOT is in the module).
# ★ 用法：adb shell touch /data/local/tmp/ksu/SKIP_STAGES   （跳过 ksud 的四阶段）
  if [ -f $RD/SKIP_STAGES ]; then
    echo "ksud stages SKIPPED (SKIP_STAGES marker) - module left as loaded"
    echo "stages=skipped reason=SKIP_STAGES rc=0" >> $RD/ksu_install.log
  elif [ "$MOD" = "1" ]; then
    [ -d /data/adb/modules/zygisksu ] && touch /data/adb/modules/zygisksu/disable
    # Each stage is one-shot: it does its work (mounts, module scripts, etc.) and
    # exits by itself - all four report rc=0 here. The timeout is hang protection
    # ONLY, and a timeout kill is now reported as 124 explicitly, so that "killed
    # by timeout" can never again be confused with "exited on its own" (timeout
    # returns 124 when it has to kill, and 0 here means it never did).
    for stage in post-fs-data services boot-completed install; do
      timeout 180 $KSUD $stage >/dev/null 2>&1
      rc=$?
      [ "$rc" = "124" ] && rc="124 KILLED-BY-TIMEOUT"
      echo "ksud $stage rc=$rc"
      # ★ 2026-10-16（修「检测链路值没填」）：**这一行必须同时进 ksu_install.log**。
      #   App 的 awaitKsudResult() 就是靠 `tail -n 6 <dir>/ksu_install.log`
      #   找 `rc=124` 来判断"ksud install 被 timeout 杀掉"。
      #   原来只 echo 到 stdout（→ $LOG），App 那个判定永远是 false。
      echo "ksud $stage rc=$rc" >> $RD/ksu_install.log
    done
    ls -la /data/adb/ksud 2>&1

    # ---- 8a0. Keep ksud alive: start its su-log daemon.
    #
    # The only long-running process inside ksud is the su-log reader, and this is
    # how to get it: `ksud debug sulogd` -> sulog::ensure_sulogd_running() ->
    # spawn_sulogd(), which calls utils::create_daemon() (fork, detach, join init's
    # process group) and then re-execs itself as `ksud sulogd` - a loop with a lock
    # file and automatic restarts. So it is a genuine daemon: it does not belong to
    # this loader's process tree, and no `timeout` can reap it. It is what records
    # su grants/denials for the Manager's log view.
    #
    # (The marker is $RD/NO_SULOGD.)
# ★ 用法：adb shell touch /data/local/tmp/ksu/NO_SULOGD   （不起 ksud 的 su 日志守护）
    if [ -f $RD/NO_SULOGD ]; then
      echo "sulogd: SKIPPED (NO_SULOGD marker)"
    else
      # `ksud feature set sulog 1` is the proper entry point, not `debug sulogd`:
      # feature.rs:set_kernel_feature() enables the kernel's sulog feature AND
      # calls ensure_sulogd_running() when the feature is the sulog one. Plain
      # `debug sulogd` would start the daemon but leave the kernel side off.
      $KSUD feature set sulog 1 2>&1
      echo "sulog feature set rc=$?"
      $KSUD feature get sulog 2>&1 | head -3
      sleep 2
      echo "sulogd procs: $(ps -A -o NAME 2>/dev/null | grep -c ksud)"
      ps -A -o PID,PPID,USER,NAME 2>/dev/null | grep ksud | head -3
    fi

    # ---- 8a. Allowlist evidence (running as root here, so this is readable).
    # The persisted allowlist is a BINARY file (u32 magic, u32 version, then
    # struct perm_data records) - see kernel/policy/allowlist.c:do_persistent_allow_list().
    # The package names inside it are ASCII, so strip non-printable bytes to prove
    # which granted apps (e.g. bin.mt.plus) really are in the kernel's allowlist
    # after a reboot. Without an entry here, sucompat deliberately does nothing
    # for that uid and the app sees no root.
    echo "--- allowlist evidence ---"
    ls -la /data/adb/ksu/ 2>&1
    tr -c '[:print:]' '\n' < /data/adb/ksu/.allowlist 2>&1 | grep -a . | head -40

    # ---- 8a1. Stage a world-executable ksud copy at /dev/su.
    # The kprobe sucompat (kernel/supercall/supercall.c) rewrites
    # execve("/system/bin/su") to /dev/su. It cannot point at /data/adb/ksud:
    # that file is 0755, but /data/adb itself is 0700 root, so a normal app
    # cannot even traverse to it - and the kprobe handler cannot open the file
    # with kernel creds and use execveat() the way upstream sucompat does,
    # because opening a file sleeps and a kprobe runs in the BRK exception
    # context. /dev is world-searchable and writable by us at this point.
    # The "su" suffix is deliberate: ksud decides it is in su mode from argv[0],
    # which the app supplies ("su"), but the name matching it costs nothing.
    cp -f /data/adb/ksud /dev/su 2>&1
    chmod 755 /dev/su 2>&1
    ls -l /dev/su 2>&1
    echo "dev_su_id=$(echo id | /dev/su 2>&1 | head -1)"

    # ---- 8a2. Does su work for a GRANTED APP uid, not just the shell's 2000?
    # uid 2000 is allowed by this loader's own allow_shell=1 param and gets its
    # root profile from a special case in ksu_get_root_profile(), so a passing
    # shell test says nothing about a real app. This runs the actual app
    # scenario: drop to the app's uid and exec /system/bin/su -c id, which is
    # what MT Manager (bin.mt.plus) does when you ask it for root. Needs the
    # module's kprobes to be installed (they are, from step 6).
    APP_PKG=bin.mt.plus
    APP_UID=$(awk -v p="$APP_PKG" '$1==p{print $2; exit}' /data/system/packages.list 2>/dev/null)
    echo "--- app su test: $APP_PKG uid=${APP_UID:-unknown} ---"
    if [ -n "$APP_UID" ] && [ -x $RD/suas ]; then
      $RD/suas "$APP_UID" 2>&1 | head -3
    else
      echo "app su test skipped (uid='$APP_UID' suas=$([ -x $RD/suas ] && echo yes || echo no))"
    fi

    # Export the persisted allow-list for host-side parsing. It is a binary record
    # array (u32 magic, u32 version, then struct app_profile records), and whether
    # this app's uid is really in it is the one thing the su test above cannot
    # distinguish from "allowed some other way".
    cp -f /data/adb/ksu/.allowlist $RD/allowlist.bin 2>&1
    chmod 644 $RD/allowlist.bin 2>&1
    ls -l $RD/allowlist.bin 2>&1

    # ---- 8a3. Did the su-log daemon record the grant we just made?
    # This is the payoff for keeping ksud's daemon alive: the kprobe sucompat path
    # emits a grant-root event itself (it replaces ksu_handle_execve_sucompat(),
    # which is where the kernel used to emit from), so the entry below should
    # appear right after the `suas` line above.
    echo "--- sulog tail ---"
    for f in /data/adb/ksu/log/sulog-*.log; do
      if [ -f "$f" ]; then
        echo "== $f"
        tail -6 "$f"
      fi
    done

    # ---- 8a2. OPT-IN: give every app a real `su` on PATH ($RD/PROVIDE_SU).
    #
    # sucompat is the normal KernelSU mechanism (the kernel intercepts
    # execve("/system/bin/su") and redirects it to ksud), but it depends on the
    # syscall-table patch actually landing - see PATCHES.md sections 23/24. This
    # is the independent path, and it is what Magisk does: expose `su` through an
    # overlayfs upper layer over /system/bin, leaving every existing binary
    # visible via the lower layer. Nothing in /system is modified - no remount,
    # no dm-verity risk - it is only a mount in the shared mount namespace, so
    # every app's execvp("su") finds it at the next exec.
    #
    # Opt-in on purpose: it overlays the directory that holds the dynamic linker,
    # so it is the one step here that could plausibly upset userspace.
    if [ -f $RD/PROVIDE_SU ]; then
      echo "--- PROVIDE_SU: overlay /system/bin with su -> /data/adb/ksud ---"
      mkdir -p /data/local/tmp/suover/upper /data/local/tmp/suover/work
      chmod 755 /data/local/tmp/suover /data/local/tmp/suover/upper /data/local/tmp/suover/work
      ln -sf /data/adb/ksud /data/local/tmp/suover/upper/su
      mount -t overlay ksu_su -o lowerdir=/system/bin,upperdir=/data/local/tmp/suover/upper,workdir=/data/local/tmp/suover/work /system/bin 2>&1
      echo "su_overlay_mount_rc=$?"
      ls -l /system/bin/su 2>&1
      echo "su_overlay_id=$(echo id | /system/bin/su 2>&1 | head -1)"
      echo "su_overlay_bin_ok=$(ls /system/bin/linker64 /system/bin/sh 2>&1 | tr '\n' ' ')"
    fi
  else
    echo "module missing - skipping ksud stages"
  fi

  # ---- 8b. Crash-evidence guards - NOW OFF BY DEFAULT, and that matters.
  #
  # History: hiding the tombstone used to be how we tried to keep init from
  # classifying the zygote crash (chain: "Valid log: /data/tombstones/tombstone_23
  # has been found!" -> bootfail_errno 0x50000003 -> proc_upper_bf ->
  # try_to_recovery -> reset). It never worked (init is zygote's parent; it
  # classifies from waitpid, not from the tombstone).
  #
  # Since step 1c closes the report path at its kernel entry gate, hiding the
  # evidence is not just useless - it is HARMFUL, and it is why the run that
  # first survived the panic still reset at uptime 279s. Device-verified
  # 2026-09-19 (kmsg of boot f5c94fee): after the zygote crash init entered its
  # log-collection loop and, because /data/tombstones was chmod 000 and empty,
  # tombstoned could not write a tombstone, so init retried once a second for
  # ~120s -
  #   [1:init]bootfail: find log in [/data/system/dropbox] failed!
  #   [1:init]bootfail: find log in [/data/tombstones] failed!
  #   [1:init]bootfail: failed to get tombstones/dropbox log path!
  # - and then the device did a PMIC/PS_HOLD hard reset (uptime 279s) with NO
  # kernel message at all: not a panic (qcom_reboot would have printed one and
  # the bootfail entry gate would have refused it anyway), and not the reboot()
  # syscall either (our kprobe in supercall.c logs every call and only ksud's
  # appear). init looping in that path with its main loop blocked is the
  # consistent explanation of a silent hardware-watchdog reset.
  #
  # So by default we now LEAVE THE TOMBSTONE MACHINERY ALONE: tombstoned writes
  # its tombstone, init finds it on the first try, its report is refused by the
  # (disabled) detector, and the loop never starts.
  # Markers $RD/HIDE_TOMBSTONES / $RD/KILL_PROC_UPPER_BF restore the old guards.
  TP=$(ls -ld /data/tombstones 2>/dev/null | cut -c1-10)
  if [ "$TP" = "d---------" ]; then
    chmod 755 /data/tombstones 2>/dev/null && echo "tombstones: restored 755 (was left locked by an earlier run)"
  fi
  if [ -f $RD/HIDE_TOMBSTONES ]; then
    rm -f /data/tombstones/tombstone_* 2>/dev/null
    if chmod 000 /data/tombstones 2>/dev/null; then
      echo "tombstones: emptied + chmod 000 (HIDE_TOMBSTONES marker)"
    else
      echo "tombstones: chmod failed - falling back to the rm loop only"
    fi
    setsid sh -c 'while :; do rm -f /data/tombstones/tombstone_* 2>/dev/null; [ "$(ls -ld /data/tombstones 2>/dev/null | cut -c1-10)" = "d---------" ] || chmod 000 /data/tombstones 2>/dev/null; sleep 2; done' >/dev/null 2>&1 </dev/null &
    echo "tombstone lock detached (HIDE_TOMBSTONES marker)"
  else
    echo "tombstones: left writable (default - hiding them is what hung init at uptime 279s)"
  fi
# ★ 用法：adb shell touch /data/local/tmp/ksu/KILL_PROC_UPPER_BF   （杀掉 proc_upper_bf（荣耀 bootfail 上报进程））
  if [ -f $RD/KILL_PROC_UPPER_BF ]; then
    setsid sh -c 'while :; do pkill -9 -x proc_upper_bf 2>/dev/null; sleep 1; done' >/dev/null 2>&1 </dev/null &
    echo "proc_upper_bf killer detached (KILL_PROC_UPPER_BF marker)"
  fi

  # ---- 8c. Pin the exploit's page-keepers the moment they appear.
  # The crash that ends the session is a USERSPACE crash whose memory holds our
  # own fake rb_node values (kernel pointer | colour bits, e.g. 0xffffff8a3ecb7802
  # and 0xffffff8856f14202 - both low byte 0x02), and bootanimation+zygote crash
  # at the SAME address, so a shared (file-backed) page got poisoned and then
  # handed to userspace. The exploit forks keepers to retain those pages by COW:
  #   cve43499-hold  (main.c spawn_allocation_keeper)
  #   cve43499-p0ref (pipe.c spawn_p0_ref_keeper)
  #
  # PINNING IS NOW OFF BY DEFAULT, and that is the important part of this step.
  #
  # It used to pin every process in the exploit's tree at oom_score_adj=-1000 to
  # "retain the poisoned pages". That whole theory is dead (the poison is a
  # constant per boot - see the tombstone analysis), and the pinning turned out
  # to be what restarts zygote and therefore what creates the crash loop:
  #
  #   kmsg of boot 711602cc (2026-09-19 09:32):
  #     144.62s  module loaded
  #     144.78s  KernelSU: Searching manager... (reads every base.apk in /data/app)
  #     156.43s  [1:init]init: Service 'zygote' (pid 1820) received signal 9
  #   i.e. zygote - which was running fine - is KILLED ~12 s after the load, init
  #   restarts it, and only the restarted zygote hits the poison and crashes.
  #
  # Two facts explain the kill: the exploit's reclaim design leaves loadavg at
  # 15-23 with the keepers holding the reclaimed pages, and pinning the whole tree
  # at -1000 makes those pages unkillable - so a memory-pressure killer has to
  # take something else, and zygote is the biggest thing around. The two positive
  # controls (NO_LOAD, TEST_MOD) survived 300 s+ and they predate this pinning.
  #
  # So: leave the tree killable, let the pressure be released on the exploit's own
  # processes, and hope zygote is never restarted at all - in which case the poison
  # is never consumed and there is no crash loop to begin with.
  # Marker $RD/PIN_KEEPERS restores the old pinning for reference.
  rm -f $RD/keeper_watch.log
  pin_tree() {
    n=0
    for d in /proc/[0-9]*; do
      pid=${d#/proc/}
      c=$(cat $d/comm 2>/dev/null)
      case "$c" in
        *43499*) ;;                     # exploit binary (any name) or keeper
        *) continue ;;
      esac
      echo -1000 > /proc/$pid/oom_score_adj 2>/dev/null && n=$((n+1))
    done
    echo "$n"
  }
  if [ -f $RD/PIN_KEEPERS ]; then
    PINNED=$(pin_tree)
    echo "step 8c: pinned $PINNED process(es) matching *43499* (PIN_KEEPERS marker)"
  else
    TREE=0
    for d in /proc/[0-9]*; do
      c=$(cat $d/comm 2>/dev/null)
      case "$c" in *43499*) TREE=$((TREE+1));; esac
    done
    echo "step 8c: NOT pinning - $TREE exploit-tree process(es) left killable (pinning is what got zygote SIGKILLed)"
  fi

  # The pid-based pinner only runs with the marker; otherwise this block just
  # documents where the keepers would have been.
  if [ -f $RD/PIN_KEEPERS ]; then
  cat > $RD/keeper_mon.sh <<'KEEPER_MON'
#!/system/bin/sh
RD=/data/local/tmp/ksu
LOG=$RD/keeper_watch.log
KPIDS=""
find_pids() {
  # the exploit logs "stability keeper pid=NNNN" / "p0 reference keeper pid=NNNN"
  grep -o 'keeper pid=[0-9]*' $RD/dc_ksu.log 2>/dev/null | cut -d= -f2 | tr '\n' ' '
}
i=0
while [ $i -lt 3000 ]; do
  KPIDS=$(find_pids)
  [ -n "$KPIDS" ] && break
  sleep 0.2 2>/dev/null || sleep 1
  i=$((i+1))
done
echo "keeper_mon: logged keeper pids='$KPIDS' after ${i} polls (uptime $(cut -d. -f1 /proc/uptime))" >> $LOG
for p in $KPIDS; do
  if echo -1000 > /proc/$p/oom_score_adj 2>/dev/null; then
    echo "keeper_mon: PINNED pid=$p adj=$(cat /proc/$p/oom_score_adj 2>/dev/null) comm=$(cat /proc/$p/comm 2>/dev/null)" >> $LOG
  else
    echo "keeper_mon: pin FAILED pid=$p (exists=$( [ -d /proc/$p ] && echo yes || echo no ))" >> $LOG
  fi
done
i=0
while [ $i -lt 1200 ]; do
  line=""
  for p in $KPIDS; do
    if [ -d /proc/$p ]; then
      line="$line $p:$(cut -d' ' -f3 /proc/$p/stat 2>/dev/null)/adj$(cat /proc/$p/oom_score_adj 2>/dev/null)"
    else
      line="$line $p:GONE"
    fi
  done
  # keep re-pinning anything in the tree that escaped (a later fork)
  pin_tree() {
    n=0
    for d in /proc/[0-9]*; do
      q=${d#/proc/}
      c=$(cat $d/comm 2>/dev/null)
      case "$c" in *43499*) ;; *) continue ;; esac
      echo -1000 > /proc/$q/oom_score_adj 2>/dev/null && n=$((n+1))
    done
    echo "$n"
  }
  printf '%s keepers:%s | tree_pinned=%s load=%s\n' "$(cut -d. -f1 /proc/uptime)" "${line:- none}" "$(pin_tree)" "$(cut -d' ' -f1 /proc/loadavg)" >> $LOG
  sleep 1
  i=$((i+1))
done
KEEPER_MON
  chmod 755 $RD/keeper_mon.sh
  setsid sh $RD/keeper_mon.sh >/dev/null 2>&1 </dev/null &
  echo "keeper pinner started (log-pid + tree scan) -> $RD/keeper_watch.log"
  else
    echo "step 8c: keeper pinner disabled (no PIN_KEEPERS marker)"
  fi

  # ---- 8d. Drop the page cache. The shared-page corruption signature above is
  #          consistent with a poisoned CACHED page; evicting clean cache makes
  #          the next mapping re-read it from disk (which is intact - the device
  #          behaves until the next exploit run, and every reboot heals it).
  sync
  if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then
    echo "page cache dropped (poisoned cached pages evicted)"
  else
    echo "page cache drop failed"
  fi

  # ---- 9. Restore hardening knobs (BEFORE enforcing).
  if [ -n "$KR" ]; then
    if echo "$KR" > /proc/sys/kernel/kptr_restrict 2>/dev/null; then
      echo "kptr_restrict restored to $KR"
    else
      echo "kptr_restrict restore FAILED (still $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null))"
    fi
  fi
  echo 1 > /sys/module/module/parameters/sig_enforce 2>/dev/null && echo "sig_enforce restored to Y"

  # ══════════════════════════════════════════════════════════════════════════
  # ★★ 2.51（吸收 PPG 5.0.7）运行时开 sucompat：开 → 探活 → 失败回退 ★★
  #
  #   为什么不在 insmod 时开：sucompat 一旦生效，loader 自己（u:r:kernel:s0，
  #   不在 allowlist）立刻失去 exec，后面 ksud 加冕 / install / 健康检查全跑不了。
  #   PPG 的顺序是「装载时关着 → 跑完收尾 → feature set su_compat 1 → 5 秒探活 →
  #   不通就关回去」，这里照搬。
  # ══════════════════════════════════════════════════════════════════════════
  if [ "${DEFER_SUCOMPAT:-0}" = "1" ]; then
    echo "  [sucompat] DEFER_SUCOMPAT（本机装载后无法执行任何命令，此分支已停用）"
  fi

  # （2.52 的装载后 su overlay 段已删：装载后本进程连 stat 都失败，
  #   那段只会打出 "缺件" 的假阴性。overlay 现在统一在装载前做，见上面 2.55 段。）

  # ★ 2.67：收尾不再扫（理由同上，装载后 fork 不安全）

  # ---- 10. SELinux: 收尾切回严格（★ fix3-20261018，与 kit 路线对齐）
  #
  #   历史（改之前）：这里只在 $RD/ENFORCE 存在时才切，默认留 Permissive。
  #   依据是 2026-09-19 03:15 的实测：load 本身干净（health_check=1、ksud 四阶段
  #   rc=0），但切 Enforcing 后 zygote 立刻崩（"Critical Process: zygote Crashed"
  #   @ /data/log/log.db），系统跟着挂。
  #
  #   为什么现在敢改：那次崩的两个条件现在都不成立了 ——
  #     · 当时用的是 6.1.128 的 kernelsu_cga.ko（vermagic 不匹配），
  #       现在是 vermagic 逐字匹配的 os9-selx11；
  #     · 当时 /dev/su 没有 chcon（device 标签），Enforcing 下所有域丢 su
  #       ⇒ 系统服务连锁失败。kit 侧 2026-09-28 定位并修掉了同一个坑。
  #   所以收尾统一交给 _selinux_finalize：它先确认 /dev/su = ksu_file（否则不切，
  #   避免 kit 踩过的自锁），再 sleep 20 切，切完两次回读自证。
  #
  #   仍要宽容：touch $RD/KEEP_PERMISSIVE
  #
  #   ★ 调用点故意放在文件末尾（hisecd 解冻之后）：enforce 之后 kill -CONT 可能被拒，
  #     那会把 hisecd 永久冻住（Honor 的周期 root 扫描被卡 ⇒ 只能物理断电）。
  #     所以这里只留说明，真正的 `_selinux_finalize "$MOD"` 在 §thaw 之后。

  # NOTE: kmsg_dumper deliberately KEEPS RUNNING. The system can die tens of
  # seconds after a successful load (device-verified: zygote crash ~30s in,
  # then AP_S_PANIC), and the dumper is the only channel that survives a fast
  # panic — so we leave it writing $RD/kmsg_cap.txt and pull it after the next
  # boot instead of stopping it here.
  if [ -n "$KMSG_PID" ] && kill -0 "$KMSG_PID" 2>/dev/null; then
    echo "kmsg_dumper left running (pid $KMSG_PID) to capture a post-load death"
  else
    echo "kmsg_dumper not available (载荷里没有这个二进制) ⇒ 装载后死机就拿不到 kmsg"
  fi

  # Everything that needed hisecd frozen is done - thaw it now (the EXIT trap
  # would do it anyway; doing it explicitly keeps the log honest).
  #
  # EXPERIMENT (marker $RD/FREEZE_HISECD_LONG): SUPERSEDED - kept only to re-run.
  # It was tried on 2026-09-19 to test whether hisecd's anti-root reaction (the
  # unsigned-module uevent: HISEC: stp uevent ... mod-sign ... result=-61 ->
  # StaticCheckPolicy risk=1 -> static check) is what kills the device. It is
  # NOT: with hisecd frozen for the whole session the device still died, and
  # control experiment B showed hisecd's full reaction is harmless. See the
  # section 2 comment above. CAVEAT: a frozen hisecd wedges Honor's periodic
  # root scan and
  # makes `adb reboot` a no-op, so recovering needs a physical power cycle.
  if [ -f $RD/FREEZE_HISECD_LONG ]; then
    trap - 0   # cancel the thaw-on-exit so it really stays stopped
    echo "hisecd LEFT FROZEN (FREEZE_HISECD_LONG): recovery needs a power cycle"
  else
    if [ -n "$hp" ]; then kill -CONT $hp 2>/dev/null && echo "hisecd THAWED (end of flow) pid=$hp"; hp=""; fi
  fi

  # ★ fix3-20261018：SELinux 收尾放在最末尾 —— 先把 hisecd 解冻，再切严格。
  #   顺序反了的话，enforce 之后 kill -CONT 可能被拒，hisecd 会永久冻住。
  _stage su_cred_apply
  _su_cred_apply
  _stage mgr_selfheal
  _mgr_selfheal "$MOD"
  _stage selinux_finalize
  _selinux_finalize "$MOD"

  _stage fresh_selfcheck
  _fresh_selfcheck
  _stage probe_su
  _probe_su
  echo "=== final ==="
  timeout 10 grep -i kernelsu /proc/modules 2>/dev/null || echo "(no kernelsu)"
  getenforce
  fi   # ← MINIMAL 分支结束（上面的 if [ -f $RD/MINIMAL ]）
} >> $OUT 2>&1
echo "KSU_LOAD_DONE $OUT"

# ============================================================================
#  【本包新增】自定义 root 任务 hook（marker 门控，默认 no-op）
#  用途：NO_LOAD 模式下设备可长时间存活（实测 600s+ 无复位），而 loader 全程
#        以 uid 0 运行 —— 把你要做的 root 操作写进 /data/local/tmp/ksu/post_root.sh
#        即可获得一个"不受时间限制的 root 操作窗口"（代价：没有 KSU 的 su 框架）。
#  启用：adb shell touch /data/local/tmp/ksu/NO_LOAD   然后正常跑一轮
#  本 hook 只增不改，未创建 post_root.sh 时完全不执行。
# ============================================================================

# ── selx5 (2026-09-24): 会话 wakelock —— 防止休眠冻结窗口/管理器注入时机
if [ -w /sys/power/wake_lock ]; then
  echo ksu_session > /sys/power/wake_lock 2>/dev/null && echo "wake_lock ksu_session acquired"
else
  echo "(wake_lock not writable - skip)"
fi
