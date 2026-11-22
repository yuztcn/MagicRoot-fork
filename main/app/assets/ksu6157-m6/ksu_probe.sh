#!/system/bin/sh
# ============================================================================
#  ksu_probe.sh —— 在 loader 的 uid=0 窗口内做 "ko 可行性核对"
#
#  为什么放在这里：真机实测这台 Magic6 Pro 的 rootd 通道只在提权后很短时间
#  内有效，之后就"无输出"。所有依赖 rootd 的事后诊断都必然失败。
#  而提权时 loader 自己是 uid=0 —— 那时候做核对最可靠。
#
#  v2（2026-10-15）：修正上一版的粗糙处
#    · 上一版报 "清单已写入设备：(失败)" 却仍算出结果 ⇒ 用的是设备上**残留的旧清单**
#    · 上一版报缺 commit_creds —— 内核核心符号，不该缺 ⇒ 疑似假阳性
#    本版：先确认清单真实就位（行数/首尾行），再用严格写法重算，并精确复查可疑符号。
#
#  只读：读 /proc/kallsyms、/proc/modules、ls。不加载任何模块。
# ============================================================================
RD=/data/local/tmp/ksu
OUT=$RD/ksu_probe.txt
mkdir -p $RD 2>/dev/null

{
echo "======== ksu_probe start $(date +%H:%M:%S) ========"
echo "uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "kernel=$(uname -r)"
echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
echo "uptime=$(cut -d. -f1 /proc/uptime)"
echo "selinux=$(getenforce 2>/dev/null)"
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
echo "modules_count=$(grep -c . /proc/modules 2>/dev/null)"

# ---- 1. 清单就位确认（上一版就是这里没查，导致用了旧数据） ----
echo
echo "==== 1. 符号清单就位确认 ===="
for f in need_syms.txt need_syms_official61.txt; do
  if [ -s $RD/$f ]; then
    echo "$f : OK  lines=$(wc -l < $RD/$f) bytes=$(wc -c < $RD/$f)"
    echo "   head: $(head -1 $RD/$f)"
    echo "   tail: $(tail -1 $RD/$f)"
  else
    echo "$f : ** 缺失或为空 **"
  fi
done

# ---- 2. 建 have 列表 ----
echo
echo "==== 2. kallsyms 符号总数 ===="
awk '{print $3}' /proc/kallsyms 2>/dev/null | sort -u > $RD/_have.txt
echo "have_symbols=$(wc -l < $RD/_have.txt)"

# ---- 3. 严格核对（每行一个符号、精确匹配） ----
echo
echo "==== 3. ko 符号核对（kit 6.1.128 ko）===="
if [ -s $RD/need_syms.txt ]; then
  awk 'NF==1 && $1 !~ /^#/' $RD/need_syms.txt > $RD/_need.txt
  echo "need_symbols=$(wc -l < $RD/_need.txt)"
  echo "--- MISSING ---"
  grep -F -x -v -f $RD/_have.txt $RD/_need.txt 2>/dev/null | head -60
  echo "--- MISSING_COUNT ---"
  grep -F -x -v -f $RD/_have.txt $RD/_need.txt 2>/dev/null | wc -l
else
  echo "(need_syms.txt 不可用 —— 跳过)"
fi

echo
echo "==== 4. 官方 6.1 LKM 的符号（226 个）===="
if [ -s $RD/need_syms_official61.txt ]; then
  awk 'NF==1 && $1 !~ /^#/' $RD/need_syms_official61.txt > $RD/_needo.txt
  echo "need_official=$(wc -l < $RD/_needo.txt)"
  echo "--- MISSING_OFFICIAL ---"
  grep -F -x -v -f $RD/_have.txt $RD/_needo.txt 2>/dev/null | head -60
  echo "--- MISSING_OFFICIAL_COUNT ---"
  grep -F -x -v -f $RD/_have.txt $RD/_needo.txt 2>/dev/null | wc -l
else
  echo "(need_syms_official61.txt 不可用 —— 跳过)"
fi

# ---- 5. 复查可疑符号（上一版报缺 commit_creds —— 内核核心符号，不该缺） ----
echo
echo "==== 5. 可疑符号复查（kallsyms 原始行）===="
for s in commit_creds __change_memory_common kallsyms_lookup_name init_task; do
  line=$(grep -w "$s" /proc/kallsyms 2>/dev/null | head -1)
  if [ -n "$line" ]; then
    echo "$s : 存在 -> $line"
  else
    echo "$s : ** kallsyms 里查不到 **"
  fi
done
echo "--- 所有含 commit_creds 的符号名 ---"
awk '{print $3}' /proc/kallsyms 2>/dev/null | grep -i commit_creds | head -6
echo "--- 所有含 change_memory 的符号名 ---"
awk '{print $3}' /proc/kallsyms 2>/dev/null | grep -i change_memory | head -6

# ---- 6. 当前内核模块状态 ----
echo
echo "==== 6. 当前内核模块状态 ===="
grep -i kernelsu /proc/modules 2>/dev/null || echo "(no kernelsu module)"
echo "--- loadko_result 关键行 ---"
grep -i 'undefined\|resolved\|patched\|loaded\|unresolved' $RD/loadko_result.log 2>/dev/null | head -8

# ---- 7. 现有 root 入口 ----
echo
echo "==== 7. 现有 root 入口 ===="
echo "dev_su=$(ls -l /dev/su 2>&1 | head -1)"
echo "system_bin_su=$(ls -l /system/bin/su 2>&1 | head -1)"
echo "adb_ksud=$(ls -l /data/adb/ksud 2>&1 | head -1)"

echo
echo "======== ksu_probe end $(date +%H:%M:%S) ========"
} > $OUT 2>&1

chmod 666 $OUT 2>/dev/null
rm -f $RD/_have.txt $RD/_need.txt $RD/_needo.txt 2>/dev/null
echo "ksu_probe done -> $OUT ($(wc -l < $OUT 2>/dev/null) lines)"
