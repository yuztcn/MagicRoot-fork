#!/system/bin/sh
# post_root v4-minimal (W3 Bad Epoll) —— NO_LOAD uid0 窗口内执行
# 目标：最快完成窗口内必做事（kptr_restrict + 真地址 kallsyms 快照），然后重武装
# rootd 常驻通道（命中一次全 boot 可用，600s+ 不复位）。
# 诊断版逻辑已备份到 tools/post_root_v3diag.bak.sh
RD=/data/local/tmp/ksu

# 【真阳性守卫】非 uid0（miss 轮 loader 以 shell 跑到这里）直接退出：
# 否则 shell 也能 cat 出全零 kallsyms，w3_kallsyms_full.txt 会被误当命中证据
if [ "$(id -u)" != "0" ]; then
  echo "post_root: NOT uid0 (uid=$(id -u)) - skip (miss round)"
  exit 0
fi

echo "=== post_root v4-minimal start $(date +%H:%M:%S) uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null) ==="

# 1) 窗口内必做：放开 kptr_restrict（shell 侧后续不可做）
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
echo "kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"

# 2) 全量 kallsyms 真地址快照（本 boot 专属 = 符号 oracle）
cat /proc/kallsyms > $RD/w3_kallsyms_full.txt 2>/dev/null
chmod 640 $RD/w3_kallsyms_full.txt 2>/dev/null   # harden: 不再让任意 App 读全量 kallsyms（KASLR）
# 2b) 内核日志全量快照（模块装载/sucompat verify 的证据链，窗口外 dmesg 被拒）
dmesg > $RD/ksu_dmesg_snapshot.txt 2>/dev/null
chmod 640 $RD/ksu_dmesg_snapshot.txt 2>/dev/null   # harden: dmesg 里有内核地址
chmod 640 $RD/w3_kallsyms_full.txt 2>/dev/null   # harden: 不再让任意 App 读全量 kallsyms（KASLR）
wc -l $RD/w3_kallsyms_full.txt

# 3) slabinfo 快照
cat /proc/slabinfo > $RD/w3_slabinfo.txt 2>/dev/null
chmod 640 $RD/w3_slabinfo.txt 2>/dev/null

# 4) 不启动历史诊断套件的 FIFO eval 服务。
# 当前 MagicRoot 的 M6 交接没有任何 rootd.fifo/rootd.out 消费者；保留一个
# root:shell 可写的常驻命令服务会在主 rootd 清理后留下第二条提权入口。
# kptr_restrict、kallsyms、dmesg 和 slabinfo 快照仍由上面的只读步骤完成。
echo "post_root: persistent FIFO root service disabled (unused by M6 handoff)"
echo "=== post_root v4-minimal done ==="
