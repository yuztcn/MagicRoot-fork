# CVE-2026-98260 target metadata (6.1.157 AMG-AN00 / HONOR GT).
# Constants are compiled into exploit-android-key-ptr; metadata only.
#
# 这颗内核的 UTS_RELEASE 是 6.1.157-android14-11-g2646292297b1；
# run98260.sh 按前缀匹配，个别 ROM 追加后缀也不会误判。

CHAIN_98260_KERNEL=""
CHAIN_98260_MODELS="AMG-AN00"
CHAIN_98260_ROOT_SOCK="/data/local/tmp/pc98260-root.sock"
CHAIN_98260_EXPECTED_MEMSTART_PFN="0x80000"
