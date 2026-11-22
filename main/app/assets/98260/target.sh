# CVE-2026-98260 target metadata (6.12.58).
# Constants are compiled into exploit-android-key-ptr; metadata only.

CHAIN_98260_KERNEL="6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k"
CHAIN_98260_MODELS="MLY-AN00 BKQ-AN90"
CHAIN_98260_ROOT_SOCK="/data/local/tmp/pc98260-root.sock"
CHAIN_98260_EXPECTED_MEMSTART_PFN="0x80000"

# The KSU su node is created by the selected manager after the module is
# loaded and can take 60-120 seconds on SukiSU/BakaSU.  Wait long enough for
# the app-side manager launch to initialize it, but keep a bounded probe.
CHAIN_98260_SU_WAIT_TRIES=5
CHAIN_98260_PROVIDER_TRIES=1
