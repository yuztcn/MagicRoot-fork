# CVE-2026-98260 target metadata (6.18.21 g928)
CHAIN_98260_KERNEL="6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k"
CHAIN_98260_MODELS="WKL-AN20 WKL-AN80"
CHAIN_98260_ROOT_SOCK="/data/local/tmp/pc98260-root.sock"
CHAIN_98260_EXPECTED_MEMSTART_PFN="0x80000"
# 6.18 g928 only: real_cred is required, page freeing is slow, and a page
# miss must hard-abort.  6.6/6.12 profiles leave these unset.
CHAIN_98260_REAL_CRED=1
CHAIN_98260_ABORT_PAGE_MISS=1
CHAIN_98260_WAIT_CAP=25
