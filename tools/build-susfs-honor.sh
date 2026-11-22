#!/bin/sh
# Build a SUSFS guard for a specific Android GKI KMI inside the upstream DDK
# image.  Run this from the vendored susfs4ksu-lkm directory (or set SRC).
#
# Usage:
#   VARIANT=android16-6.12 KDIR=/opt/ddk/src/android16-6.12 \
#     sh tools/build-susfs-honor.sh
#
# Expected environment: Linux + clang/LLVM + a prepared KDIR with headers and
# Module.symvers.  The pinned DDK images are listed in
# docs/susfs-honor-adaptation-2026-10-29.md.
set -eu

VARIANT=${VARIANT:?set VARIANT, e.g. android16-6.12}
KDIR=${KDIR:?set KDIR to a prepared kernel build tree}
SRC=${SRC:-$(CDPATH= cd -- "$(dirname -- "$0")/../lkm/susfs4ksu-lkm" && pwd)}
OUT=${OUT:-/out/susfs_guard_lkm-$VARIANT.ko}

case "$VARIANT" in
    android16-6.12|android15-6.6|android17-6.18) ;;
    *) echo "unsupported VARIANT: $VARIANT" >&2; exit 2 ;;
esac

[ -d "$KDIR" ] || { echo "KDIR missing: $KDIR" >&2; exit 2; }
[ -d "$SRC/kernel" ] || { echo "guard source missing: $SRC/kernel" >&2; exit 2; }

export ARCH=arm64
make -C "$KDIR" M="$SRC/kernel" ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 \
    modules -j"$(nproc)"

cp "$SRC/kernel/susfs_guard_lkm.ko" "$OUT"
python3 "$(dirname -- "$0")/check_susfs_guard.py" "$OUT" --kmi "$VARIANT"
echo "BUILD_SUSFS_DONE $OUT"
