#!/bin/sh
# Rebuild main/app/assets/98260-h1c/cve98260_plant from the HOneClick sources
# with the compound-page pfn_in_line() fix (docs/61821-115-CHAIN-ANALYSIS.md).
#
# Upstream builds this helper statically with NDK r28c.  On hosts without a
# static bionic libc the same sources build as a portable PIE; the app-level
# strings are identical apart from the added `order=` token.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
out=${1:-"$here/../../main/app/assets/98260-h1c/cve98260_plant"}
cc=${CC:-clang}
"$cc" -O2 -s -fPIE -pie -Wno-macro-redefined \
    -o "$out" "$here/uaf_plant.c" "$here/pc98260_rootd.c"
echo "built $out"
sha256sum "$out" 2>/dev/null || shasum -a 256 "$out"
