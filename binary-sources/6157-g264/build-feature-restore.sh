#!/bin/bash
# Rebuild the g264 feature-restored CGA base and optionally derive gaaa.
# The output directory must be new or empty.  No device command or APK asset
# installation is performed by this script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT=${1:?"usage: build-feature-restore.sh <new-output-dir>"}
: "${CGA_PACKAGE:?extracted CGA package root with obj/}"
: "${KERNEL_SRC:?Android 6.1 kernel source directory}"
: "${KDIR:?prebuilt/generated Android 6.1 header directory}"
: "${KERNELSU_SRC:?KernelSU v3.3.1 source directory}"
: "${CGA_CC:=clang}"
: "${LD_LLD:=ld.lld}"
: "${GAAA_VMLINUX:=}"
: "${GAAA_BOOT_SHA256:=a41aa37fc83e39334a1805bcd3f510c860d76e6dd02e44db762012f6caf9e524}"

if [ -d "$OUT" ] && [ -n "$(find "$OUT" -mindepth 1 -print -quit)" ]; then
    echo "output directory is not empty: $OUT" >&2
    exit 2
fi
if [ ! -d "$CGA_PACKAGE/obj" ] || [ ! -d "$KERNELSU_SRC/kernel" ]; then
    echo "invalid CGA package or KernelSU source" >&2
    exit 2
fi
if [ -d "$KERNELSU_SRC/.git" ]; then
    actual=$(git -C "$KERNELSU_SRC" rev-parse HEAD)
    [ "$actual" = "0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d" ] || {
        echo "KernelSU revision mismatch: $actual" >&2
        exit 2
    }
fi
read -r -a CC <<< "$CGA_CC"
if [ "${CGA_ALLOW_OTHER_COMPILER:-0}" != "1" ]; then
    "${CC[@]}" --version | grep -q 'clang version 18.1.6' || {
        echo "CGA_CC must be the original Zig 0.13 Clang 18.1.6" >&2
        exit 2
    }
fi

mkdir -p "$OUT/obj" "$OUT/KernelSU" "$OUT/zig-global" "$OUT/zig-local"
cp -a "$KERNELSU_SRC/." "$OUT/KernelSU/"
cp "$ROOT/binary-sources/6157-g264/cga/init.c" "$OUT/KernelSU/kernel/core/init_noselinux.c"
cp "$ROOT/binary-sources/6157-g264/cga/hookmgr.c" "$OUT/KernelSU/kernel/hook/hookmgr_nohook.c"
cp "$ROOT/binary-sources/6157-g264/cga/supercall.c" "$OUT/KernelSU/kernel/supercall/supercall.c"
cp "$ROOT/binary-sources/6157-g264/cga/arm64_syscall_hook.c" "$OUT/KernelSU/kernel/hook/arm64/syscall_hook.c"
cp "$ROOT/binary-sources/6157-g264/cga/syscall_hook.h" "$OUT/KernelSU/kernel/hook/syscall_hook.h"
cp "$ROOT/binary-sources/6157-g264/cga/ksu_build_cfg.h" "$OUT/ksu_build_cfg.h"
cp "$CGA_PACKAGE/obj/"*.o "$OUT/obj/"

compile() {
    local source=$1 output=$2
    env ZIG_GLOBAL_CACHE_DIR="$OUT/zig-global" ZIG_LOCAL_CACHE_DIR="$OUT/zig-local" \
        "${CC[@]}" \
        -target aarch64-freestanding \
        -c "$source" -o "$output" \
        -O2 -g0 -fsanitize=kcfi -ffixed-x18 \
        -fno-pic -fno-pie -fno-stack-protector -fomit-frame-pointer \
        -fno-asynchronous-unwind-tables -fno-unwind-tables \
        -mcmodel=small -fno-strict-aliasing -fshort-wchar \
        -nostdinc -ffreestanding -fno-builtin -fno-common -Wno-everything \
        -D__NO_FORTIFY -D__KERNEL__ -DMODULE \
        -include "$OUT/ksu_build_cfg.h" \
        -I "$KERNEL_SRC/arch/arm64/include" \
        -I "$KDIR/arch/arm64/include/generated" \
        -I "$KDIR/include" \
        -I "$KERNEL_SRC/include" \
        -I "$KERNEL_SRC/arch/arm64/include/uapi" \
        -I "$KDIR/arch/arm64/include/generated/uapi" \
        -I "$KERNEL_SRC/include/uapi" \
        -I "$KDIR/include/generated/uapi" \
        -I "$KERNEL_SRC/security/selinux" \
        -I "$KERNEL_SRC/security/selinux/include" \
        -I "$OUT/KernelSU/kernel" \
        -I "$OUT/KernelSU/kernel/include" \
        -include "$KERNEL_SRC/include/linux/compiler-version.h" \
        -include "$KERNEL_SRC/include/linux/kconfig.h"
}

compile "$OUT/KernelSU/kernel/core/init_noselinux.c" "$OUT/obj/init.o"
compile "$OUT/KernelSU/kernel/hook/hookmgr_nohook.c" "$OUT/obj/hookmgr.o"
compile "$OUT/KernelSU/kernel/supercall/supercall.c" "$OUT/obj/supercall.o"
compile "$OUT/KernelSU/kernel/hook/arm64/syscall_hook.c" "$OUT/obj/hook_arm64_syscall_hook.o"

"$LD_LLD" -r -z max-page-size=4096 -o "$OUT/ksm-raw.ko" "$OUT/obj/"*.o
python3 -I "$ROOT/binary-sources/6157-g264/pipeline/slim2.py" "$OUT/ksm-raw.ko" "$OUT/ksm-s1.ko"
LEGACY_CGA_BASE="${CGA_LEGACY_BASE:-$ROOT/binary-sources/61157-g264/legacy-cga/ksm-g264-base.ko}"
[ -f "$LEGACY_CGA_BASE" ] || {
    echo "missing audit base: $LEGACY_CGA_BASE" >&2
    echo "the 225/220 base is no longer stored in the public tree; set CGA_LEGACY_BASE to a local copy" >&2
    exit 1
}
python3 -I "$ROOT/binary-sources/6157-g264/pipeline/extract_abs_symbols.py" \
    "$LEGACY_CGA_BASE" \
    "$OUT/g264-restore-syms.txt" "$ROOT/main/app/assets/ksu6157-g264/ksu-syms.txt"
CGA_ELF_SYMS="$OUT/g264-restore-syms.txt" python3 -I \
    "$ROOT/binary-sources/6157-g264/pipeline/offrelink6.py" "$OUT/ksm-s1.ko" "$OUT/ksm-r0.ko" 0
python3 -I "$ROOT/binary-sources/6157-g264/pipeline/set_vermagic.py" \
    "$OUT/ksm-r0.ko" "$OUT/ksm-g264-base.ko" "6.1.157-android14-11-g2646292297b1"

BASE_HASH=$(sha256sum "$OUT/ksm-g264-base.ko" | cut -d' ' -f1)
if [ -n "$GAAA_VMLINUX" ]; then
    CGA_BASE_SHA256=$BASE_HASH CGA_EXPECTED_ABS=226 CGA_EXPECTED_STUBS=221 \
        python3 -I "$ROOT/binary-sources/61157-g264/rebase_cga_module.py" extract \
        --base "$OUT/ksm-g264-base.ko" \
        --vmlinux "gaaa=$GAAA_VMLINUX" \
        --boot-sha256 "gaaa=$GAAA_BOOT_SHA256" \
        --kernel gaaa=6.1.157-android14-11-gaaa383620ebf \
        --output "$OUT/cga-feature-restore.json"
    CGA_BASE_SHA256=$BASE_HASH CGA_EXPECTED_ABS=226 CGA_EXPECTED_STUBS=221 \
        python3 -I "$ROOT/binary-sources/61157-g264/rebase_cga_module.py" apply \
        --base "$OUT/ksm-g264-base.ko" --profiles "$OUT/cga-feature-restore.json" \
        --output-root "$OUT" --only gaaa
fi

python3 -I "$ROOT/binary-sources/6157-g264/pipeline/checkprintk.py" "$OUT/ksm-g264-base.ko"
if [ -f "$OUT/ksm-gaaa-base.ko" ]; then
    python3 -I "$ROOT/binary-sources/6157-g264/pipeline/checkprintk.py" "$OUT/ksm-gaaa-base.ko"
fi
sha256sum "$OUT/ksm-g264-base.ko" "$OUT"/ksm-gaaa-base.ko 2>/dev/null || true
