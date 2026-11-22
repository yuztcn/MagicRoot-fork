#!/bin/bash
# Static KernelSU flavor asset audit.  For every supported 98260/64560
# profile, run the same ksu_select_ko() used on-device and report whether the
# selected template and symbol table exist.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ASSETS="$HERE/../main/app/assets"
cd "$ASSETS" || exit 1
D=$PWD
. ./kernel_profiles.sh

echo "profile  flavor    result                 template / syms"
failures=0
for p in 61258 61258b 61258c 6138 6138y 6123 g856 g142 61821 61821brm g554 f171 6658 6689 ga812 g893 g4b36 aph112 g52d15; do
  for f in kernelsu resukisu next sukisu fina; do
    KO_TEMPLATE=""; SYMS=""; FLAVOR_SYMS_MISSING=0
    ksu_select_ko "$p" "$f" >/dev/null 2>&1
    ko=${KO_TEMPLATE:-}; sy=${SYMS:-}
    result=OK
    [ -f "$ko" ] || { result=KO_MISSING; failures=$((failures + 1)); }
    [ -f "$sy" ] || { result="${result},SYMS_MISSING"; failures=$((failures + 1)); }
    [ "${FLAVOR_SYMS_MISSING:-0}" = "0" ] || { result="${result},ROUTER_UNSUPPORTED"; failures=$((failures + 1)); }
    printf '%-8s %-9s %-22s %s / %s\n' "$p" "$f" "$result" "$(basename "$ko")" "$(basename "$sy")"
  done
done

# SukiSU Nova uses a manager-extracted LKM, so only the symbol table is
# bundled.  These profiles have an exact kallsyms/ELF source and a completed
# syms_<profile>_nova.txt; routing must select it without a fallback.
for p in 61258 61258c g856 6138 g142 g554 f171 6658 6689 ga812 g893 g4b36 g52d15; do
  KO_TEMPLATE=""; SYMS=""; FLAVOR_SYMS_MISSING=0
  ksu_select_ko "$p" nova >/dev/null 2>&1
  ko=${KO_TEMPLATE:-}; sy=${SYMS:-}
  case "$(basename "$sy")" in
    *_nova.txt) ;;
    *) printf 'BAD nova %-8s syms=%s (expected *_nova.txt)\n' "$p" "$sy"
       failures=$((failures + 1)) ;;
  esac
  [ -f "$ko" ] || { printf 'BAD nova %-8s ko missing=%s\n' "$p" "$ko"; failures=$((failures + 1)); }
  [ -f "$sy" ] || { printf 'BAD nova %-8s syms missing=%s\n' "$p" "$sy"; failures=$((failures + 1)); }
  [ "${FLAVOR_SYMS_MISSING:-0}" = "0" ] || {
    printf 'BAD nova %-8s router unsupported\n' "$p"; failures=$((failures + 1)); }
done
# No exact image is available for these builds: Nova must fail closed instead
# of borrowing another kernel's symbol addresses.
for p in 61258b 6138y 6123; do
  KO_TEMPLATE=""; SYMS=""; FLAVOR_SYMS_MISSING=0
  ksu_select_ko "$p" nova >/dev/null 2>&1
  [ "${FLAVOR_SYMS_MISSING:-0}" = "1" ] || {
    printf 'BAD nova %-8s did not fail closed syms=%s\n' "$p" "${SYMS:-}"
    failures=$((failures + 1)); }
done

# g142 must have a real 64560 route as well as the existing 98260 route.
g142_release=6.12.58-android16-6-g142ddad31e60-abogki576095858-4k
for f in kernelsu resukisu next sukisu fina nova; do
  MAGICROOT_KSU_FLAVOR=$f
  export MAGICROOT_KSU_FLAVOR
  select_kernel_profile "$g142_release" ANY >/dev/null
  if [ "$PROFILE_ID" != "g142" ] ||
     [ "$KASLR_BIN" != "$D/kaslr_slide_aph136g142" ] || [ ! -x "$KASLR_BIN" ] ||
     [ ! -f "$SYMS" ] || [ ! -f "$KO_TEMPLATE" ] ||
     [ "$PROFILE_KASLR_PREPARE_LINK" != "0xffffffc0801935b8" ] ||
     [ "$PROFILE_KASLR_SELINUX_LINK" != "0xffffffc0827e7a60" ]; then
    printf 'BAD g142 64560 route flavor=%s kaslr=%s syms=%s ko=%s\n' \
      "$f" "$KASLR_BIN" "$SYMS" "$KO_TEMPLATE"
    failures=$((failures + 1))
  fi
done
select_chain_98260_profile "$g142_release" ANY
if [ "$PROFILE_ID" != "honor-g142-98260" ]; then
  echo "BAD g142 98260 route profile=$PROFILE_ID"
  failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL flavor/route audit failures=$failures" >&2
  exit 1
fi
echo "PASS flavor/route audit (including g142 64560 + 98260)"