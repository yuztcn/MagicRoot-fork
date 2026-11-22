from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")

start = t.find("KO_CACHE_DIR=${KO_CACHE_DIR:-/data/local/tmp/.magic-ko-cache}\nprune_ko_cache() {")
end_marker = 'if [ "$MODULE_ALREADY_LIVE_ENFORCING" = "1" ]; then'
end = t.find(end_marker)
if start < 0 or end < 0:
    raise SystemExit("ko cache block anchors missing")
old = t[start:end]

new = '''KO_CACHE_DIR=${KO_CACHE_DIR:-/data/local/tmp/.magic-ko-cache}

# Stable content hash for cache identity.  Android toybox normally provides
# sha256sum; fall back to cksum/stat only on unusual systems.
file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    elif command -v md5sum >/dev/null 2>&1; then
        md5sum "$1" 2>/dev/null | awk '{print $1}'
    else
        stat -c '%s:%Y' "$1" 2>/dev/null
    fi
}
key_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum 2>/dev/null | awk '{print $1}' | cut -c1-32
    elif command -v cksum >/dev/null 2>&1; then
        printf '%s' "$1" | cksum 2>/dev/null | awk '{print $1}'
    else
        printf '%s' "$1" | tr ': |' '___' | cut -c1-24
    fi
}

prune_ko_cache() {
    [ -d "$KO_CACHE_DIR" ] || return 0
    [ "$KO_CACHE_MAX" -ge 1 ] 2>/dev/null || KO_CACHE_MAX=6
    [ "$KO_CACHE_DAYS" -ge 1 ] 2>/dev/null || KO_CACHE_DAYS=7
    find "$KO_CACHE_DIR" -maxdepth 1 -type f -name "*.ko" -mtime +"$KO_CACHE_DAYS" -delete 2>/dev/null || true
    # Remove orphan sidecars whose .ko was deleted by the age pass.
    for _meta in "$KO_CACHE_DIR"/*.key; do
        [ -e "$_meta" ] || continue
        [ -e "${_meta%.key}.ko" ] || rm -f "$_meta" 2>/dev/null || true
    done
    # Keep the current entry unconditionally; KO_CACHE_MAX is only a disk
    # retention limit, never a flavor-selection input.
    _keep_other=$((KO_CACHE_MAX - 1))
    [ "$_keep_other" -ge 0 ] 2>/dev/null || _keep_other=0
    _ko_list=$(ls -1t "$KO_CACHE_DIR"/*.ko 2>/dev/null || true)
    if [ -n "$KO_PERSIST" ] && [ -n "$_ko_list" ]; then
        _ko_list=$(printf '%s\\n' "$_ko_list" | grep -vF "$KO_PERSIST" 2>/dev/null || true)
    fi
    if [ -n "$_ko_list" ]; then
        printf '%s\\n' "$_ko_list" | tail -n +$((_keep_other + 1)) | while IFS= read -r old; do
            [ -n "$old" ] || continue
            rm -f "$old" "${old%.ko}.key" 2>/dev/null || true
        done
    fi
}

patch_ko() {
    echo "== 2. patch KernelSU module =="
    echo "KSU_FLAVOR=$KSU_FLAVOR KSU_KMI=source=$(cat "$D/ko_source_kmi" 2>/dev/null || echo 6.12.76) target=$(uname -r) strategy=vermagic+sym_rebase portable=yes exact_target_build=no"
    KO_CACHE="$D/ko.cache"
    KO_CACHE_DIR=${KO_CACHE_DIR:-/data/local/tmp/.magic-ko-cache}
    KO_TEMPLATE_SHA=$(file_sha256 "$KO_TEMPLATE")
    KO_SYMS_SHA=$(file_sha256 "$SYMS")
    KO_PATCH_SHA=$(file_sha256 "$D/ko_patch")
    KO_KEY=""
    if [ -n "$BOOT_ID" ]; then
        # Flavor + profile + template/syms content hashes are all identity
        # inputs.  Do not rely on size/mtime alone: a replaced same-size
        # template must never hit an old cache entry.
        KO_KEY="$BOOT_ID|$PROFILE_ID|$SLIDE|$(uname -r)|$KSU_FLAVOR|$(basename "$KO_TEMPLATE")|$KO_TEMPLATE_SHA|$(basename "$SYMS")|$KO_SYMS_SHA|$KO_PATCH_SHA"
    fi
    echo "KO_CACHE_IDENTITY flavor=$KSU_FLAVOR profile=$PROFILE_ID template=$(basename "$KO_TEMPLATE"):${KO_TEMPLATE_SHA:-none} syms=$(basename "$SYMS"):${KO_SYMS_SHA:-none} keep=$KO_CACHE_MAX"
    KO_CACHE_HIT=0
    KO_PERSIST=""
    KO_PERSIST_KEY=""
    if [ -n "$KO_KEY" ]; then
        KO_TAG=$(key_hash "$KO_KEY")
        KO_PERSIST="$KO_CACHE_DIR/$KO_TAG.ko"
        KO_PERSIST_KEY="$KO_CACHE_DIR/$KO_TAG.key"
    fi
    if [ -n "$KO_KEY" ] && [ -s "$D/ksu-patched.ko" ] && [ -f "$KO_CACHE" ] &&
       [ "$(cat "$KO_CACHE" 2>/dev/null)" = "$KO_KEY" ]; then
        KO_CACHE_HIT=1
        echo "KO_CACHE_HIT boot_id=$BOOT_ID flavor=$KSU_FLAVOR profile=$PROFILE_ID"
    elif [ -n "$KO_PERSIST" ] && [ -s "$KO_PERSIST" ] && [ -f "$KO_PERSIST_KEY" ] &&
         [ "$(cat "$KO_PERSIST_KEY" 2>/dev/null)" = "$KO_KEY" ]; then
        mkdir -p "$KO_CACHE_DIR" 2>/dev/null || true
        cp -f "$KO_PERSIST" "$D/ksu-patched.ko" 2>/dev/null && {
            printf "%s\\n" "$KO_KEY" > "$KO_CACHE" 2>/dev/null || true
            KO_CACHE_HIT=1
            echo "KO_CACHE_RESTORED boot_id=$BOOT_ID flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        }
    elif [ -n "$KO_PERSIST" ] && [ -s "$KO_PERSIST" ]; then
        # Legacy/mismatched entry (written before content-hash sidecars, or a
        # tag collision from the old truncated filename).  Never load it.
        echo "KO_CACHE_STALE reason=key_missing_or_mismatch tag=$KO_TAG flavor=$KSU_FLAVOR"
        rm -f "$KO_PERSIST" "$KO_PERSIST_KEY" 2>/dev/null || true
    fi
    if [ "$KO_CACHE_HIT" != "1" ]; then
        rm -f "$D/ko_patch.self" 2>/dev/null || true
        "$D/ko_patch" "$KO_TEMPLATE" "$D/ksu-patched.ko" "$SYMS" "$SLIDE" "$(uname -r)" > "$D/ko_patch.log" 2>&1
        KO_PATCH_RC=$?
        cat "$D/ko_patch.log" 2>/dev/null
        if [ "$KO_PATCH_RC" != "0" ]; then
            echo "FAIL=ko_patch rc=$KO_PATCH_RC"
            return 3
        fi
        # patched/missing self-check: a missing symbol means the module would
        # fail to load with ENOENT later; refuse before touching the kernel.
        KO_PATCH_LINE=$(grep -m1 '^PATCHED=' "$D/ko_patch.log" 2>/dev/null)
        KO_PATCHED=$(printf '%s\\n' "$KO_PATCH_LINE" | sed -n 's/^PATCHED=\\([0-9][0-9]*\\) MISSING=\\([0-9][0-9]*\\).*/\\1/p')
        KO_MISSING=$(printf '%s\\n' "$KO_PATCH_LINE" | sed -n 's/^PATCHED=\\([0-9][0-9]*\\) MISSING=\\([0-9][0-9]*\\).*/\\2/p')
        SYMS_N=$(grep -c '[^[:space:]]' "$SYMS" 2>/dev/null)
        case "$SYMS_N" in ''|*[!0-9]*) SYMS_N=0 ;; esac
        echo "KO_PATCH_SELF_CHECK=patched=${KO_PATCHED:-none} missing=${KO_MISSING:-none} syms=$SYMS_N template=$(basename "$KO_TEMPLATE") flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        if [ -z "$KO_PATCHED" ] || [ -z "$KO_MISSING" ]; then
            echo "FAIL=ko_patch_selfcheck_unparsed log=$D/ko_patch.log"
            return 3
        fi
        if [ "$KO_MISSING" != "0" ]; then
            echo "FAIL=ko_patch_missing missing=$KO_MISSING patched=$KO_PATCHED syms=$SYMS_N flavor=$KSU_FLAVOR"
            echo "HINT=syms table does not cover the module's undefined symbols for this KMI"
            return 3
        fi
        if [ "$KO_PATCHED" -le 0 ]; then
            echo "FAIL=ko_patch_patched_zero syms=$SYMS_N"
            return 3
        fi
        printf '%s\\n' "$KO_PATCH_LINE" > "$D/ko_patch.self" 2>/dev/null || true
        if [ -n "$KO_KEY" ]; then
            printf '%s\\n' "$KO_KEY" > "$KO_CACHE" 2>/dev/null || true
            if [ -n "$KO_PERSIST" ]; then
                mkdir -p "$KO_CACHE_DIR" 2>/dev/null || true
                cp -f "$D/ksu-patched.ko" "$KO_PERSIST" 2>/dev/null || true
                printf '%s\\n' "$KO_KEY" > "$KO_PERSIST_KEY" 2>/dev/null || true
                echo "KO_CACHE_SAVED flavor=$KSU_FLAVOR profile=$PROFILE_ID tag=$KO_TAG"
            fi
        fi
    else
        echo "KO_PATCH_SKIPPED reason=same_boot_slide_template flavor=$KSU_FLAVOR profile=$PROFILE_ID"
        if [ -f "$D/ko_patch.self" ]; then
            echo "KO_PATCH_SELF_CHECK_CACHED=$(cat "$D/ko_patch.self" 2>/dev/null)"
        else
            echo "KO_PATCH_SELF_CHECK=skipped reason=ko_cache"
        fi
    fi
    prune_ko_cache
    echo "KO_CACHE_KEEP=$KO_CACHE_MAX AGE_DAYS=$KO_CACHE_DAYS dir=$KO_CACHE_DIR (retention only; not a flavor selector)"
    return 0
}

'''
t = t[:start] + new + t[end:]
p.write_text(t, encoding="utf-8", newline="\n")
print(f"replaced ko cache/patch block: {len(old)} -> {len(new)} bytes")
