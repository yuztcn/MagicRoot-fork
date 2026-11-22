from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")

old = '''file_sha256() {
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
}'''
new = '''file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        _h=$(sha256sum "$1" 2>/dev/null | awk '{print $1}')
        [ -n "$_h" ] && { printf '%s\\n' "$_h"; return 0; }
    fi
    if command -v md5sum >/dev/null 2>&1; then
        _h=$(md5sum "$1" 2>/dev/null | awk '{print $1}')
        [ -n "$_h" ] && { printf '%s\\n' "$_h"; return 0; }
    fi
    stat -c '%s:%Y' "$1" 2>/dev/null
}
key_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        _h=$(printf '%s' "$1" | sha256sum 2>/dev/null | awk '{print $1}' | cut -c1-32)
        [ -n "$_h" ] && { printf '%s\\n' "$_h"; return 0; }
    fi
    if command -v cksum >/dev/null 2>&1; then
        _h=$(printf '%s' "$1" | cksum 2>/dev/null | awk '{print $1}')
        [ -n "$_h" ] && { printf '%s\\n' "$_h"; return 0; }
    fi
    printf '%s\\n' "$1" | tr ': |' '___' | cut -c1-24
}'''
if old not in t:
    raise SystemExit("hash function anchor missing")
t = t.replace(old, new, 1)

old2 = '''    _keep_other=$((KO_CACHE_MAX - 1))
    [ "$_keep_other" -ge 0 ] 2>/dev/null || _keep_other=0'''
new2 = '''    if [ -n "$KO_PERSIST" ]; then
        _keep_other=$((KO_CACHE_MAX - 1))
    else
        _keep_other=$KO_CACHE_MAX
    fi
    [ "$_keep_other" -ge 0 ] 2>/dev/null || _keep_other=0'''
if old2 not in t:
    raise SystemExit("keep-other anchor missing")
t = t.replace(old2, new2, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("hash fallback and no-persist prune fixed")
