from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")
old = '''    else
        echo "KO_PATCH_SKIPPED reason=same_boot_slide_template"
    fi
    prune_ko_cache'''
new = '''    else
        echo "KO_PATCH_SKIPPED reason=same_boot_slide_template"
        if [ -f "$D/ko_patch.self" ]; then
            echo "KO_PATCH_SELF_CHECK_CACHED=$(cat "$D/ko_patch.self" 2>/dev/null)"
        else
            echo "KO_PATCH_SELF_CHECK=skipped reason=ko_cache"
        fi
    fi
    prune_ko_cache'''
if old not in t:
    raise SystemExit("anchor missing")
p.write_text(t.replace(old, new, 1), encoding="utf-8", newline="\n")
print("patched cache-hit self-check")
