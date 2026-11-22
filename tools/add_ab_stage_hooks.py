from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\run.sh")
t = p.read_text(encoding="utf-8")

a1 = '''    echo "fsuid step done (CapBnd 由 helper 在 phase1 后写入 CAPBND_OK)"
fi

echo "== 6. phase1+phase2 =="'''
b1 = '''    echo "fsuid step done (CapBnd 由 helper 在 phase1 后写入 CAPBND_OK)"
fi
# Device A/B hook: stop after the fsuid stage so fsuid parameters can be
# compared without running cred/module.
if [ "${MAGICROOT_AB_STAGE:-}" = "fsuid" ]; then
    echo "AB_STAGE_OK stage=fsuid"
    exit 0
fi

echo "== 6. phase1+phase2 =="'''
if a1 not in t:
    raise SystemExit("fsuid anchor missing")
t = t.replace(a1, b1, 1)

a2 = '''        echo "FAIL=skip_fsuid_finit"
        exit 7
    fi
fi

echo "== 7. KernelSU userspace =="'''
b2 = '''        echo "FAIL=skip_fsuid_finit"
        exit 7
    fi
fi
# Device A/B hook: stop as soon as the module is Live; avoids the
# manager/root_stage variability while still testing perm/fsuid/cred/module.
if [ "${MAGICROOT_AB_STAGE:-}" = "module" ]; then
    echo "AB_STAGE_OK stage=module"
    exit 0
fi

echo "== 7. KernelSU userspace =="'''
if a2 not in t:
    raise SystemExit("module anchor missing")
t = t.replace(a2, b2, 1)

p.write_text(t, encoding="utf-8", newline="\n")
print("AB stage hooks (fsuid/module) added")
