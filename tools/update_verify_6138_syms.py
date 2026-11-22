from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\verify_apk.py")
t = p.read_text(encoding="utf-8")
anchor = '''    ("syms_6138.txt", None, "official syms 6138"),'''
addition = '''    ("syms_6138.txt", None, "official syms 6138"),
    ("syms_6138_next.txt", "fbe4f62e5016c27d", "6.12.38 next syms (227)"),
    ("syms_6138_sukisu.txt", "fd8d998474677650", "6.12.38 sukisu syms (245)"),
    ("syms_6138_fina.txt", "e79ca949dc9487a0", "6.12.38 fina syms (232)"),'''
if anchor not in t:
    raise SystemExit("anchor missing")
t = t.replace(anchor, addition, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("verify_apk: 6138 syms entries added")

R = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\kernel_profiles.sh")
rt = R.read_text(encoding="utf-8")
rt = rt.replace("""#        fina     = FinaSU 1.0.8            kernel 33020 / uapi 6""",
                """#        fina     = FinaSU 1.0.10           kernel 33034 / uapi 6""")
rt = rt.replace("""# Standard deployment extracts the userspace ksud (lib/arm64-v8a/libksud.so or
# the renamed native library used by newer managers) plus the manager signing
# tuple from the installed manager APK, and falls back to the bundled
# per-flavor files below when the manager is absent.""",
                """# The userspace ksud (lib/arm64-v8a/libksud.so or the renamed native library
# used by newer managers) and the manager signing tuple are extracted from the
# installed manager APK; there is no bundled manager/userspace fallback.""")
R.write_text(rt, encoding="utf-8", newline="\n")
print("kernel_profiles header refreshed")
