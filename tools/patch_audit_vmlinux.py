from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\kernel_profile_audit.py")
t = p.read_text(encoding="utf-8")
t = t.replace('return {"error": f"pyelftools unavailable: {exc}"}', 'return {"__error__": f"pyelftools unavailable: {exc}"}')
t = t.replace('return {"error": "vmlinux missing"}', 'return {"__error__": "vmlinux missing"}')
t = t.replace('return {"error": "no symtab"}', 'return {"__error__": "no symtab"}')
t = t.replace('''    syms = vmlinux_symbols(path)
    if "error" in syms:
        return syms''', '''    syms = vmlinux_symbols(path)
    if "__error__" in syms:
        return syms''')
p.write_text(t, encoding="utf-8", newline="\n")
print("patched vmlinux error sentinel")
