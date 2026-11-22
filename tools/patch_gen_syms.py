from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\gen_syms_from_vmlinux.py")
t = p.read_text(encoding="utf-8")
t = t.replace(
'''    ap.add_argument("--write", action="store_true",
                    help="write/replace syms_<profile>[_<flavor>].txt in assets")''',
'''    ap.add_argument("--write", action="store_true",
                    help="write/replace syms_<profile>[_<flavor>].txt in assets")
    ap.add_argument("--flavors", default="",
                    help="comma-separated subset (default: all five)")''')
t = t.replace(
'''    for flavor, template in TEMPLATES.items():''',
'''    only = {x.strip() for x in args.flavors.split(",") if x.strip()}
    for flavor, template in TEMPLATES.items():
        if only and flavor not in only:
            continue''')
p.write_text(t, encoding="utf-8", newline="\n")
print("gen syms script extended")
