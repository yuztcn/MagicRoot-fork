from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\tools\verify_apk.py")
t = p.read_text(encoding="utf-8")
old_run = '''    "assets/run.sh": [b"KSU_FLAVOR=", b"manager_ksud_missing", b"MAGICROOT_KSU_FLAVOR",
                       b"FAIL=ksu_grant", b"GRANT_RETRY", b"ksu-official.ko",
                       b"MODULE_WAIT_POLL"],'''
new_run = '''    "assets/run.sh": [b"KSU_FLAVOR=", b"manager_ksud_missing", b"MAGICROOT_KSU_FLAVOR",
                       b"FAIL=ksu_grant", b"GRANT_RETRY", b"ksu-official.ko",
                       b"MODULE_WAIT_POLL", b"KASLR_CROSS_CHECK", b"KO_PATCH_SELF_CHECK",
                       b"CRED_LEAK_SELF_CHECK", b"KSU_GRANT_METHOD"],'''
old_kp = '''    "assets/kernel_profiles.sh": [b"KSU_FLAVORS", b"ksu_flavor_pkg", b"ksu_select_ko",
                                  b"ksu-template-bakasu.ko", b"ko-$flavor.ko"],'''
new_kp = '''    "assets/kernel_profiles.sh": [b"KSU_FLAVORS", b"ksu_flavor_pkg", b"ksu_select_ko",
                                  b"ksu-template-bakasu.ko", b"ko-$flavor.ko",
                                  b"PROFILE_KASLR_PREPARE_LINK"],'''
if old_run not in t:
    raise SystemExit("run marker anchor missing")
t = t.replace(old_run, new_run, 1)
if old_kp not in t:
    raise SystemExit("profile marker anchor missing")
t = t.replace(old_kp, new_kp, 1)
p.write_text(t, encoding="utf-8", newline="\n")
print("verify markers updated")
