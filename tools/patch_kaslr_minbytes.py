from pathlib import Path

p = Path(r"<LOCAL_USER>user\Documents\<DSH>\MagicRootEnhanced\main\app\assets\kernel_profiles.sh")
t = p.read_text(encoding="utf-8")
t = t.replace("PROFILE_KASLR_MIN_BYTES=8388608", "PROFILE_KASLR_MIN_BYTES=1048576")
p.write_text(t, encoding="utf-8", newline="\n")
print("KASLR min bytes lowered to 1 MiB for both profiles")
