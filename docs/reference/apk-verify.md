# MagicRoot BakaSU APK 閳?static verification

- apk: `/data/user/0/cc.codroid/files/home/workspace/magicroot/main/app/MagicRoot.apk`
- size: 64770003 B
- asset payload: 164656833 B (352 entries)
- badging: aapt2 unavailable

| asset | size | sha256 | note |
|---|---:|---|---|
| `ksu-template-bakasu.ko` | 508792 | `18105ef8e8aba5b15d9a7e0befa46e35` | BakaSU 4.2.0-rc3 KMI 6.12 LKM template (508792 B) |
| `ksu_flavor` | 8 | `46a9a3a7dd46bb489ba74a4fd1ee3b26` | flavor marker resukisu |
| `syms_61258_bakasu.txt` | 9543 | `0a1be238f3d4cd715bfe472dedd19f5f` | 6.12.58 BakaSU syms (274) |
| `syms_6138_bakasu.txt` | 9543 | `ef440bd11cf673edab90933d2a203249` | 6.12.38 BakaSU syms (274) |
| `ksu-template.ko` | 404928 | `7e25d68419d08535d35e3630d9f0ff1a` | official KernelSU 3.3.1 6.12 template (fallback) |
| `ksu-template-next.ko` | 500656 | `67c5d9e9026c52ff4c9b2e681aa81d18` | KernelSU-Next 3.4.2 native 6.12 LKM (MultiSU) |
| `ksu-template-sukisu.ko` | 648056 | `9f999173fa65b3eb3a90e2becf2bf5ec` | SukiSU 4.2.1-r2 native 6.12 LKM (MultiSU) |
| `ksu-template-fina.ko` | 572192 | `616e01a3de04048cd3b0c5da246e0bbf` | FinaSU 1.2.1 native 6.12 LKM (MultiSU bundle) |
| `syms_61258_next.txt` | 9543 | `0a1be238f3d4cd715bfe472dedd19f5f` | 6.12.58 next syms |
| `syms_61258_sukisu.txt` | 9543 | `0a1be238f3d4cd715bfe472dedd19f5f` | 6.12.58 sukisu syms |
| `syms_61258_fina.txt` | 9543 | `0a1be238f3d4cd715bfe472dedd19f5f` | 6.12.58 fina syms |
| `t64560_v36` | 66760 | `29557db859e8e04a25aed646b1f1251b` | 6.12 permissive writer |
| `t64560_cred` | 76104 | `eec3cc1ab2bd301b8466a252df3868b9` | 6.12 v42 cred writer MAXVICTIM=32 |
| `su_entry.sh` | 5954 | `dc23aedd1495ce22005c4e2011436cf4` | PMX v1.6 su entry + Termux wrapper patch |
| `kernel_profiles.sh` | 29506 | `a078ac96b67679529a11daa8425a4005` | flavor-aware profiles |
| `root_stage.sh` | 28628 | `c27aafdb8665b798a92dcc735f8bb938` | flavor-aware root stage |
| `syms_61258.txt` | 9543 | `0a1be238f3d4cd715bfe472dedd19f5f` | official syms 61258 |
| `syms_6138.txt` | 9543 | `ef440bd11cf673edab90933d2a203249` | official syms 6138 |
| `syms_6138_next.txt` | 9543 | `ef440bd11cf673edab90933d2a203249` | 6.12.38 next syms (274) |
| `syms_6138_sukisu.txt` | 9543 | `ef440bd11cf673edab90933d2a203249` | 6.12.38 sukisu syms (274) |
| `syms_6138_fina.txt` | 9543 | `ef440bd11cf673edab90933d2a203249` | 6.12.38 fina syms (274) |
| `syms_g4b36.txt` | 9543 | `18844a6a1f37608483db425e4e50b2ac` | 6.12.38 g4b36 official syms (274) |
| `syms_g4b36_nova.txt` | 9543 | `18844a6a1f37608483db425e4e50b2ac` | 6.12.38 g4b36 nova syms (274) |
| `98260-g4b36/exploit-android-key-ptr` | 104816 | `1a2a7c314fab28270b3d11e5d0c5a808` | g4b36 98260 real-cred payload |
| `98260-g4b36/target.sh` | 547 | `765ec972fd9c4447c75d2218ff653af0` | g4b36 target metadata |
| `98260-g4b36/SHA256SUMS.txt` | 166 | `3922acbdaeae8ee300e7e31b3da95415` | g4b36 pinned asset hashes |
| `98260/exploit-android-perf` | 107 | `1954bf48011f8e7f93c6a9010375abae` | 98260 SELinux writer placeholder (superseded by key-ptr) |
| `98260/exploit-android-perf-chain` | 107 | `1954bf48011f8e7f93c6a9010375abae` | 98260 cred/UID0 stage placeholder (superseded by key-ptr) |
| `98260/exploit-android-key-ptr` | 104816 | `0fd3ff76cce3288252a2cf6f8ad64463` | 98260 dual fake/real-cred (6.12.58, free-gated bounded 4096-write precise reclaim, same-4K-half triple) |
| `pc98260-su` | 418016 | `8838ab17e38252492df3761b74126855` | 98260 rootd client (top-level asset staged for all 98260 profiles) |
| `98260/run98260.sh` | 108737 | `8d8b99fd859ce47ce7b53a0fac50822a` | 98260 device-side fail-stop stage machine |
| `98260/target.sh` | 612 | `e2fd82b7b6d4f7b50230f62638a9e66a` | 98260 target constants (kernel/models/hashes) |
| `98260/SHA256SUMS.txt` | 506 | `fcc9d495720c5173f446718aace3f4c4` | 98260 pinned asset hashes |

## Result

All required assets and flavor markers present.
