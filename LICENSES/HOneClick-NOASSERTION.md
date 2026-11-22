# HOneClick — license & provenance status

Upstream: https://github.com/superboyyy/HOneClick

1. Root `LICENSE`: MIT License (`Copyright (c) 2026 superboyyy`), followed by a
   scope note stating that the MIT license applies only to original research
   material in HOneClick (`LICENSES/HOneClick-MIT.txt`). Because of that trailing
   scope paragraph, the GitHub SPDX API reports `NOASSERTION`.
2. Third-party boundaries declared by HOneClick (`THIRD_PARTY_NOTICES.md` /
   `ASSET_PROVENANCE.md`):
   - `native/t64560_v36.c`, `native/t64560_v42_honor.c`: derived from
     `Feng1586/CVE-2026-64560-public` (MIT, `LICENSES/CVE-2026-64560-public-MIT.txt`).
   - `native/cve98260/*`: adapted from `sganggs/CVE-2026-98260-BRM-AN00`
     (no explicit license declared in sganggs; `pc98260_su.c`/`pc98260_rootd.c`
     trace further back to `quyicheng03-boop/CVE-2026-98260-popsicle-android`,
     MIT since 2026-10-29 `70829ac`). HOneClick restricts `native/cve98260/*`
     to personal research.
   - `assets/ksu-template*.ko`, `assets/ksud`: GPL-3.0 (KernelSU).
3. MagicRoot usage:
   - Source ported/adapted in MagicRoot: `KernelProfileGenerator.java`
     (boot.img / kallsyms / BTF profile generator), `binary-sources/64560/upstream-honeclick/`,
     and `binary-sources/98260-h1c/` (`uaf_plant.c`, `pc98260_rootd.c`).
   - MagicRoot preserves HOneClick's MIT notice (`LICENSES/HOneClick-MIT.txt`),
     `CVE-2026-64560-public` MIT notice (`LICENSES/CVE-2026-64560-public-MIT.txt`),
     and `popsicle` MIT notice (`LICENSES/Popsicle-MIT.txt`).
