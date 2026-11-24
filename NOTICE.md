# MagicRoot licensing notice / 许可与范围说明

MagicRoot
Copyright (C) 2026 MagicRoot contributors

MagicRoot 1.0.6 and later are licensed under the GNU Affero General Public
License, version 3 (AGPL-3.0). The full license text is in `LICENSE`
(verbatim copy of <https://www.gnu.org/licenses/agpl-3.0.txt>).

If you modify MagicRoot and let other users interact with it over a network,
Section 13 of the AGPL requires you to offer those users the corresponding
source code.

Prior releases: MagicRoot 1.0.5 and earlier were released under the MIT
License. Those grants remain valid for the versions distributed under them;
this notice does not retroactively revoke them.

## License compatibility / 许可兼容性

1. AGPL-3.0 is compatible with MIT, Apache-2.0, BSD and GPL-3.0 components;
   those components keep their own licenses and are not re-licensed here.
2. AGPL-3.0 is NOT compatible with GPL-2.0-only code in a single combined
   work. The KernelSU / KernelSU-Next / BakaSU prebuilt LKMs bundled under
   main/app/assets/ are GPL-2.0 third-party works distributed as separate
   files; they are not part of the AGPL-licensed source work and are not
   re-licensed by this file. Do not merge them into the AGPL work without
   resolving the GPL-2.0 compatibility question with the rightsholders.
3. FinaSU and SuSFS follow their own upstream terms.

---

## Scope & Third-Party Boundary Notice / 适用范围与第三方边界说明

1. Scope of the MagicRoot AGPL-3.0 License
   The AGPL-3.0 license in `LICENSE` applies ONLY to MagicRoot's original application code
   (`main/compose-app/`), orchestration/deployment shell scripts (`main/app/assets/*.sh`),
   profile generators, and original kernel/target adaptation modifications.
   It does NOT supersede or re-license any upstream source code or prebuilt
   third-party binary bundled in the repository or release APK.

2. Third-Party Source Code Used / Modified in MagicRoot (源码复用与二次修改)
   - EAEdward/xiaomi9pmroot (MIT, `LICENSES/Xiaomi9pmroot-MIT.txt`):
     initial 6.12/6.6 UAF/reclaim plant (`uaf_plant_61258.c`) and shared `rootd`/`su` base.
   - woshigenm/CVE-2026-98260 (MIT, `LICENSES/Woshigenm-MIT.txt`):
     real-cred write primitives (`PLANT_ZERO`/`PLANT_PTR`/`PLANT_SELINUX`,
     `leak_real_cred`, `mintwait`, `collect_site_pid`) integrated into 98260 plant.
   - quyicheng03-boop/CVE-2026-98260-popsicle-android (MIT since 2026-10-29 `70829ac`,
     `LICENSES/Popsicle-MIT.txt`): earliest publicly indexed origin of the shared
     `pc98260_su.c` / `pc98260_rootd.c` client-daemon components (`su98260.c`,
     `rootd.c`, `pc98260_rootd.c`, `pc98260_su.c`); popsicle's own plant is NOT used.
   - superboyyy/HOneClick (MIT for original material, `LICENSES/HOneClick-MIT.txt`;
     GitHub API reports `NOASSERTION` due to scope note, see `LICENSES/HOneClick-NOASSERTION.md`):
     `KernelProfileGenerator.java` (boot.img / kallsyms / BTF profile generator),
     `binary-sources/64560/upstream-honeclick/`, and `binary-sources/98260-h1c/`
     (`uaf_plant.c`, `pc98260_rootd.c` — itself tracing via sganggs to popsicle).
   - Feng1586/CVE-2026-64560-public (MIT for original material,
     `LICENSES/CVE-2026-64560-public-MIT.txt`; GitHub API reports `NOASSERTION`
     due to scope note): 64560 zero-write primitives (`t64560_v36.c`, `t64560_v42.c`).
   - honor_ubl 3.1.1 aph136g142 adaptation (MIT, `LICENSES/Honor-UBL-Adaptation-MIT.txt`):
     `kaslr_slide_aph136g142.c` and `pc98260_target_g142.h`.
   - UI & System Libraries (Apache-2.0, `LICENSES/Apache-2.0.txt`):
     Miuix (`compose-miuix-ui/miuix`), Jetpack Compose / AndroidX,
     Shizuku API (`RikkaApps/Shizuku-API` / `XiaoTong6666` fork),
     and `Kyant0/AndroidLiquidGlass` (`CombinedBackdrop.kt`, `LiquidLens.kt`).

3. Prebuilt Binaries Bundled Without Building Upstream Source (未复用源码、随包分发预编译产物)
   The following components are NOT built from upstream manager/driver source trees
   by MagicRoot; prebuilt artifacts (or provenance-locked binaries) are bundled in
   `main/app/assets/` and remain solely under their respective upstream licenses:
   - KernelSU / KernelSU-Next / BakaSU (`GPL-2.0`, `LICENSES/GPL-2.0.txt`) &
     SukiSU Ultra (`GPL-3.0`, `LICENSES/GPL-3.0.txt`) & FinaSU (upstream terms):
     prebuilt `.ko` LKM templates and legacy 6.1/6.18.21 fallback `ksud` binaries
     (generic flows extract `ksud` from the installed manager at runtime).
   - 6.1.x CGA modules (`main/app/assets/g264/ksm-*-base.ko`, `61157/g264/ksm-g264-base.ko`):
     bundled prebuilt base module and deterministic rebased variants; corresponding GPL
     kernel module audit sources reside in `binary-sources/6157-g264/cga/`.
   - SuSFS (`inforcqb/susfs4ksu-lkm`, upstream license): prebuilt `susfs_insmod` and
     `susfs_guard_lkm-{6.6,6.12,6.18}.ko`.
   - Legacy 64560 release binaries (`main/app/assets/{t64560_v36,t64560_cred,addrcalc,
     forker,ko_patch,cred_target,wait_helper,kaslr_slide_*}`): prebuilt verified binaries
     retained in release assets (audit sources live in `binary-sources/64560/`).

4. Technical / Behavioral References Only (仅技术参考：未复用源码、未随包分发)
   - `YuKongA/CVE-2026-98260` (MIT), `Yunnijian/OnePlus16-Jailbreak` (GPL-3.0;
     early snapshot MIT), `AzirX1337/CVE-2026-98260-OnePlus16-PYB110-Jailbreak` (MIT),
     `xingranya/onekeyjb` (GPL-3.0), `No-World/rootkit` (MIT),
     `TKgbUssr/PMX110-6.18.21-exploit`, and `LSPosed` / `Zygisk Next`
     (on-device script hotfix only; no manager APK or module bundled).

See `THIRD_PARTY_NOTICES.md` and `LICENSES/` for full texts and file-level details.
