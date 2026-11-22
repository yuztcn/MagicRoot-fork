#!/system/bin/sh
# Kernel / root-backend profile registry for MagicRoot.
#
# Two independent selections happen here:
#   1. the kernel profile (6.12.58 / 6.12.38 ...), which picks KASLR anchors,
#      syms and the CVE-2026-64560 payload binaries;
#   2. the root backend flavor, which picks the manager package, the userspace
#      ksud and the KernelSU-family LKM template:
#        resukisu = BakaSU 4.2.0-rc3       kernel/uapi from installed manager
#        fina     = FinaSU 1.3.0             kernel 33082 / uapi 6
#        kernelsu = official KernelSU 3.3.1 kernel 32680 / uapi 5
#        sukisu   = SukiSU 4.2.1-r2         kernel 41068 / uapi 6
#        next     = KernelSU-Next 3.4.2     kernel 33355 / uapi 5
#        nova     = SukiSU Nova 3.0.0       manager-extracted LKM / uapi 6
#        maplesu  = MapleSU 5.2.0            manager-extracted LKM / uapi 7 (ksud 32650)
#
# The userspace ksud (lib/arm64-v8a/libksud.so or the renamed native library
# used by newer managers) and the manager signing tuple are extracted from the
# installed manager APK; there is no bundled manager/userspace fallback.
#
# A per-flavor KMI-matched LKM can be supplied at runtime as
#   $D/ko-<flavor>.ko
# which overrides the bundled template.

# Allowed backend flavors (keep in sync with UiState.kt / MainActivity.java).
KSU_FLAVORS="kernelsu resukisu next sukisu fina nova maplesu"

ksu_flavor_normalize() {
    case "$1" in
        resukisu|fina|kernelsu|sukisu|next|nova|maplesu) echo "$1" ;;
        official|bakasu) echo "resukisu" ;;
        *) echo "kernelsu" ;;
    esac
}

ksu_flavor_pkg() {
    case "$1" in
        resukisu) echo "com.resukisu.resukisu" ;;
        fina)     echo "me.yuki.fina" ;;
        kernelsu) echo "me.weishu.kernelsu" ;;
        sukisu)   echo "com.sukisu.ultra" ;;
        next)     echo "com.rifsxd.ksunext" ;;
        nova)     echo "com.sukisu.nova" ;;
        maplesu)  echo "dev.maplesu.manager" ;;
        *)        echo "me.weishu.kernelsu" ;;
    esac
}

ksu_flavor_label() {
    case "$1" in
        resukisu) echo "BakaSU" ;;
        fina)     echo "FinaSU" ;;
        kernelsu) echo "KernelSU" ;;
        sukisu)   echo "SukiSU" ;;
        next)     echo "KernelSU-Next" ;;
        nova)     echo "SukiSU Nova" ;;
        maplesu)  echo "MapleSU" ;;
        *)        echo "KernelSU" ;;
    esac
}

ksu_flavor_kver() {
    case "$1" in
        resukisu)
            # BakaSU stable/dev/CI use different kernel versions; never freeze
            # one number.  The app passes the installed manager versionCode.
            echo "${MAGICROOT_KSU_MANAGER_VERSION:-}" ;;
        fina)     echo "33090" ;;
        kernelsu) echo "32680" ;;
        sukisu)   echo "41100" ;;
        next)     echo "33355" ;;
        nova)     echo "30000" ;;
        maplesu)  echo "32650" ;;
        *)        echo "32680" ;;
    esac
}

ksu_flavor_ksud() {
    # All supported backends expose the userspace daemon as ksud; the app
    # extracts the real binary from the installed manager APK.
    case "" in
        resukisu|fina|kernelsu|sukisu|next|nova|maplesu) echo "ksud" ;;
        *) echo "ksud" ;;
    esac
}

ksu_flavor_uapi() {
    case "$1" in
        resukisu) echo "6" ;;
        fina)     echo "6" ;;
        kernelsu) echo "5" ;;
        sukisu)   echo "6" ;;
        next)     echo "5" ;;
        nova)     echo "6" ;;
        maplesu)  echo "7" ;;
        *)        echo "5" ;;
    esac
}

# Per-flavor native 6.12 KMI LKM template + matching syms table.
# The reference MultiSU bundle provides native android16-6.12 LKMs for the
# five bundled backends.  SukiSU Nova has no bundled template: its LKM is
# always extracted from the installed manager APK and only its symbol table
# ships here.
ksu_select_ko() {
    profile="$1"   # 61258 | 6138
    flavor="$2"
    FLAVOR_SYMS_MISSING=0
    # 6.1.x has no generic per-flavor template pair: the runner loads the
    # manager KO (runtime-kallsyms patch), the per-build CGA module, or M6.
    # Return before the generic-template branch so the log does not claim the
    # flavor is unsupported while the dedicated 6.1 path is about to load it.
    if [ "$profile" = "6157" ]; then
        KO_TEMPLATE=""
        SYMS=""
        KO_COMPAT="dynamic-6.1-manager-ko"
        return 0
    fi
    if [ "$profile" = "61821brm" ]; then
        # Official KernelSU uses the g186-specific compatibility LKM. Never
        # fall back to another flavor or a generic android17-6.18 module.
        case "$flavor" in
            resukisu) KO_TEMPLATE="$D/98260-61821-brm/ksu-template-61821-bakasu.ko"; KO_COMPAT="native-6.18-g186-bakasu" ;;
            next)     KO_TEMPLATE="$D/98260-61821-brm/ksu-template-61821-next.ko";   KO_COMPAT="native-6.18-g186-next" ;;
            sukisu)   KO_TEMPLATE="$D/98260-61821-brm/ksu-template-61821-sukisu.ko"; KO_COMPAT="native-6.18-g186-sukisu" ;;
            fina)     KO_TEMPLATE="$D/98260-61821-brm/ksu-template-61821-fina.ko";   KO_COMPAT="native-6.18-g186-fina" ;;
            maplesu)  KO_TEMPLATE="$D/ko-maplesu.ko"; KO_COMPAT="manager-adaptive-maplesu" ;;
            *)        KO_TEMPLATE="$D/98260-61821-brm/ksu-template-61821-kernelsu.ko"; KO_COMPAT="brm-g186-official-v1" ;;
        esac
        SYMS="$D/98260-61821-brm/syms_61821_brm.txt"
    elif [ "$profile" = "61821h1c117" ]; then
        # Five local test templates regenerated for the exact 117 vermagic.
        # Each was checked offline against syms_117.txt: ko_patch MISSING=0.
        case "$flavor" in
            resukisu) _f117=bakasu ;;
            maplesu)  _f117="" ;;
            *)        _f117="$flavor" ;;
        esac
        if [ -n "$_f117" ]; then
            KO_TEMPLATE="$D/98260-61821-117/ksu-template-117-${_f117}.ko"
            KO_COMPAT="native-6.18-117-${_f117}"
        else
            # MapleSU ships no bundled 6.18 template; the carved manager KO is required.
            KO_TEMPLATE="$D/ko-maplesu.ko"
            KO_COMPAT="manager-adaptive-maplesu"
        fi
        SYMS="$D/98260-61821-117/syms_117.txt"
    elif [ "$profile" = "61821" ]; then
        # BRM hands the g18x/g928 chain to the *selected* manager; forcing
        # official KernelSU here would pair a BakaSU manager with an official
        # LKM and is a known source of late-load instability.
        case "$flavor" in
            resukisu) KO_TEMPLATE="$D/98260-61821/ksu-template-61821-bakasu.ko"; KO_COMPAT="native-6.18-bakasu" ;;
            next)     KO_TEMPLATE="$D/98260-61821/ksu-template-61821-next.ko";   KO_COMPAT="native-6.18-kernelsu-next" ;;
            sukisu)   KO_TEMPLATE="$D/98260-61821/ksu-template-61821-sukisu.ko"; KO_COMPAT="native-6.18-sukisu" ;;
            fina)     KO_TEMPLATE="$D/98260-61821/ksu-template-61821-fina.ko";   KO_COMPAT="native-6.18-finasu" ;;
            maplesu)  KO_TEMPLATE="$D/ko-maplesu.ko"; KO_COMPAT="manager-adaptive-maplesu" ;;
            *)        KO_TEMPLATE="$D/98260-61821/ksu-template.ko"; KO_COMPAT="native-6.18-kernelsu" ;;
        esac
        SYMS="$D/98260-61821/syms_61821_${flavor}.txt"
        [ -f "$SYMS" ] || SYMS="$D/98260-61821/syms_61821_kernelsu.txt"
        [ -f "$KO_TEMPLATE" ] || {
            KO_TEMPLATE="$D/98260-61821/ksu-template.ko"
            KO_COMPAT="native-6.18-kernelsu-fallback"
        }
    elif [ "$profile" = "aph112" ]; then
        # APH-AN00 shares the g459a 6.12.58b kernel build with the 61258b
        # profile.  Reuse that profile's per-flavor symbol tables; only the
        # generic 6.12 templates are needed here.
        case "$flavor" in
            resukisu) SYMS="$D/syms_61258b_bakasu.txt"; KO_COMPAT="native-6.12-aph-bakasu" ;;
            next)     SYMS="$D/syms_61258b_next.txt";   KO_COMPAT="native-6.12-aph-kernelsu-next" ;;
            sukisu)   SYMS="$D/syms_61258b_sukisu.txt"; KO_COMPAT="native-6.12-aph-sukisu" ;;
            fina)     SYMS="$D/syms_61258b_fina.txt";   KO_COMPAT="native-6.12-aph-finasu" ;;
            maplesu)  SYMS="$D/syms_61258b.txt";        KO_COMPAT="native-6.12-aph-maplesu" ;;
            *)        SYMS="$D/syms_aph112.txt";        KO_COMPAT="native-6.12-aph-kernelsu" ;;
        esac
        case "$flavor" in
            resukisu) KO_TEMPLATE="$D/ksu-template-bakasu.ko" ;;
            next)     KO_TEMPLATE="$D/ksu-template-next.ko" ;;
            sukisu)   KO_TEMPLATE="$D/ksu-template-sukisu.ko" ;;
            fina)     KO_TEMPLATE="$D/ksu-template-fina.ko" ;;
            maplesu)  KO_TEMPLATE="$D/ko-maplesu.ko" ;;
            *)        KO_TEMPLATE="$D/ksu-template.ko" ;;
        esac
    elif [ "$profile" = "g554" ] || [ "$profile" = "f171" ] || [ "$profile" = "6658" ] || [ "$profile" = "6689" ] || [ "$profile" = "g893" ]; then
        case "$flavor" in
            resukisu) KO_TEMPLATE="$D/ksu-template-66118-bakasu.ko"; KO_COMPAT="native-6.6-bakasu" ;;
            next)     KO_TEMPLATE="$D/ksu-template-66118-next.ko";   KO_COMPAT="native-6.6-kernelsu-next" ;;
            sukisu)   KO_TEMPLATE="$D/ksu-template-66118-sukisu.ko"; KO_COMPAT="native-6.6-sukisu" ;;
            fina)     KO_TEMPLATE="$D/ksu-template-66118-fina.ko";   KO_COMPAT="native-6.6-finasu" ;;
            maplesu)  KO_TEMPLATE="$D/ko-maplesu.ko"; KO_COMPAT="manager-adaptive-maplesu" ;;
            *)        KO_TEMPLATE="$D/ksu-template-66118.ko"; KO_COMPAT="native-6.6-kernelsu" ;;
        esac
        [ -f "$KO_TEMPLATE" ] || {
            KO_TEMPLATE="$D/ksu-template-66118.ko"
            KO_COMPAT="native-6.6-kernelsu-fallback"
        }
        if [ "$profile" = "6658" ]; then
            SYMS="$D/98260-6658/syms_6658_${flavor}.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-6658/syms_6658_bakasu.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-6658/syms_6658.txt"
        elif [ "$profile" = "6689" ]; then
            SYMS="$D/98260-6689/syms_6689_${flavor}.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-6689/syms_6689_bakasu.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-6689/syms_6689_kernelsu.txt"
        elif [ "$profile" = "g893" ]; then
            SYMS="$D/98260-g893/syms_g893_${flavor}.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-g893/syms_g893_bakasu.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-g893/syms_g893_kernelsu.txt"
        else
            SYMS="$D/98260-$profile/syms_66118_${flavor}.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-$profile/syms_66118_bakasu.txt"
            [ -f "$SYMS" ] || SYMS="$D/98260-$profile/syms_66118.txt"
        fi
    elif [ "$profile" = "g142" ] || [ "$profile" = "ga812" ]; then
        # Self-contained profile-dir symbol tables (98260-g142 / 98260-ga812).
        if [ "$profile" = "ga812" ]; then
            case "$flavor" in
                resukisu) KO_TEMPLATE="$D/ksu-template-66118-bakasu.ko" ;;
                next)     KO_TEMPLATE="$D/ksu-template-66118-next.ko" ;;
                sukisu)   KO_TEMPLATE="$D/ksu-template-66118-sukisu.ko" ;;
                fina)     KO_TEMPLATE="$D/ksu-template-66118-fina.ko" ;;
                maplesu)  KO_TEMPLATE="$D/ko-maplesu.ko" ;;
                *)        KO_TEMPLATE="$D/ksu-template-66118.ko" ;;
            esac
        else
            case "$flavor" in
                resukisu) KO_TEMPLATE="$D/ksu-template-bakasu.ko" ;;
                next)     KO_TEMPLATE="$D/ksu-template-next.ko" ;;
                sukisu)   KO_TEMPLATE="$D/ksu-template-sukisu.ko" ;;
                fina)     KO_TEMPLATE="$D/ksu-template-fina.ko" ;;
                maplesu)  KO_TEMPLATE="$D/ko-maplesu.ko" ;;
                *)        KO_TEMPLATE="$D/ksu-template.ko" ;;
            esac
        fi
        KO_COMPAT="native-${profile}"
        SYMS="$D/98260-$profile/syms_${profile}_${flavor}.txt"
        [ -f "$SYMS" ] || SYMS="$D/98260-$profile/syms_${profile}_bakasu.txt"
        [ -f "$SYMS" ] || SYMS="$D/98260-$profile/syms_${profile}_kernelsu.txt"
    else
    case "$flavor" in
        resukisu)
            KO_TEMPLATE="$D/ksu-template-bakasu.ko"
            SYMS="$D/syms_${profile}_bakasu.txt"
            [ -f "$SYMS" ] || SYMS="$D/syms_${profile}_resukisu.txt"
            KO_COMPAT="native-6.12-bakasu"
            ;;
        kernelsu)
            KO_TEMPLATE="$D/ksu-template.ko"
            SYMS="$D/syms_${profile}.txt"
            KO_COMPAT="native-6.12-kernelsu"
            ;;
        next)
            KO_TEMPLATE="$D/ksu-template-next.ko"
            SYMS="$D/syms_${profile}_next.txt"
            KO_COMPAT="native-6.12-kernelsu-next"
            ;;
        sukisu)
            KO_TEMPLATE="$D/ksu-template-sukisu.ko"
            SYMS="$D/syms_${profile}_sukisu.txt"
            KO_COMPAT="native-6.12-sukisu"
            ;;
        fina)
            KO_TEMPLATE="$D/ksu-template-fina.ko"
            SYMS="$D/syms_${profile}_fina.txt"
            KO_COMPAT="native-6.12-finasu"
            ;;
        nova)
            # SukiSU Nova ships its LKM inside the manager APK; the runtime
            # manager-KO override is authoritative.  Keep the official
            # template only as a last-resort placeholder and require a
            # nova-specific table so a missing profile fails closed.
            KO_TEMPLATE="$D/ksu-template.ko"
            SYMS="$D/syms_${profile}_nova.txt"
            KO_COMPAT="native-6.12-nova"
            ;;
        maplesu)
            # MapleSU (dev.maplesu.manager) is independent from SukiSU/Nova and
            # ships its LKM only inside the manager APK.  Use the carved
            # manager KO; symbol table prefers a dedicated _maplesu table, then
            # the generic (kernelsu) one.
            KO_TEMPLATE="$D/ko-maplesu.ko"
            SYMS="$D/syms_${profile}_maplesu.txt"
            [ -f "$SYMS" ] || SYMS="$D/syms_${profile}.txt"
            KO_COMPAT="manager-adaptive-maplesu"
            ;;
        *)
            KO_TEMPLATE="$D/ksu-template.ko"
            SYMS="$D/syms_${profile}.txt"
            KO_COMPAT="native-6.12-kernelsu"
            ;;
    esac
    fi
    # MagicRoot always late-loads the LKM.  The stock SukiSU template schedules
    # stop_input_hook_work even though late-load skipped INIT_WORK, causing the
    # first zygote restart to hit __queue_work's list-empty WARNING.  Use the
    # audited no-op-cleanup template for the verified 6.12.58 SukiSU route.
    if [ "${MAGICROOT_BUILTIN_SUKISU:-0}" = "1" ] && [ "$profile-$flavor" = "61258-sukisu" ] && [ -f "$D/ksu-template-sukisu-lateload.ko" ]; then
        KO_TEMPLATE="$D/ksu-template-sukisu-lateload.ko"
        KO_COMPAT="native-6.12-sukisu-lateload-work-fix"
        echo "KSU_LATELOAD_WORK_FIX=1 template=$(basename "$KO_TEMPLATE")"
    elif [ -f "$D/ko-$flavor.ko" ]; then
        KO_TEMPLATE="$D/ko-$flavor.ko"
        KO_COMPAT="override"
    fi
    # Fail closed: a template without a matching syms table for this KMI would
    # resolve against another kernel's addresses and crash the module.
    if [ ! -f "$KO_TEMPLATE" ] || [ ! -f "$SYMS" ]; then
        FLAVOR_SYMS_MISSING=1
        echo "KSU_FLAVOR_UNSUPPORTED flavor=$flavor profile=$profile template=$KO_TEMPLATE syms=$SYMS"
    fi
}

select_kernel_profile() {
    RELEASE="$1"
    MODEL="${2:-$(getprop ro.product.model 2>/dev/null || echo unknown)}"
    PROFILE_ID=""
    PROFILE_READY=0
    KASLR_BIN=""
    SYMS=""
    KO_TEMPLATE=""
    KO_COMPAT=""
    PROFILE_KASLR_MIN_VOTES=""
    PROFILE_KASLR_MIN_ANCHORS=""
    PROFILE_KASLR_MIN_BYTES=""
    PROFILE_KASLR_PREPARE_LINK=""
    PROFILE_KASLR_SELINUX_LINK=""
    PROFILE_CRED_LAYOUT=""
    KSU_FLAVOR=$(ksu_flavor_normalize "${MAGICROOT_KSU_FLAVOR:-$(cat "$D/ksu_flavor" 2>/dev/null | tr -d '\r\n')}")
    export MAGICROOT_KSU_FLAVOR="$KSU_FLAVOR"
    KSU_MANAGER_PKG=${MAGICROOT_KSU_PKG:-$(ksu_flavor_pkg "$KSU_FLAVOR")}
    KSU_MANAGER_LABEL=$(ksu_flavor_label "$KSU_FLAVOR")
    EXPECT_KVER=$(ksu_flavor_kver "$KSU_FLAVOR")
    EXPECT_UAPI=$(ksu_flavor_uapi "$KSU_FLAVOR")
    export MAGICROOT_KSU_MANAGER="$KSU_MANAGER_PKG"
    export MAGICROOT_KSU_LABEL="$KSU_MANAGER_LABEL"
    export PROFILE_KASLR_MIN_VOTES PROFILE_KASLR_MIN_ANCHORS PROFILE_KASLR_MIN_BYTES
    export PROFILE_KASLR_PREPARE_LINK PROFILE_KASLR_SELINUX_LINK
    export PROFILE_CRED_LAYOUT
    export MAGICROOT_EXPECT_KVER="$EXPECT_KVER"
    export MAGICROOT_EXPECT_UAPI="$EXPECT_UAPI"
    V36_BIN="$D/t64560_v36"
    CRED_BIN="$D/t64560_cred"

    case "$RELEASE" in
        6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k)
            if [ "$MODEL" = "APH-AN00" ]; then
                PROFILE_ID="aph112"
                PROFILE_READY=1
                KASLR_BIN="$D/kaslr_slide_aph112"
                V36_BIN=""
                CRED_BIN=""
                PROFILE_KASLR_MIN_VOTES=3
                PROFILE_KASLR_MIN_ANCHORS=5
                PROFILE_KASLR_MIN_BYTES=1048576
                PROFILE_KASLR_PREPARE_LINK=0xffffffc08019b924
                PROFILE_KASLR_SELINUX_LINK=0xffffffc0827e7a20
                PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
                ksu_select_ko "aph112" "$KSU_FLAVOR"
            else
                PROFILE_ID="61258b"
                PROFILE_READY=1
                KASLR_BIN="$D/kaslr_slide_61258b"
                V36_BIN=""
                CRED_BIN=""
                PROFILE_KASLR_MIN_VOTES=3
                PROFILE_KASLR_MIN_ANCHORS=5
                PROFILE_KASLR_MIN_BYTES=1048576
                PROFILE_KASLR_PREPARE_LINK=0xffffffc08019b924
                PROFILE_KASLR_SELINUX_LINK=0xffffffc0827e7a20
                PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
                ksu_select_ko "61258b" "$KSU_FLAVOR"
            fi
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.12.58-android16-6-g142ddad31e60-abogki576095858-4k)
            # honor_ubl 3.1.1 aph136g142: dedicated six-anchor KASLR helper.
            # The exact release selects the build; no model/BTF/ROM gate.
            PROFILE_ID="g142"
            PROFILE_READY=1
            KASLR_BIN="$D/kaslr_slide_aph136g142"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=5
            PROFILE_KASLR_MIN_BYTES=1048576
            PROFILE_KASLR_PREPARE_LINK=0xffffffc0801935b8
            PROFILE_KASLR_SELINUX_LINK=0xffffffc0827e7a60
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "g142" "$KSU_FLAVOR"
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k)
            PROFILE_ID="61258"
            PROFILE_READY=1
            KASLR_BIN="$D/kaslr_slide_61258"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=5
            PROFILE_KASLR_MIN_BYTES=1048576
            PROFILE_KASLR_PREPARE_LINK=0xffffffc08019c448
            PROFILE_KASLR_SELINUX_LINK=0xffffffc0827e7a60
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "61258" "$KSU_FLAVOR"
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k)
            PROFILE_ID="6138"
            PROFILE_READY=1
            KASLR_BIN="$D/kaslr_slide_6138"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=5
            PROFILE_KASLR_MIN_BYTES=1048576
            PROFILE_KASLR_PREPARE_LINK=0xffffffc080b8a21c
            PROFILE_KASLR_SELINUX_LINK=0xffffffc0826663c8
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "6138" "$KSU_FLAVOR"
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k)
            PROFILE_ID="6138y"
            PROFILE_READY=1
            KASLR_BIN="$D/kaslr_slide_6138y"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=5
            PROFILE_KASLR_MIN_BYTES=1048576
            PROFILE_KASLR_PREPARE_LINK=0xffffffc080b89d98
            PROFILE_KASLR_SELINUX_LINK=0xffffffc0826663c8
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "6138y" "$KSU_FLAVOR"
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k)
            PROFILE_ID="6123"
            PROFILE_READY=1
            KASLR_BIN="$D/kaslr_slide_6123"
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=5
            PROFILE_KASLR_MIN_BYTES=1048576
            PROFILE_KASLR_PREPARE_LINK=0xffffffc080cec840
            PROFILE_KASLR_SELINUX_LINK=0xffffffc082656570
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "6123" "$KSU_FLAVOR"
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.12.23-android16-5-gcd85666d7884-abogki452537391-4k)
            PROFILE_ID="g856"
            PROFILE_READY=1
            # 98260 measures the slide in-process; the 64560 KASLR helper is
            # not built for this build, so do not point at the g45 binary.
            KASLR_BIN=""
            V36_BIN="$D/t64560_v36"
            CRED_BIN="$D/t64560_cred"
            PROFILE_KASLR_MIN_VOTES=3
            PROFILE_KASLR_MIN_ANCHORS=5
            PROFILE_KASLR_MIN_BYTES=1048576
            PROFILE_KASLR_PREPARE_LINK=0xffffffc080df532c
            PROFILE_KASLR_SELINUX_LINK=0xffffffc082656570
            PROFILE_CRED_LAYOUT="6.12-BTF task_cred=0x900 cred_cap_eff=0x40 cred_cap_bset=0x48 itimer_node=0x78 slot_stride=0x100"
            ksu_select_ko "g856" "$KSU_FLAVOR"
            export MAGICROOT_KSU_TEMPLATE="$KO_TEMPLATE"
            export MAGICROOT_KSU_COMPAT="$KO_COMPAT"
            export MAGICROOT_FLAVOR_SYMS_MISSING="$FLAVOR_SYMS_MISSING"
            return 0
            ;;
        6.18.*)
            PROFILE_ID="reserved-6.18"
            KO_TEMPLATE=""
            return 0
            ;;
        *)
            PROFILE_ID="unsupported"
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Second chain: CVE-2026-98260 (Honor 6.12.58 / 6.12.38 adapted builds).
#
# This profile is deliberately NOT reachable from select_kernel_profile():
# the 98260 binaries derive their own KASLR slide (tracefs kprobe + perf), so
# the 64560 KASLR anchors/syms are never used for it.  run.sh only calls this
# when MAGICROOT_CHAIN=98260; the 64560 pipeline keeps its own behavior.
# The shared stage machine (assets/98260/run98260.sh) selects the per-kernel
# binary directory itself from the exact uname -r build.
# ---------------------------------------------------------------------------
CHAIN_98260_PROFILE_ID="honor-61258-98260"
CHAIN_98260_KERNEL="6.12.58-android16-6-g3a7ac1674240-abogki541502914-4k"
CHAIN_98260_PROFILE_ID_61258B="honor-61258b-98260"
CHAIN_98260_KERNEL_61258B="6.12.58-android16-6-g459a4285ccf8-abogki532718632-4k"
CHAIN_98260_PROFILE_ID_61258C="honor-61258c-98260"
CHAIN_98260_KERNEL_61258C="6.12.58-android16-6-g42fcf008ff5c-abogki504518581-4k"
CHAIN_98260_PROFILE_ID_APH112="honor-aph112-98260"
CHAIN_98260_PROFILE_ID_6138="honor-6138-98260"
CHAIN_98260_KERNEL_6138="6.12.38-android16-5-gfde7767f6ef6-abogki481467632-4k"
CHAIN_98260_PROFILE_ID_6123="honor-6123-98260"
CHAIN_98260_KERNEL_6123="6.12.23-android16-5-g45ea5e4bce8a-abogki445100407-4k"
CHAIN_98260_PROFILE_ID_G856="honor-g856-98260"
CHAIN_98260_KERNEL_G856="6.12.23-android16-5-gcd85666d7884-abogki452537391-4k"
CHAIN_98260_PROFILE_ID_6138Y="honor-6138y-98260"
CHAIN_98260_KERNEL_6138Y="6.12.38-android16-5-g7ae8ec909e03-abogki471017112-4k"
CHAIN_98260_PROFILE_ID_G554="honor-g554-66118-98260"
CHAIN_98260_KERNEL_G554="6.6.118-android15-8-g554929766a0d-abogki544555896-4k"
CHAIN_98260_PROFILE_ID_F171="honor-f171-66118-98260"
CHAIN_98260_KERNEL_F171="6.6.118-android15-8-gf17133276a57-abogki518694926-4k"
CHAIN_98260_PROFILE_ID_6658="honor-6658-98260"
CHAIN_98260_KERNEL_6658="6.6.58-android15-8-g6484937db664-abogki407459068-4k"
CHAIN_98260_PROFILE_ID_6689="honor-6689-98260"
CHAIN_98260_KERNEL_6689="6.6.89-android15-8-g082e5a98dac1-abogki463734347-4k"
CHAIN_98260_PROFILE_ID_61821="honor-61821-98260"
CHAIN_98260_KERNEL_61821="6.18.21-android17-5-g928d1bb4f1d7-abogki542339678-4k"
CHAIN_98260_PROFILE_ID_61821BRM="honor-61821-brm-98260"
CHAIN_98260_KERNEL_61821BRM="6.18.21-android17-5-ge186062ea75f-abogki564062290-4k"
CHAIN_98260_PROFILE_ID_61821H1C117="honor-61821-h1c117-98260"
CHAIN_98260_KERNEL_61821H1C117="6.18.21-android17-5-gfee2325de189-abogki572422516-4k"
CHAIN_98260_PROFILE_ID_G142="honor-g142-98260"
CHAIN_98260_KERNEL_G142="6.12.58-android16-6-g142ddad31e60-abogki576095858-4k"
CHAIN_98260_PROFILE_ID_GA812="honor-ga812-98260"
CHAIN_98260_KERNEL_GA812="6.6.118-android15-8-ga812a1946391-abogki576098434-4k"
CHAIN_98260_PROFILE_ID_G893="honor-g893-66118-98260"
CHAIN_98260_KERNEL_G893="6.6.118-android15-8-g893e848657cc-4k"
CHAIN_98260_PROFILE_ID_G4B36="honor-g4b36-98260"
CHAIN_98260_KERNEL_G4B36="6.12.38-android16-5-g4b3671e1f5b7-abogki460618149-4k"
CHAIN_98260_PROFILE_ID_G52D15="honor-g52d15-98260"
CHAIN_98260_KERNEL_G52D15="6.12.81-android16-6-g52d15df5db87-abogki576042287-4k"
CHAIN_98260_KERNELS="$CHAIN_98260_KERNEL|$CHAIN_98260_KERNEL_61258B|$CHAIN_98260_KERNEL_61258C|$CHAIN_98260_KERNEL_6138|$CHAIN_98260_KERNEL_6123|$CHAIN_98260_KERNEL_G856|$CHAIN_98260_KERNEL_6138Y|$CHAIN_98260_KERNEL_G554|$CHAIN_98260_KERNEL_F171|$CHAIN_98260_KERNEL_6658|$CHAIN_98260_KERNEL_6689|$CHAIN_98260_KERNEL_61821|$CHAIN_98260_KERNEL_61821BRM|$CHAIN_98260_KERNEL_G142|$CHAIN_98260_KERNEL_GA812|$CHAIN_98260_KERNEL_G893|$CHAIN_98260_KERNEL_G4B36|$CHAIN_98260_KERNEL_61821H1C117|$CHAIN_98260_KERNEL_G52D15"

select_chain_98260_profile() {
    _chain_release="$1"
    _chain_model="${2:-}"
    PROFILE_CHAIN=98260
    PROFILE_READY=1
    case "$_chain_release" in
        "$CHAIN_98260_KERNEL")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID" ;;
        "$CHAIN_98260_KERNEL_61258B")
            if [ "$_chain_model" = "APH-AN00" ]; then
                PROFILE_ID="$CHAIN_98260_PROFILE_ID_APH112"
            else
                PROFILE_ID="$CHAIN_98260_PROFILE_ID_61258B"
            fi ;;
        "$CHAIN_98260_KERNEL_61258C")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_61258C" ;;
        "$CHAIN_98260_KERNEL_6138")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_6138" ;;
        "$CHAIN_98260_KERNEL_6123")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_6123" ;;
        "$CHAIN_98260_KERNEL_G856")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_G856" ;;
        "$CHAIN_98260_KERNEL_6138Y")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_6138Y" ;;
        "$CHAIN_98260_KERNEL_G554")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_G554" ;;
        "$CHAIN_98260_KERNEL_F171")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_F171" ;;
        "$CHAIN_98260_KERNEL_6658")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_6658" ;;
        "$CHAIN_98260_KERNEL_6689")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_6689" ;;
        "$CHAIN_98260_KERNEL_G142")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_G142" ;;
        "$CHAIN_98260_KERNEL_GA812")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_GA812" ;;
        "$CHAIN_98260_KERNEL_G893")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_G893" ;;
        "$CHAIN_98260_KERNEL_G4B36")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_G4B36" ;;
        "$CHAIN_98260_KERNEL_G52D15")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_G52D15" ;;
        "$CHAIN_98260_KERNEL_61821")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_61821" ;;
        "$CHAIN_98260_KERNEL_61821BRM")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_61821BRM" ;;
        "$CHAIN_98260_KERNEL_61821H1C117")
            PROFILE_ID="$CHAIN_98260_PROFILE_ID_61821H1C117" ;;
        *)
            PROFILE_READY=0
            return 1 ;;
    esac
    return 0
}
