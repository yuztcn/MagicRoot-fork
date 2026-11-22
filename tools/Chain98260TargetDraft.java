package com.aoki.magicroot;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Maintainer-only CLI: draft a {@code pc98260_target_<id>.h} from a local
 * boot.img for the 98260 BRM (6.12.x/6.6.x) chain. See
 * docs/98260-612-NEW-KERNEL-PORTING.md for the full workflow this fits
 * into and why its output is a *draft*, not something the app ships or
 * runs on its own.
 *
 * <p>This is a PC-side developer tool, not part of the APK: it is not
 * referenced by MainActivity.java, not registered in ASSETS/ASSETS_98260,
 * and does not change anything run98260.sh/run.sh dispatch on a device.
 * It only reuses {@link KernelProfileGenerator}, which already ships in
 * the app for the (separate, already-wired) 6.18.x adaptive-profile and
 * 6.12.x/6.6.x kallsyms-dump features.</p>
 *
 * <p>Build and run (from the repo root):</p>
 * <pre>
 * mkdir -p /tmp/draft-out
 * javac -d /tmp/draft-out \
 *     main/compose-app/app/src/main/java/com/aoki/magicroot/KernelProfileGenerator.java \
 *     tools/Chain98260TargetDraft.java
 * java -cp /tmp/draft-out com.aoki.magicroot.Chain98260TargetDraft \
 *     /path/to/boot.img /tmp/draft-out/pc98260_target_NEW.h
 * </pre>
 */
public final class Chain98260TargetDraft {
    private Chain98260TargetDraft() {}

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("用法: Chain98260TargetDraft <boot.img> <输出.h路径>");
            System.exit(2);
        }
        try {
            byte[] boot = Files.readAllBytes(Paths.get(args[0]));
            byte[] image = KernelProfileGenerator.extractKernel(boot);
            KernelProfileGenerator.Chain98260Draft draft = KernelProfileGenerator.generateChain98260Draft(image);
            String text = draft.toHeaderText();
            Files.write(Paths.get(args[1]), text.getBytes(StandardCharsets.UTF_8));
            System.out.println("DRAFT_OK kernel=" + draft.kernel + " out=" + args[1]);
            System.out.println("下一步（全部需要人工完成，本工具只产出草稿常量）：");
            System.out.println("  1. 用反汇编器核对 LINK_ALLOC_TIMER / LINK_ALLOC_CRED 两处调用点，");
            System.out.println("     确认确实是该内核版本 do_timer_create/prepare_creds 里唯一一处");
            System.out.println("     kmem_cache_alloc* 调用，而不是误匹配到其他分配路径。");
            System.out.println("  2. 参照 binary-sources/98260-6.12/build-98260-6.12.ps1 编译出");
            System.out.println("     针对这个内核的新 exploit-android-key-ptr 二进制。");
            System.out.println("  3. 在对应真机上验证完整 98260 链路后，才能把新的内核 case 加进");
            System.out.println("     main/app/assets/run.sh / 98260/run98260.sh 的分派表。");
        } catch (IOException e) {
            System.err.println("FAIL=" + e.getMessage());
            System.exit(1);
        }
    }
}
