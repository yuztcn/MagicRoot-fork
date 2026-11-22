package com.aoki.magicroot;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

/** Offline boot image unpacker and 98260 profile generator for Android. */
public final class KernelProfileGenerator {
    private static final long IMAGE_BASE = 0xffffffc080000000L;
    private static final byte[] ANDROID_MAGIC = "ANDROID!".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ARM64_MAGIC = "ARMd".getBytes(StandardCharsets.US_ASCII);

    private KernelProfileGenerator() {}

    public static final class Symbol {
        final long address;
        final String name;
        final char type;

        Symbol(long address, String name, char type) {
            this.address = address;
            this.name = name;
            this.type = type;
        }
    }

    public static final class Result {
        public final String kernel;
        public final String id;
        public final long timerLink;
        public final long credLink;
        public final long slideSiteLow;
        public final long selinuxLink;
        public final long userNs;
        public final long rootUser;
        public final long groups;
        public final long ucounts;
        public final int kitimerSize;
        public final int kitimerNode;
        public final int taskCred;
        public final int credSize;
        public final List<Symbol> symbols;
        public final long beginNewExec;
        public final int btfBase;
        public final int kallsymsCount;

        Result(String kernel, String id, long timerLink, long credLink,
               long slideSiteLow, long selinuxLink, long userNs, long rootUser,
               long groups, long ucounts, int kitimerSize, int kitimerNode,
               int taskCred, int credSize, List<Symbol> symbols,
               long beginNewExec, int btfBase, int kallsymsCount) {
            this.kernel = kernel;
            this.id = id;
            this.timerLink = timerLink;
            this.credLink = credLink;
            this.slideSiteLow = slideSiteLow;
            this.selinuxLink = selinuxLink;
            this.userNs = userNs;
            this.rootUser = rootUser;
            this.groups = groups;
            this.ucounts = ucounts;
            this.kitimerSize = kitimerSize;
            this.kitimerNode = kitimerNode;
            this.taskCred = taskCred;
            this.credSize = credSize;
            this.symbols = symbols;
            this.beginNewExec = beginNewExec;
            this.btfBase = btfBase;
            this.kallsymsCount = kallsymsCount;
        }

        public String toSymbolText() {
            StringBuilder out = new StringBuilder(symbols.size() * 48);
            for (Symbol symbol : symbols) {
                out.append(String.format(Locale.ROOT, "%016x %c %s\n",
                        symbol.address, symbol.type, symbol.name));
            }
            return out.toString();
        }

        public String safeId() {
            return id.replaceAll("[^A-Za-z0-9_.-]+", "-");
        }
    }

    /**
     * Plain kallsyms dump for the 6.12.x/6.6.x "ko_patch" flow.
     *
     * <p>Unlike {@link #generate}, this does not touch BTF or validate any
     * vulnerability call order: 6.12/6.6 are standard GKI builds where
     * kallsyms is exported normally (see binary-sources/66118/PATCH-NOTES.md
     * — "本内核 kallsyms 中 0 缺失"), so a local, offline symbol dump from the
     * boot image is a complete and verifiable {@code name 0xADDR} table, the
     * same thing tools/gen_syms_from_vmlinux.py produces from a vmlinux.
     * 6.1.x is deliberately rejected here: those vendor kernels hide
     * commit_creds and friends from kallsyms, so a local dump would look
     * complete while silently missing the addresses that actually matter —
     * see docs 6157-SUPPORT-AUDIT.md / the CGA absolute-symbol remap.</p>
     */
    public static final class KallsymsResult {
        public final String kernel;
        public final String id;
        public final List<Symbol> symbols;
        public final int kallsymsCount;

        KallsymsResult(String kernel, String id, List<Symbol> symbols, int kallsymsCount) {
            this.kernel = kernel;
            this.id = id;
            this.symbols = symbols;
            this.kallsymsCount = kallsymsCount;
        }

        public String safeId() {
            return id.replaceAll("[^A-Za-z0-9_.-]+", "-");
        }
    }

    private static final String[] KALLSYMS_SANITY_SYMBOLS = {
            "commit_creds", "prepare_creds", "_printk",
            "init_user_ns", "init_groups", "init_ucounts",
    };

    public static KallsymsResult generateKallsyms(byte[] image) throws IOException {
        String kernel = parseKernelRelease(image);
        if (kernel.startsWith("6.18.")) {
            throw new IOException("6.18.x 请使用完整的自适应生成（含 BTF/漏洞签名校验），不要用纯 kallsyms 导出: " + kernel);
        }
        if (!(kernel.startsWith("6.12.") || kernel.startsWith("6.6."))) {
            throw new IOException("纯 kallsyms 导出仅支持 6.12.x / 6.6.x GKI 内核，当前: " + kernel
                    + "（6.1.x 厂商内核会把 commit_creds 等关键符号从 kallsyms 隐藏，"
                    + "本地镜像无法安全推导地址，必须走真机 CGA 符号表路线，不能用这个导出）");
        }
        ParsedKallsyms parsed = parseKallsyms(image);
        Map<String, Long> symbols = new HashMap<>(parsed.symbols.size() * 2);
        for (Symbol symbol : parsed.symbols) symbols.putIfAbsent(symbol.name, symbol.address);
        // Fail closed rather than silently shipping a dump missing the
        // handful of symbols every KSU LKM template actually needs; ko_patch
        // itself reports MISSING=N per-module, but a dump that is already
        // incomplete for these anchors is not worth writing out at all.
        for (String name : KALLSYMS_SANITY_SYMBOLS) requireSymbol(symbols, name);
        String safe = kernel.replaceAll("[^A-Za-z0-9_.-]+", "-");
        return new KallsymsResult(kernel, "kernel-" + safe, parsed.symbols, parsed.symbols.size());
    }

    /**
     * Draft {@code pc98260_target_<id>.h} constants for the 98260 BRM
     * (legacy, precompiled-binary) chain on 6.12.x/6.6.x — a PC/maintainer
     * porting aid, not an on-device/APK capability.
     *
     * <p>Unlike {@link #generateKallsyms}, this also resolves the two
     * function-internal allocator call sites ({@code do_timer_create} /
     * {@code prepare_creds} — see {@code LINK_ALLOC_TIMER}/{@code
     * LINK_ALLOC_CRED} in the existing {@code binary-sources/*}/
     * {@code pc98260_target_*.h} files) by disassembling the one BL
     * instruction inside each function that targets a {@code
     * kmem_cache_alloc*} symbol, plus the {@code cred}/{@code k_itimer}
     * BTF geometry {@link #generate} already parses for 6.18. These two
     * offsets are NOT portable across kernel branches (6.12.x uses
     * {@code do_timer_create+0xac}, 6.6.x uses {@code +0x94}, 6.18.x uses
     * {@code +0xb8} — confirmed from the existing per-build headers), so
     * they must be recomputed per exact kernel, never copied from a
     * neighbouring build.</p>
     *
     * <p>This method only produces the numeric constants a human still has
     * to review before they go into a new {@code pc98260_target_*.h} and
     * get compiled (via the existing {@code build-98260-6.12.ps1}
     * pipeline) into a brand-new {@code exploit-android-key-ptr} binary.
     * It does not patch, dispatch, or run anything — {@code
     * exploit-android-key-ptr} bakes these constants in at compile time,
     * so a new kernel always needs a newly compiled binary regardless of
     * how the constants were derived; see {@code LINK_ALLOC_TASK}'s
     * instability across even same-branch builds
     * (6.6.89: {@code copy_process+0x13c} vs 6.6.118: {@code +0x144}) for
     * why no offset here should ever be assumed stable without this kind
     * of per-build recomputation.</p>
     */
    public static final class Chain98260Draft {
        public final String kernel;
        public final String id;
        public final long linkSelinuxState;
        public final long linkInitUserNs;
        public final long linkRootUser;
        public final long linkInitGroups;
        public final long linkInitUcounts;
        public final Long memstartAddr;
        public final long linkAllocTimer;
        public final int timerLinkOffset;
        public final String timerSiteFunc;
        public final long linkAllocCred;
        public final int credLinkOffset;
        public final int taskCred;
        public final int taskRealCred;
        public final int kitimerSize;
        public final int kitimerIt;
        public final int credSize;
        public final Map<String, Integer> credMembers;

        Chain98260Draft(String kernel, String id, long linkSelinuxState, long linkInitUserNs,
                         long linkRootUser, long linkInitGroups, long linkInitUcounts, Long memstartAddr,
                         long linkAllocTimer, int timerLinkOffset, String timerSiteFunc,
                         long linkAllocCred, int credLinkOffset,
                         int taskCred, int taskRealCred, int kitimerSize, int kitimerIt, int credSize,
                         Map<String, Integer> credMembers) {
            this.kernel = kernel;
            this.id = id;
            this.linkSelinuxState = linkSelinuxState;
            this.linkInitUserNs = linkInitUserNs;
            this.linkRootUser = linkRootUser;
            this.linkInitGroups = linkInitGroups;
            this.linkInitUcounts = linkInitUcounts;
            this.memstartAddr = memstartAddr;
            this.linkAllocTimer = linkAllocTimer;
            this.timerLinkOffset = timerLinkOffset;
            this.timerSiteFunc = timerSiteFunc;
            this.linkAllocCred = linkAllocCred;
            this.credLinkOffset = credLinkOffset;
            this.taskCred = taskCred;
            this.taskRealCred = taskRealCred;
            this.kitimerSize = kitimerSize;
            this.kitimerIt = kitimerIt;
            this.credSize = credSize;
            this.credMembers = credMembers;
        }

        public String safeId() {
            return id.replaceAll("[^A-Za-z0-9_.-]+", "-");
        }

        /** Renders a draft header in the same shape as the hand-written
         * {@code pc98260_target_*.h} files, clearly marked as unreviewed. */
        public String toHeaderText() {
            // C preprocessor guards only allow [A-Za-z0-9_]; safeId() keeps
            // '.' and '-' for filenames, so sanitize those separately here.
            String guard = "PC98260_TARGET_"
                    + safeId().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9_]", "_") + "_H";
            StringBuilder out = new StringBuilder();
            out.append("/* MACHINE-GENERATED DRAFT — DO NOT COMPILE OR SHIP WITHOUT HUMAN REVIEW.\n")
               .append(" * Produced by KernelProfileGenerator.generateChain98260Draft() from a local\n")
               .append(" * boot.img; see docs/98260-612-NEW-KERNEL-PORTING.md. LINK_ALLOC_TIMER/\n")
               .append(" * LINK_ALLOC_CRED are a disassembly heuristic (first BL to kmem_cache_alloc*\n")
               .append(" * inside the function) verified against two already-shipped builds, not a\n")
               .append(" * proof it is right for THIS kernel. Spot-check both against a disassembler\n")
               .append(" * before compiling exploit-android-key-ptr for a new target.\n")
               .append(" *\n")
               .append(" * Target: ").append(kernel).append("\n")
               .append(" */\n")
               .append("#ifndef ").append(guard).append("\n")
               .append("#define ").append(guard).append("\n\n")
               .append("#include <stdint.h>\n\n")
               .append("#define TARGET_KERNEL        \"").append(kernel).append("\"\n\n")
               .append("/* ---- absolute addresses (link-time; add g_slide at runtime) ---------- */\n")
               .append(hex("LINK_SELINUX_STATE", linkSelinuxState, "selinux_state"))
               .append(hex("LINK_INIT_USER_NS", linkInitUserNs, "init_user_ns"))
               .append(hex("LINK_ROOT_USER", linkRootUser, "root_user"))
               .append(hex("LINK_INIT_GROUPS", linkInitGroups, "init_groups"))
               .append(hex("LINK_INIT_UCOUNTS", linkInitUcounts, "init_ucounts"));
            if (memstartAddr != null) out.append(hex("GEOM_MEMSTART_ADDR", memstartAddr, "memstart_addr symbol"));
            out.append("\n/* ---- allocator call sites (disassembly-derived; NOT portable) -------- */\n")
               .append(hex("LINK_ALLOC_TIMER", linkAllocTimer,
                       String.format(Locale.ROOT, "%s+0x%x", timerSiteFunc, timerLinkOffset)))
               .append(hex("LINK_ALLOC_CRED", linkAllocCred,
                       String.format(Locale.ROOT, "prepare_creds+0x%x", credLinkOffset)))
               .append("\n/* ---- struct geometry (BTF, byte offsets) ------------------------------ */\n")
               .append(String.format(Locale.ROOT, "#define GEO_TASK_CRED        0x%x%n", taskCred))
               .append(String.format(Locale.ROOT, "#define GEO_TASK_REAL_CRED   0x%x%n", taskRealCred))
               .append(String.format(Locale.ROOT, "#define GEO_KITIMER_IT       0x%x%n", kitimerIt))
               .append(String.format(Locale.ROOT, "#define GEO_KITIMER_SIZE     0x%x%n", kitimerSize))
               .append(String.format(Locale.ROOT, "#define GEO_CRED_SIZE        %d%n", credSize));
            for (Map.Entry<String, Integer> entry : credMembers.entrySet()) {
                // BTF padding/anonymous members have an empty name; skip them
                // rather than emit an invalid "#define GEO_CRED_ 0x.." macro.
                if (entry.getKey() == null || entry.getKey().isEmpty()) continue;
                out.append(String.format(Locale.ROOT, "#define GEO_CRED_%-12s 0x%x%n",
                        entry.getKey().toUpperCase(Locale.ROOT), entry.getValue()));
            }
            out.append("\n/* ---- platform constants (same across every known sample; NOT derived\n")
               .append(" * from this image — verify on a real device via /proc/iomem if this is a\n")
               .append(" * genuinely new SoC/platform, not just a new Honor firmware build) -------- */\n")
               .append("#define GEOM_PAGE_OFFSET     UINT64_C(0xffffff8000000000)\n")
               .append("#define GEOM_VA_BITS         39\n")
               .append("#define GEOM_MEMSTART_PFN    UINT64_C(0x80000)\n\n")
               .append("#endif /* ").append(guard).append(" */\n");
            return out.toString();
        }

        private static String hex(String macro, long value, String comment) {
            return String.format(Locale.ROOT, "#define %-20s UINT64_C(0x%x)  /* %s */%n", macro, value, comment);
        }
    }

    public static Chain98260Draft generateChain98260Draft(byte[] image) throws IOException {
        String kernel = parseKernelRelease(image);
        if (!(kernel.startsWith("6.12.") || kernel.startsWith("6.6."))) {
            throw new IOException("98260 BRM target-header 草稿生成仅支持 6.12.x / 6.6.x: " + kernel
                    + "（6.18.x 走 generate()/H1C 引擎；6.1.x 厂商内核的关键符号不在 kallsyms 里，"
                    + "没有可用的本地静态分析基础，必须走真机 CGA 路线）");
        }
        ParsedKallsyms parsed = parseKallsyms(image);
        Map<String, Long> symbols = new HashMap<>(parsed.symbols.size() * 2);
        for (Symbol symbol : parsed.symbols) symbols.putIfAbsent(symbol.name, symbol.address);
        for (String name : KALLSYMS_SANITY_SYMBOLS) requireSymbol(symbols, name);

        long doTimerCreate = requireSymbol(symbols, "do_timer_create");
        // 6.12.58-era builds inline alloc_posix_timer(), so the k_itimer
        // allocation call site lives in do_timer_create.  Newer 6.12.x builds
        // (first seen in 6.12.81-android16-6-g52d15df5db87) keep alloc_posix_timer()
        // as a real function and do_timer_create merely BLs to it; the trace
        // event still fires at the kmem_cache_alloc* return site inside
        // alloc_posix_timer, so fall back to that function when the direct
        // scan fails.  findAllocCallSite rejects a wrong-function miss (no
        // kmem_cache_alloc* BL in body), so trying both is safe.
        long linkAllocTimer;
        long timerSiteStart;
        String timerSiteFunc;
        try {
            linkAllocTimer = findAllocCallSite(image, parsed.symbols, symbols, "do_timer_create");
            timerSiteStart = doTimerCreate;
            timerSiteFunc = "do_timer_create";
        } catch (IOException noInline) {
            linkAllocTimer = findAllocCallSite(image, parsed.symbols, symbols, "alloc_posix_timer");
            timerSiteStart = requireSymbol(symbols, "alloc_posix_timer");
            timerSiteFunc = "alloc_posix_timer";
        }
        long prepareCreds = requireSymbol(symbols, "prepare_creds");
        long linkAllocCred = findAllocCallSite(image, parsed.symbols, symbols, "prepare_creds");

        Btf btf = new Btf(image);
        Struct task = btf.requireStruct("task_struct");
        Struct kitimer = btf.requireStruct("k_itimer");
        Struct cred = btf.requireStruct("cred");

        String safe = kernel.replaceAll("[^A-Za-z0-9_.-]+", "-");
        return new Chain98260Draft(
                kernel, "kernel-" + safe,
                requireSymbol(symbols, "selinux_state"),
                requireSymbol(symbols, "init_user_ns"),
                requireSymbol(symbols, "root_user"),
                requireSymbol(symbols, "init_groups"),
                requireSymbol(symbols, "init_ucounts"),
                symbols.get("memstart_addr"),
                linkAllocTimer, (int) (linkAllocTimer - timerSiteStart), timerSiteFunc,
                linkAllocCred, (int) (linkAllocCred - prepareCreds),
                member(task, "cred"), member(task, "real_cred"),
                kitimer.size, member(kitimer, "it"),
                cred.size, new LinkedHashMap<>(cred.members));
    }

    /**
     * Scans {@code [start(funcName), start(next symbol))} for the first
     * {@code BL} instruction whose resolved absolute target is a symbol
     * named {@code kmem_cache_alloc*}, and returns {@code call_site + 4} —
     * the {@code _RET_IP_} a kernel allocator tracepoint/kprobe placed on
     * that call would observe. Verified to reproduce the hand-disassembled
     * {@code LINK_ALLOC_TIMER}/{@code LINK_ALLOC_CRED} values in the
     * existing {@code pc98260_target_g856.h} (6.12.23, +0xac/+0x2c) and
     * {@code pc98260_target_6689.h} (6.6.89, +0x94/+0x20) headers exactly.
     */
    private static long findAllocCallSite(byte[] image, List<Symbol> allSymbols,
                                           Map<String, Long> byName, String funcName)
            throws IOException {
        long begin = requireSymbol(byName, funcName);
        long end = begin + 0x4000;
        for (long address : byName.values()) {
            if (address > begin && address < end) end = address;
        }
        java.util.Set<Long> allocAddrs = new java.util.HashSet<>();
        for (Symbol symbol : allSymbols) {
            if (symbol.name.startsWith("kmem_cache_alloc")) allocAddrs.add(symbol.address);
        }
        for (long pc = begin; pc < end; pc += 4) {
            int fileOffset = (int) (pc - IMAGE_BASE);
            if (fileOffset < 0 || fileOffset + 4 > image.length) break;
            int instruction = u32(image, fileOffset);
            if ((instruction & 0xfc000000) != 0x94000000) continue;
            int imm = instruction & 0x03ffffff;
            if ((imm & 0x02000000) != 0) imm |= 0xfc000000;
            long target = pc + (long) imm * 4;
            if (allocAddrs.contains(target)) return pc + 4;
        }
        throw new IOException("在 " + funcName + " 函数体内未找到 kmem_cache_alloc* 调用（不是预期的分配模式，"
                + "拒绝猜测地址）");
    }

    public static byte[] extractKernel(byte[] boot) throws IOException {
        if (startsWith(boot, ANDROID_MAGIC)) {
            if (boot.length < 44) throw new IOException("boot.img 头部不完整");
            long kernelSizeLong = u32(boot, 8) & 0xffffffffL;
            int headerSize = u32(boot, 20);
            int headerVersion = u32(boot, 40);
            int pageSize = headerVersion >= 3 ? 4096 : u32(boot, 36);
            if (pageSize <= 0 || (pageSize & (pageSize - 1)) != 0)
                throw new IOException("无效的 boot image page size: " + pageSize);
            if (kernelSizeLong <= 0 || kernelSizeLong > 256L * 1024 * 1024)
                throw new IOException("无效的 kernel size: " + kernelSizeLong);
            int kernelOffset = align(headerSize, pageSize);
            int kernelSize = (int) kernelSizeLong;
            if (kernelOffset < 0 || kernelOffset + (long) kernelSize > boot.length)
                throw new IOException("boot.img kernel 区域越界");
            byte[] section = Arrays.copyOfRange(boot, kernelOffset, kernelOffset + kernelSize);
            return decompressKernel(section);
        }
        if (boot.length > 64 && boot[0x38] == 'A' && boot[0x39] == 'R'
                && boot[0x3a] == 'M' && boot[0x3b] == 'd') {
            return boot;
        }
        return decompressKernel(boot);
    }

    private static byte[] decompressKernel(byte[] data) throws IOException {
        if (data.length >= 2 && (data[0] & 0xff) == 0x1f && (data[1] & 0xff) == 0x8b) {
            try (GZIPInputStream in = new GZIPInputStream(new ByteArrayInputStream(data));
                 ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * 2)) {
                copyLimited(in, out, 256 * 1024 * 1024);
                return out.toByteArray();
            }
        }
        if (data.length > 64 && data[0x38] == 'A' && data[0x39] == 'R'
                && data[0x3a] == 'M' && data[0x3b] == 'd') {
            return data;
        }
        throw new IOException("不支持的内核压缩格式；请提供原始 AArch64 Image 或 gzip 内核");
    }

    public static Result generate(byte[] image) throws IOException {
        ParsedKallsyms parsed = parseKallsyms(image);
        Map<String, Long> symbols = new HashMap<>(parsed.symbols.size() * 2);
        for (Symbol symbol : parsed.symbols) symbols.putIfAbsent(symbol.name, symbol.address);
        String kernel = parseKernelRelease(image);
        if (!kernel.startsWith("6.18."))
            throw new IOException("当前 KernelSU 模块仅支持 6.18 KMI 内核: " + kernel);
        Map<String, Integer> calls = vulnerabilityCalls(image, symbols);
        if (!(calls.get("posix_cpu_timers_exit") > calls.get("unshare_files")
                && calls.get("posix_cpu_timers_exit") > calls.get("exec_task_namespaces"))) {
            throw new IOException("该内核已不具备目标漏洞调用顺序");
        }

        Btf btf = new Btf(image);
        Struct kitimer = btf.requireStruct("k_itimer");
        Struct task = btf.requireStruct("task_struct");
        Struct cred = btf.requireStruct("cred");
        int kitimerNode = member(kitimer, "it");
        int taskCred = member(task, "cred");
        Map<String, Integer> requiredCred = new LinkedHashMap<>();
        requiredCred.put("uid", 8);
        requiredCred.put("suid", 16);
        requiredCred.put("cap_inheritable", 48);
        requiredCred.put("cap_permitted", 56);
        requiredCred.put("cap_effective", 64);
        requiredCred.put("cap_bset", 72);
        requiredCred.put("cap_ambient", 80);
        requiredCred.put("security", 128);
        requiredCred.put("user", 136);
        requiredCred.put("user_ns", 144);
        requiredCred.put("ucounts", 152);
        requiredCred.put("group_info", 160);
        for (Map.Entry<String, Integer> entry : requiredCred.entrySet()) {
            int actual = member(cred, entry.getKey());
            if (actual != entry.getValue())
                throw new IOException("cred." + entry.getKey() + " 偏移不兼容: "
                        + actual + " != " + entry.getValue());
        }

        long doTimerCreate = requireSymbol(symbols, "do_timer_create");
        long prepareCreds = requireSymbol(symbols, "prepare_creds");
        long timerLink = doTimerCreate + 0xb8;
        long credLink = prepareCreds + 0x2c;
        String safe = kernel.replaceAll("[^A-Za-z0-9_.-]+", "-");
        return new Result(
                kernel,
                "kernel-" + safe,
                timerLink,
                credLink,
                timerLink & 0x1fffff,
                requireSymbol(symbols, "selinux_state"),
                requireSymbol(symbols, "init_user_ns"),
                requireSymbol(symbols, "root_user"),
                requireSymbol(symbols, "init_groups"),
                requireSymbol(symbols, "init_ucounts"),
                kitimer.size,
                kitimerNode,
                taskCred,
                cred.size,
                parsed.symbols,
                requireSymbol(symbols, "begin_new_exec"),
                btf.base,
                parsed.symbols.size());
    }

    public static byte[] patchVermagic(byte[] module, String kernelRelease) throws IOException {
        if (module.length < 64 || module[0] != 0x7f || module[1] != 'E'
                || module[2] != 'L' || module[3] != 'F')
            throw new IOException("KernelSU 模板不是 ELF 文件");
        long shoff = u64(module, 0x28);
        int shentsize = u16(module, 0x3a);
        int shnum = u16(module, 0x3c);
        int shstrndx = u16(module, 0x3e);
        if (shoff < 0 || shoff + (long) shentsize * shnum > module.length)
            throw new IOException("ELF section table 越界");
        int shstr = (int) (shoff + (long) shstrndx * shentsize);
        long strOff = u64(module, shstr + 24);
        long strSize = u64(module, shstr + 32);
        if (strOff < 0 || strSize < 0 || strOff + strSize > module.length)
            throw new IOException("ELF section names 越界");
        int modinfoHeader = -1;
        byte[] wanted = ".modinfo".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < shnum; i++) {
            int h = (int) (shoff + (long) i * shentsize);
            int nameOff = u32(module, h);
            if (nameOff < 0 || nameOff >= strSize) continue;
            int at = (int) strOff + nameOff;
            int end = at;
            while (end < module.length && module[end] != 0) end++;
            if (Arrays.equals(Arrays.copyOfRange(module, at, end), wanted)) {
                modinfoHeader = h;
                break;
            }
        }
        if (modinfoHeader < 0) throw new IOException("KernelSU 模板没有 .modinfo");
        long oldOff = u64(module, modinfoHeader + 24);
        long oldSize = u64(module, modinfoHeader + 32);
        if (oldOff < 0 || oldSize < 0 || oldOff + oldSize > module.length)
            throw new IOException(".modinfo 越界");
        byte[] old = Arrays.copyOfRange(module, (int) oldOff, (int) (oldOff + oldSize));
        byte[] magic = "vermagic=".getBytes(StandardCharsets.US_ASCII);
        byte[] replacement = "zermagic=".getBytes(StandardCharsets.US_ASCII);
        replaceAll(old, magic, replacement);
        byte[] vermagic = ("vermagic=" + kernelRelease
                + " SMP preempt mod_unload modversions aarch64\0")
                .getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream(module.length + old.length + vermagic.length);
        out.write(module);
        int newOff = out.size();
        out.write(old);
        out.write(vermagic);
        byte[] result = out.toByteArray();
        put64(result, modinfoHeader + 24, newOff);
        put64(result, modinfoHeader + 32, old.length + vermagic.length);
        return result;
    }

    private static Map<String, Integer> vulnerabilityCalls(byte[] image, Map<String, Long> symbols)
            throws IOException {
        String[] required = {"unshare_files", "exec_task_namespaces",
                "posix_cpu_timers_exit", "exit_itimers"};
        long begin = requireSymbol(symbols, "begin_new_exec");
        long end = begin + 0x2000;
        for (long address : symbols.values()) {
            if (address > begin && address < end) end = address;
        }
        Map<String, Integer> calls = new HashMap<>();
        for (long pc = begin; pc < end; pc += 4) {
            int fileOffset = (int) (pc - IMAGE_BASE);
            if (fileOffset < 0 || fileOffset + 4 > image.length) break;
            int instruction = u32(image, fileOffset);
            if ((instruction & 0xfc000000) != 0x94000000) continue;
            int imm = instruction & 0x03ffffff;
            if ((imm & 0x02000000) != 0) imm |= 0xfc000000;
            long target = pc + (long) imm * 4;
            for (String name : required) {
                Long symbol = symbols.get(name);
                if (symbol != null && symbol == target)
                    calls.put(name, (int) pc);
            }
        }
        for (String name : required) {
            if (!calls.containsKey(name))
                throw new IOException("未找到漏洞调用顺序: " + name);
        }
        return calls;
    }

    private static String parseKernelRelease(byte[] image) throws IOException {
        Pattern pattern = Pattern.compile("Linux version ([^\\s]+)");
        Matcher matcher = pattern.matcher(new String(image, StandardCharsets.ISO_8859_1));
        if (!matcher.find()) throw new IOException("未在镜像中找到 Linux 版本字符串");
        return matcher.group(1);
    }

    /** Let callers pick {@link #generate} vs {@link #generateKallsyms} before paying the full cost. */
    public static String peekKernelRelease(byte[] image) throws IOException {
        return parseKernelRelease(image);
    }

    private static long requireSymbol(Map<String, Long> symbols, String name) throws IOException {
        Long value = symbols.get(name);
        if (value == null) throw new IOException("缺少内核符号: " + name);
        return value;
    }

    private static int member(Struct struct, String name) throws IOException {
        Integer value = struct.members.get(name);
        if (value == null) throw new IOException("BTF 结构 " + struct.name + " 缺少字段 " + name);
        return value;
    }

    private static final class ParsedKallsyms {
        final List<Symbol> symbols;
        ParsedKallsyms(List<Symbol> symbols) { this.symbols = symbols; }
    }

    private static ParsedKallsyms parseKallsyms(byte[] image) throws IOException {
        byte[] alphabet = new byte[52];
        for (int i = 0; i < 26; i++) {
            alphabet[i * 2] = (byte) ('a' + i);
            alphabet[i * 2 + 1] = 0;
        }
        int search = 0;
        while (true) {
            int marker = indexOf(image, alphabet, search);
            if (marker < 0) throw new IOException("kallsyms token table not found");
            if (Boolean.getBoolean("hoc.profile.debug"))
                System.err.printf("kallsyms alphabet=%x%n", marker);
            search = marker + 1;
            try {
                int tokenStart = marker;
                for (int i = 0; i < 97; i++) {
                    tokenStart = lastIndexOf(image, (byte) 0, tokenStart - 2) + 1;
                    if (tokenStart <= 0) throw new IOException("bad token");
                }
                String[] tokens = new String[256];
                int pos = tokenStart;
                for (int i = 0; i < 256; i++) {
                    int end = indexOf(image, (byte) 0, pos);
                    if (end < 0) throw new IOException("bad token");
                    tokens[i] = new String(image, pos, end - pos, StandardCharsets.ISO_8859_1);
                    pos = end + 1;
                }
                int indexPos = align(pos, 8);
                if (indexPos + 512 > image.length) continue;
                int total = 0;
                boolean validIndex = true;
                for (int i = 0; i < 256; i++) {
                    int expected = total;
                    total += tokens[i].length() + 1;
                    if ((u16(image, indexPos + i * 2) & 0xffff) != expected) {
                        validIndex = false;
                        break;
                    }
                }
                if (!validIndex) continue;
                if (Boolean.getBoolean("hoc.profile.debug"))
                    System.err.printf("kallsyms table=%x index=%x%n", tokenStart, indexPos);
                int offsets = indexPos + 512;
                int baseMarker = indexOfLong(image, IMAGE_BASE, offsets,
                        Math.min(image.length, offsets + 0x2000000));
                if (baseMarker < 0) continue;
                int estimate = (baseMarker - offsets) / 4;
                if (Boolean.getBoolean("hoc.profile.debug"))
                    System.err.printf("kallsyms base=%x count=%d%n", baseMarker, estimate);
                for (int count = estimate - 4; count <= estimate + 4; count++) {
                    if (count <= 0) continue;
                    int namesPos = indexOfInt(image, count, Math.max(0, marker - 0x400000), marker);
                    while (namesPos >= 0) {
                        if ((namesPos & 3) == 0) {
                            List<Symbol> found = tryParseNames(
                                    image, namesPos, count, marker, tokenStart, tokens, offsets);
                            if (Boolean.getBoolean("hoc.profile.debug"))
                                System.err.printf("kallsyms names=%x count=%d parsed=%s%n",
                                        namesPos, count, found != null);
                            if (found != null) return new ParsedKallsyms(found);
                        }
                        namesPos = indexOfInt(image, count, namesPos + 1, marker);
                    }
                }
            } catch (IOException ignored) {
            }
        }
    }

    private static List<Symbol> tryParseNames(byte[] image, int namesPos, int count,
                                               int tokenStart, int tokenTableStart,
                                               String[] tokens, int offsets) {
        int cursor = namesPos + 8;
        List<Symbol> symbols = new ArrayList<>(count);
        try {
            for (int i = 0; i < count; i++) {
                int length = image[cursor++] & 0xff;
                if ((length & 0x80) != 0) {
                    length = (length & 0x7f) | ((image[cursor++] & 0xff) << 7);
                }
                if (length <= 0 || cursor + length > image.length) return null;
                StringBuilder name = new StringBuilder();
                for (int j = 0; j < length; j++) {
                    int token = image[cursor++] & 0xff;
                    name.append(tokens[token]);
                }
                if (name.length() == 0) return null;
                String encoded = name.toString();
                symbols.add(new Symbol(
                        IMAGE_BASE + ((u32(image, offsets + i * 4)) & 0xffffffffL),
                        encoded.substring(1), encoded.charAt(0)));
            }
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
        if (cursor > tokenTableStart || tokenTableStart - cursor >= 0x5000) return null;
        boolean hasText = false;
        for (int i = 0; i < Math.min(32, symbols.size()); i++) {
            if ("_text".equals(symbols.get(i).name)) {
                hasText = true;
                break;
            }
        }
        return hasText ? symbols : null;
    }

    private static final class Struct {
        final String name;
        final int size;
        final Map<String, Integer> members = new HashMap<>();
        Struct(String name, int size) { this.name = name; this.size = size; }
    }

    private static final class Btf {
        final int base;
        final Map<String, Struct> wanted = new HashMap<>();

        Btf(byte[] image) throws IOException {
            base = findHeader(image);
            int typeOff = u32(image, base + 8);
            int typeLen = u32(image, base + 12);
            int strOff = u32(image, base + 16);
            int strLen = u32(image, base + 20);
            int typeStart = base + 24 + typeOff;
            int typeEnd = typeStart + typeLen;
            int strStart = base + 24 + strOff;
            int strEnd = strStart + strLen;
            if (typeStart < 0 || typeEnd > image.length || strStart < 0 || strEnd > image.length)
                throw new IOException("BTF 区域越界");
            int pos = typeStart;
            while (pos < typeEnd) {
                int nameOff = u32(image, pos);
                int info = u32(image, pos + 4);
                int size = u32(image, pos + 8);
                pos += 12;
                int kind = (info >>> 24) & 0x1f;
                int vlen = info & 0xffff;
                boolean kflag = (info >>> 31) != 0;
                String name = btfString(image, strStart, strEnd, nameOff);
                if (kind == 1) {
                    pos += 4;
                } else if (kind == 3) {
                    pos += 12;
                } else if (kind == 4 || kind == 5) {
                    Struct struct = null;
                    if ("k_itimer".equals(name) || "task_struct".equals(name) || "cred".equals(name)) {
                        struct = new Struct(name, size);
                        wanted.putIfAbsent(name, struct);
                    }
                    for (int i = 0; i < vlen; i++) {
                        int memberName = u32(image, pos);
                        int memberType = u32(image, pos + 4);
                        int bitOffset = u32(image, pos + 8);
                        pos += 12;
                        if (kflag) bitOffset &= 0xffffff;
                        if (struct != null) {
                            String field = btfString(image, strStart, strEnd, memberName);
                            struct.members.put(field, bitOffset / 8);
                        }
                    }
                } else if (kind == 6) {
                    pos += 8 * vlen;
                } else if (kind == 19) {
                    pos += 12 * vlen;
                } else if (kind == 13) {
                    pos += 8 * vlen;
                } else if (kind == 14 || kind == 17) {
                    pos += 4;
                } else if (kind == 15) {
                    pos += 12 * vlen;
                }
                if (pos < typeStart || pos > typeEnd + 16) throw new IOException("BTF 类型表损坏");
            }
        }

        Struct requireStruct(String name) throws IOException {
            Struct struct = wanted.get(name);
            if (struct == null) throw new IOException("BTF 缺少结构: " + name);
            return struct;
        }

        private static int findHeader(byte[] image) throws IOException {
            for (int pos = 0; pos + 24 < image.length; pos++) {
                if ((image[pos] & 0xff) != 0x9f || (image[pos + 1] & 0xff) != 0xeb) continue;
                int version = image[pos + 2] & 0xff;
                int headerLen = u32(image, pos + 4);
                int typeLen = u32(image, pos + 12);
                int strLen = u32(image, pos + 20);
                if (version == 1 && headerLen == 24 && typeLen > 0 && typeLen < 20_000_000
                        && strLen > 0 && strLen < 4_000_000)
                    return pos;
            }
            throw new IOException("内核镜像中没有 BTF");
        }

        private static String btfString(byte[] image, int start, int end, int offset) {
            if (offset <= 0 || start + offset >= end) return "";
            int at = start + offset;
            int finish = at;
            while (finish < end && image[finish] != 0) finish++;
            return new String(image, at, finish - at, StandardCharsets.UTF_8);
        }
    }

    private static void copyLimited(ByteArrayInputStream in, ByteArrayOutputStream out, int limit)
            throws IOException {
        copyLimited((java.io.InputStream) in, out, limit);
    }

    private static void copyLimited(java.io.InputStream in, ByteArrayOutputStream out, int limit)
            throws IOException {
        byte[] buffer = new byte[65536];
        int total = 0;
        int n;
        while ((n = in.read(buffer)) > 0) {
            total += n;
            if (total > limit) throw new IOException("解压后内核超过大小限制");
            out.write(buffer, 0, n);
        }
    }

    private static void replaceAll(byte[] data, byte[] from, byte[] to) {
        if (from.length != to.length) throw new IllegalArgumentException("replacement length");
        outer:
        for (int i = 0; i + from.length <= data.length; i++) {
            for (int j = 0; j < from.length; j++) {
                if (data[i + j] != from[j]) continue outer;
            }
            System.arraycopy(to, 0, data, i, to.length);
            i += from.length - 1;
        }
    }

    private static int align(int value, int alignment) {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) return false;
        for (int i = 0; i < prefix.length; i++) if (data[i] != prefix[i]) return false;
        return true;
    }

    private static int u16(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8);
    }

    private static int u32(byte[] b, int o) {
        return (b[o] & 0xff) | ((b[o + 1] & 0xff) << 8)
                | ((b[o + 2] & 0xff) << 16) | ((b[o + 3] & 0xff) << 24);
    }

    private static long u64(byte[] b, int o) {
        return (u32(b, o) & 0xffffffffL) | ((u32(b, o + 4) & 0xffffffffL) << 32);
    }

    private static void put64(byte[] b, int o, long value) {
        for (int i = 0; i < 8; i++) b[o + i] = (byte) (value >>> (i * 8));
    }

    private static int indexOf(byte[] data, byte value, int from) {
        for (int i = Math.max(0, from); i < data.length; i++) if (data[i] == value) return i;
        return -1;
    }

    private static int lastIndexOf(byte[] data, byte value, int from) {
        for (int i = Math.min(from, data.length - 1); i >= 0; i--) if (data[i] == value) return i;
        return -1;
    }

    private static int indexOf(byte[] data, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i + needle.length <= data.length; i++) {
            for (int j = 0; j < needle.length; j++) if (data[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static int indexOfInt(byte[] data, int value, int from, int end) {
        for (int i = Math.max(0, from); i + 4 <= Math.min(end, data.length); i++) {
            if (u32(data, i) == value) return i;
        }
        return -1;
    }

    private static int indexOfLong(byte[] data, long value, int from, int end) {
        for (int i = Math.max(0, from); i + 8 <= Math.min(end, data.length); i++) {
            if (u64(data, i) == value) return i;
        }
        return -1;
    }
}
