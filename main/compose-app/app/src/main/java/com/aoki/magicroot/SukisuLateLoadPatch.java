package com.aoki.magicroot;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;

/**
 * Device-side structural patch for the SukiSU late-load input-hook cleanup.
 *
 * MagicRoot loads the manager's KernelSU LKM late (after boot).  In late-load
 * mode upstream core/init.c skips ksu_ksud_init(), including
 * INIT_WORK(stop_input_hook_work), yet on_post_fs_data() still schedules that
 * work item, so the first zygote pass triggers WARN_ON(!list_empty(&work->entry))
 * in __queue_work().  For a late-loaded module no input kprobe/work was ever
 * installed, so ksu_stop_input_hook_runtime() is a semantic no-op and returning
 * immediately is correct.
 *
 * The patch replaces the flag-test TBNZ in the function prologue with RET.  The
 * prologue is "ADRP flag; LDRB flag; TBNZ flag -> cleanup"; on 6.18 a BTI
 * precedes it, so the TBNZ is located by scanning for the ADRP+LDRB+TBNZ
 * sequence rather than by a fixed offset.  Only the TBNZ is patched; the ADRP
 * and LDRB carry ELF relocations that the kernel applies at insmod and must be
 * left intact.  The patch is refused if the TBNZ site is itself a relocation.
 *
 * This is kernel-version agnostic: it was verified against the SukiSU 41150
 * modules for 6.6.127, 6.12.76 and 6.18.32 carved from the manager's native
 * library, all of which share the same instruction sequence.
 */
public final class SukisuLateLoadPatch {
    private static final String FUNCTION = "ksu_stop_input_hook_runtime";
    private static final int AARCH64_RET = 0xd65f03c0;   // little-endian int
    private static final int EXPECTED_TBNZ = 0x370001c9; // tbnz w9, #0, ...

    private SukisuLateLoadPatch() {
    }

    private static final class Section {
        int nameOff, type, link, info;
        long addr, offset, size, entsize;
        String name;
    }

    private static int u16(ByteBuffer b, int off) {
        return b.getShort(off) & 0xffff;
    }

    private static long u64(ByteBuffer b, int off) {
        return b.getLong(off);
    }

    private static int u32(ByteBuffer b, int off) {
        return b.getInt(off);
    }

    private static ArrayList<Section> sections(ByteBuffer b) {
        if (b.capacity() < 64 || b.get(0) != 0x7f || b.get(1) != 'E'
                || b.get(2) != 'L' || b.get(3) != 'F')
            throw new IllegalArgumentException("not an ELF");
        if (b.get(4) != 2 || b.get(5) != 1)
            throw new IllegalArgumentException("expected little-endian ELF64");
        if (u16(b, 16) != 1 || u16(b, 18) != 183)
            throw new IllegalArgumentException("expected an AArch64 relocatable module");
        long shoff = u64(b, 40);
        int shentsize = u16(b, 58);
        int shnum = u16(b, 60);
        int shstrndx = u16(b, 62);
        if (shentsize != 64 || shnum <= shstrndx)
            throw new IllegalArgumentException("bad section table");
        ArrayList<Section> out = new ArrayList<>();
        for (int i = 0; i < shnum; i++) {
            int off = (int) shoff + i * shentsize;
            Section s = new Section();
            s.nameOff = u32(b, off);
            s.type = u32(b, off + 4);
            s.addr = u64(b, off + 16);
            s.offset = u64(b, off + 24);
            s.size = u64(b, off + 32);
            s.link = u32(b, off + 40);
            s.info = u32(b, off + 44);
            s.entsize = u64(b, off + 56);
            out.add(s);
        }
        Section names = out.get(shstrndx);
        for (Section s : out) {
            int base = (int) names.offset + s.nameOff;
            StringBuilder sb = new StringBuilder();
            for (int i = base; i < b.capacity() && b.get(i) != 0; i++)
                sb.append((char) b.get(i));
            s.name = sb.toString();
        }
        return out;
    }

    private static int symbolOffset(ByteBuffer b, ArrayList<Section> secs, String name) {
        for (Section sym : secs) {
            if (sym.type != 2 || sym.entsize != 24)
                continue; // SHT_SYMTAB
            Section str = secs.get(sym.link);
            for (long off = sym.offset; off < sym.offset + sym.size; off += 24) {
                int nameOff = u32(b, (int) off);
                int info = b.get((int) off + 4) & 0xff;
                int shndx = u16(b, (int) off + 6);
                long value = u64(b, (int) off + 8);
                long size = u64(b, (int) off + 16);
                StringBuilder sb = new StringBuilder();
                for (int i = (int) str.offset + nameOff;
                     i < b.capacity() && b.get(i) != 0; i++)
                    sb.append((char) b.get(i));
                if (!name.contentEquals(sb))
                    continue;
                if ((info & 0x0f) != 2 || shndx == 0 || shndx >= secs.size() || size < 4)
                    throw new IllegalArgumentException("unexpected symbol layout for " + name);
                Section sec = secs.get(shndx);
                long fileOff = sec.offset + value;
                if (fileOff + 4 > b.capacity())
                    throw new IllegalArgumentException("symbol points outside file");
                return (int) fileOff;
            }
        }
        throw new IllegalArgumentException("symbol not found: " + name);
    }

    /** Locate the TBNZ that follows "ADRP reg; LDRB [reg]" in the prologue. */
    private static int findFlagTestTbnz(ByteBuffer b, int funcOff) {
        for (int i = 0; i + 12 <= 48 && funcOff + i + 12 <= b.capacity(); i += 4) {
            int a = b.getInt(funcOff + i);
            int l = b.getInt(funcOff + i + 4);
            int t = b.getInt(funcOff + i + 8);
            boolean adrp = (a & 0x9f000000) == 0x90000000;
            boolean ldrb = (l & 0xffc00000) == 0x39400000;
            boolean tbnz = (t >>> 24) == 0x37;
            if (adrp && ldrb && tbnz)
                return funcOff + i + 8;
        }
        return -1;
    }

    private static void assertNoRelocation(ByteBuffer b, ArrayList<Section> secs,
                                           int fileOff) {
        int owner = -1;
        long target = -1;
        for (int i = 0; i < secs.size(); i++) {
            Section s = secs.get(i);
            if (s.type == 8)
                continue; // SHT_NOBITS has no file bytes
            if (s.offset <= fileOff && fileOff < s.offset + s.size) {
                owner = i;
                target = s.addr + fileOff - s.offset;
                break;
            }
        }
        if (owner < 0)
            throw new IllegalArgumentException("patch offset outside any section");
        for (Section s : secs) {
            if ((s.type != 4 && s.type != 9) || s.info != owner)
                continue; // SHT_RELA / SHT_REL for the owner section
            long entsize = s.entsize != 0 ? s.entsize : (s.type == 4 ? 24 : 16);
            for (long off = s.offset; off < s.offset + s.size; off += entsize) {
                long relocOff = u64(b, (int) off);
                if (relocOff == target)
                    throw new IllegalArgumentException("refusing to patch a relocation site");
            }
        }
    }

    /**
     * Patch a carved SukiSU late-load module.  Returns null when the module
     * does not carry the expected function/prologue (different SukiSU build),
     * so the caller can fall back to the unpatched module or a built-in
     * pre-patched template.
     */
    public static byte[] patch(byte[] ko) {
        try {
            ByteBuffer b = ByteBuffer.wrap(ko).order(ByteOrder.LITTLE_ENDIAN);
            ArrayList<Section> secs = sections(b);
            int funcOff = symbolOffset(b, secs, FUNCTION);
            int tbnzOff = findFlagTestTbnz(b, funcOff);
            if (tbnzOff < 0)
                return null;
            if (b.getInt(tbnzOff) != EXPECTED_TBNZ)
                return null;
            assertNoRelocation(b, secs, tbnzOff);
            byte[] out = ko.clone();
            // write RET little-endian
            out[tbnzOff] = (byte) 0xc0;
            out[tbnzOff + 1] = 0x03;
            out[tbnzOff + 2] = 0x5f;
            out[tbnzOff + 3] = (byte) 0xd6;
            return out;
        } catch (Throwable t) {
            return null;
        }
    }
}
