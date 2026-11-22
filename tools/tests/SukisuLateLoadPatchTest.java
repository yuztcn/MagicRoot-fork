package com.aoki.magicroot;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

/** Regression gate for the device-side SukiSU late-load structural patch. */
public class SukisuLateLoadPatchTest {
    private static String sha256(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        StringBuilder sb = new StringBuilder();
        for (byte x : md.digest(b))
            sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        // Paths relative to the repository root (check.sh runs from there).
        // The pre-patched built-in asset was removed; the expected output is
        // pinned by its SHA-256 instead of by reading that file.
        byte[] input = Files.readAllBytes(Paths.get("main/app/assets/ksu-template-sukisu.ko"));

        byte[] out = SukisuLateLoadPatch.patch(input);
        if (out == null)
            throw new AssertionError("patch returned null on the audited input");
        if (!sha256(out).equals("bf41885860d1c01cef780dc5b31aabf01c8513f090aef264947f426c30f51442"))
            throw new AssertionError("output sha mismatch");

        // A module without the symbol/prologue must be refused, not corrupted.
        if (SukisuLateLoadPatch.patch(new byte[256]) != null)
            throw new AssertionError("junk input must return null");
        byte[] truncated = java.util.Arrays.copyOf(input, 4096);
        if (SukisuLateLoadPatch.patch(truncated) != null)
            throw new AssertionError("truncated input must return null");

        System.out.println("SukisuLateLoadPatchTest: OK (output sha=bf418858…, "
                + "junk/truncated refused)");
    }
}
