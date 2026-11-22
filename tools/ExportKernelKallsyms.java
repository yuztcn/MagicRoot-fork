package com.aoki.magicroot;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Maintainer CLI for the existing offline 6.12.x/6.6.x kallsyms exporter. */
public final class ExportKernelKallsyms {
    private ExportKernelKallsyms() {}

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: ExportKernelKallsyms <boot.img> <output.txt>");
            System.exit(2);
        }
        try {
            byte[] boot = Files.readAllBytes(Paths.get(args[0]));
            byte[] kernel = KernelProfileGenerator.extractKernel(boot);
            KernelProfileGenerator.KallsymsResult result = KernelProfileGenerator.generateKallsyms(kernel);
            StringBuilder text = new StringBuilder();
            for (KernelProfileGenerator.Symbol symbol : result.symbols) {
                text.append(symbol.name).append(" 0x")
                        .append(Long.toHexString(symbol.address)).append('\n');
            }
            Files.write(Paths.get(args[1]), text.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("KALLSYMS_OK kernel=" + result.kernel + " count=" + result.kallsymsCount);
        } catch (IOException e) {
            System.err.println("FAIL=" + e.getMessage());
            System.exit(1);
        }
    }
}
