package com.aoki.magicroot;

import java.io.File;
import java.nio.file.Files;

public final class LiveLogStoreTest {
    public static void main(String[] args) throws Exception {
        File dir = Files.createTempDirectory("magicroot-live-log-test").toFile();
        File log = new File(dir, "nested/live.log");
        LiveLogStore store = new LiveLogStore(log);
        assertEquals("", store.readTail(10), "missing log must be empty");

        store.reset("BEGIN");
        store.append("first");
        store.append("第二行");
        assertEquals("BEGIN\nfirst\n第二行", store.readTail(10), "sync write/read");

        LiveLogStore reopened = new LiveLogStore(log);
        assertEquals("first\n第二行", reopened.readTail(2), "tail after reopen");
        reopened.append("third");
        assertEquals("第二行\nthird", reopened.readTail(2), "append after reopen");

        reopened.reset("NEW");
        assertEquals("NEW", reopened.readTail(10), "reset must truncate old run");
        reopened.append("");
        assertEquals("NEW\n", readRaw(log), "empty line remains a line");

        boolean rejected = false;
        try {
            reopened.readTail(0);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }
        if (!rejected)
            throw new AssertionError("readTail(0) must fail");
        System.out.println("LiveLogStoreTest all passed");
    }

    private static String readRaw(File file) throws Exception {
        return new String(Files.readAllBytes(file.toPath()), java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void assertEquals(String expected, String actual, String label) {
        if (!expected.equals(actual))
            throw new AssertionError(label + ": expected=" + expected + " actual=" + actual);
    }
}
