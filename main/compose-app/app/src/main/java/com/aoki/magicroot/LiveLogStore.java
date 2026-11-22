package com.aoki.magicroot;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Minimal synchronous, crash-resilient run-log store.
 *
 * Each append is flushed and fsynced before returning.  MainActivity calls this
 * from one background writer thread; methods are synchronized to keep tests and
 * any accidental caller safe.  No Android APIs are used, so persistence and
 * tail recovery are covered by a local JVM test.
 */
public final class LiveLogStore {
    private final File file;

    public LiveLogStore(File file) {
        this.file = file;
    }

    public synchronized void reset(String header) throws IOException {
        write(header == null ? "" : header, false);
    }

    public synchronized void append(String line) throws IOException {
        write(line == null ? "(null)" : line, true);
    }

    private void write(String text, boolean append) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs())
            throw new IOException("cannot create log directory: " + parent);
        try (FileOutputStream out = new FileOutputStream(file, append)) {
            if (!text.isEmpty()) {
                out.write(text.getBytes(StandardCharsets.UTF_8));
                if (!text.endsWith("\n"))
                    out.write('\n');
            }
            out.flush();
            out.getFD().sync();
        }
    }

    /** Return at most maxLines trailing lines, without a trailing newline. */
    public synchronized String readTail(int maxLines) throws IOException {
        if (maxLines <= 0)
            throw new IllegalArgumentException("maxLines must be positive");
        if (!file.isFile())
            return "";
        Deque<String> tail = new ArrayDeque<>(Math.min(maxLines, 256));
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new java.io.FileInputStream(file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (tail.size() == maxLines)
                    tail.removeFirst();
                tail.addLast(line);
            }
        }
        return String.join("\n", tail);
    }
}
