/*
 * Skald
 *
 * Copyright (C) 2026 Gard Kroken
 *
 * Built on ShinyProxy, Copyright (C) 2016-2026 Open Analytics NV.
 *
 * ===========================================================================
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Apache License as published by
 * The Apache Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Apache License for more details.
 *
 * You should have received a copy of the Apache License
 * along with this program.  If not, see <http://www.apache.org/licenses/>
 */
package eu.openanalytics.shinyproxy.publisher.storage;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * Turns a byte stream that arrives in arbitrary frames (Docker's log frames end anywhere,
 * mid-line and mid-character) into lines. A line longer than {@code lineBytes} is cut at
 * that many bytes and its rest is discarded up to the newline, so memory stays bounded
 * whatever build code prints. Bytes are decoded as UTF-8 with replacement; a trailing CR is
 * dropped.
 */
public final class LogLines {

    /** Receives each line. */
    public interface Sink {
        void line(String text, boolean cut);
    }

    private final int lineBytes;
    private final Sink sink;
    private final ByteArrayOutputStream current = new ByteArrayOutputStream();
    private boolean cut;

    public LogLines(int lineBytes, Sink sink) {
        this.lineBytes = lineBytes;
        this.sink = sink;
    }

    public void feed(ByteBuffer frame) {
        while (frame.hasRemaining()) {
            byte b = frame.get();
            if (b == '\n') {
                emit();
            } else if (current.size() < lineBytes) {
                current.write(b);
            } else {
                cut = true;
            }
        }
    }

    /** The stream ended: a last line without a newline is still a line. */
    public void end() {
        if (current.size() > 0 || cut) {
            emit();
        }
    }

    private void emit() {
        byte[] bytes = current.toByteArray();
        int length = bytes.length;
        if (length > 0 && bytes[length - 1] == '\r') {
            length--;
        }
        sink.line(new String(bytes, 0, length, StandardCharsets.UTF_8), cut);
        current.reset();
        cut = false;
    }
}
