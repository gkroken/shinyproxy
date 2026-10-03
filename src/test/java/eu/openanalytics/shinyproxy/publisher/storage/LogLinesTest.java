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

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LogLinesTest {

    private static List<String> split(int lineBytes, byte[]... frames) {
        List<String> out = new ArrayList<>();
        LogLines lines = new LogLines(lineBytes, (text, cut) -> out.add((cut ? "CUT:" : "") + text));
        for (byte[] f : frames) {
            lines.feed(ByteBuffer.wrap(f));
        }
        lines.end();
        return out;
    }

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void framesEndAnywhere() {
        assertEquals(List.of("hello world", "second", "", "last"),
                split(100, b("hel"), b("lo wor"), b("ld\nsec"), b("ond\n\nla"), b("st")));
    }

    @Test
    void aCharacterSplitAcrossFramesIsDecodedWhole() {
        byte[] e = b("caf" + (char) 0xe9 + "\n");
        byte[] first = java.util.Arrays.copyOfRange(e, 0, 4);
        byte[] second = java.util.Arrays.copyOfRange(e, 4, e.length);
        assertEquals(List.of("caf" + (char) 0xe9), split(100, first, second));
    }

    @Test
    void aLongLineIsCutAndItsRestDropped() {
        assertEquals(List.of("CUT:abcde", "next"), split(5, b("abcdefghij"), b("klm\nnext\n")));
        assertEquals(List.of("abcde"), split(5, b("abcde\n")), "exactly the limit is not cut");
        assertEquals(List.of("CUT:abcde"), split(5, b("abcdefgh")), "cut, and the stream ended");
    }

    @Test
    void crlfAndInvalidBytes() {
        assertEquals(List.of("dos"), split(100, b("dos\r\n")));
        assertEquals(List.of("x" + (char) 0xfffd + "y"), split(100, new byte[] {'x', (byte) 0xff, 'y', '\n'}));
        assertEquals(List.of(), split(100));
    }
}
