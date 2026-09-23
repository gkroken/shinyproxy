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
package eu.openanalytics.shinyproxy.publisher.bundle;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Builds tar archives for tests, by hand.
 *
 * <p>Shared rather than copied into each test: this is the same header layout
 * {@code dev/fixtures/bundles/generate.py} writes, and two implementations of it would
 * disagree eventually — which is the lesson the corpus's own miscounted PAX record taught
 * (aa461cf) and the one two copies of a length calculation taught inside a single test file
 * (3b37820-F1).
 */
final class TarArchives {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    private TarArchives() {
    }

    static TarArchives archive() {
        return new TarArchives();
    }

    TarArchives file(String name, byte[] content) {
        return raw(header(name, content.length, '0', "0000644"), content);
    }

    TarArchives directory(String name) {
        return raw(header(name.endsWith("/") ? name : name + "/", 0, '5', "0000755"),
                   new byte[0]);
    }

    /** A GNU long-name header, whose content is the name of the member after it. */
    TarArchives longName(String name) {
        byte[] value = (name + "\0").getBytes(StandardCharsets.UTF_8);
        return raw(header("././@LongLink", value.length, 'L', "0000644"), value);
    }

    /** A PAX extended header carrying one record. */
    TarArchives pax(String keyword, String value) {
        return paxRaw(paxRecord(keyword.getBytes(StandardCharsets.UTF_8),
                                value.getBytes(StandardCharsets.UTF_8)));
    }

    TarArchives paxRaw(byte[] records) {
        return raw(header("PaxHeader", records.length, 'x', "0000644"), records);
    }

    /** A header whose DECLARED size is a lie, with no content behind it. */
    TarArchives headerOnly(String name, long declaredSize, char typeFlag) {
        return raw(header(name, declaredSize, typeFlag, "0000644"), new byte[0]);
    }

    TarArchives raw(byte[] block, byte[] content) {
        out.writeBytes(block);
        out.writeBytes(content);
        int padding = (TarHeader.BLOCK - (content.length % TarHeader.BLOCK)) % TarHeader.BLOCK;
        out.writeBytes(new byte[padding]);
        return this;
    }

    /** The archive, ended properly. */
    byte[] end() {
        byte[] body = out.toByteArray();
        byte[] whole = new byte[body.length + 2 * TarHeader.BLOCK];
        System.arraycopy(body, 0, whole, 0, body.length);
        return whole;
    }

    /** The archive with no end-of-archive marker, for the truncation cases. */
    byte[] unterminated() {
        return out.toByteArray();
    }

    static byte[] paxRecord(byte[] keyword, byte[] value) {
        int body = 1 + keyword.length + 1 + value.length + 1;
        int digits = 1;
        while (Integer.toString(body + digits).length() != digits) {
            digits++;
        }
        byte[] prefix = Integer.toString(body + digits).getBytes(StandardCharsets.UTF_8);
        byte[] record = new byte[prefix.length + body];
        int at = 0;
        System.arraycopy(prefix, 0, record, at, prefix.length);
        at += prefix.length;
        record[at++] = ' ';
        System.arraycopy(keyword, 0, record, at, keyword.length);
        at += keyword.length;
        record[at++] = '=';
        System.arraycopy(value, 0, record, at, value.length);
        at += value.length;
        record[at] = '\n';
        return record;
    }

    /** One ustar header, the same layout raw_header() writes in the generator. */
    static byte[] header(String name, long size, char typeFlag, String mode) {
        byte[] block = new byte[TarHeader.BLOCK];
        write(block, 0, 100, name);
        write(block, 100, 8, mode + "\0");
        write(block, 108, 8, "0000000\0");
        write(block, 116, 8, "0000000\0");
        write(block, 124, 12, String.format("%011o", size) + "\0");
        write(block, 136, 12, "00000000000\0");
        block[156] = (byte) typeFlag;
        write(block, 257, 6, "ustar\0");
        write(block, 263, 2, "00");
        long sum = 0;
        for (int i = 0; i < TarHeader.BLOCK; i++) {
            sum += (i >= 148 && i < 156) ? ' ' : (block[i] & 0xFF);
        }
        write(block, 148, 8, String.format("%06o\0 ", sum));
        return block;
    }

    private static void write(byte[] block, int offset, int length, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < length; i++) {
            block[offset + i] = i < bytes.length ? bytes[i] : 0;
        }
    }
}
