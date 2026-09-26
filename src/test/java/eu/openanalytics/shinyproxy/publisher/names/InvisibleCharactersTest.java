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
package eu.openanalytics.shinyproxy.publisher.names;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The invisible-character rule, case by case, each case written by hand from the Unicode
 * charts and RFC 5892 rather than derived from the generated tables it checks.
 */
public class InvisibleCharactersTest {

    @Test
    public void whatRendersAsNothingIsRefused() {
        // 5c5715b-F1's list: accepted by the Cf/Zl/Zp rule, invisible all the same. Plus
        // the rest of Default_Ignorable_Code_Point's kinds, and F3's original two.
        int[] refused = {
                0x034F,             // combining grapheme joiner (Mn)
                0xFE00, 0xFE0F,     // variation selectors 1 and 16 (Mn)
                0xE0100, 0xE01EF,   // variation selectors supplement (Mn)
                0x180B, 0x180F,     // Mongolian free variation selectors (Mn)
                0x17B4, 0x17B5,     // Khmer inherent vowels (Mn)
                0x115F, 0x1160, 0x3164, 0xFFA0,   // Hangul fillers (Lo)
                0x1BCA0, 0x1BCA3,   // shorthand format controls (Cf)
                0xFFF0, 0xE0000, 0xE0FFF,         // unassigned, but default ignorable
                0x2065,             // unassigned inside the bidi block, default ignorable
                0x200B, 0xFEFF, 0x202E, 0x2066, 0x061C, 0x00AD,
                0xFFF9, 0x110BD, 0x2028, 0x2029};  // Cf/Zl/Zp that are not ignorable
        for (int cp : refused) {
            String name = "a" + new String(Character.toChars(cp)) + "b";
            assertEquals(cp, InvisibleCharacters.firstRefused(name),
                    String.format("U+%04X was not refused", cp));
        }
    }

    @Test
    public void theJoinersAreRefusedOutsideTheWordsThatNeedThem() {
        // ZWNJ/ZWJ between Latin letters, at either end, in an emoji sequence, after a
        // letter that does not join forward, before one that does not join back.
        String[] refused = {
                "a\u200cb", "a\u200db", "\u200cab", "ab\u200c", "\u200d",
                "\ud83d\udc68\u200d\ud83d\udc69\u200d\ud83d\udc67",   // family emoji
                "\u2764\ufe0f",                                        // heart + VS16
                "\u0627\u200c\u0628",   // alef (joins back only) ZWNJ beh
                "\u0628\u200c\u0621",   // beh ZWNJ hamza (does not join)
                "\u0628\u200d\u0628",   // ZWJ between Arabic letters: no virama before it
                "\u0915\u200d\u0937"};  // Devanagari ka ZWJ ssa: no virama before it
        for (String name : refused) {
            int got = InvisibleCharacters.firstRefused(name);
            assertEquals(true, got == 0x200C || got == 0x200D || got == 0xFE0F,
                    "a joiner outside its context was not refused: " + escaped(name));
        }
    }

    @Test
    public void theJoinersAreAllowedInsideTheWordsThatNeedThem() {
        String[] allowed = {
                // Persian "mi-khaham": meem yeh ZWNJ khah waw alef heh meem. Yeh joins
                // forward, khah joins back: RFC 5892 A.1's second clause.
                "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
                // The same with a transparent mark (fatha) on each side of the ZWNJ.
                "\u0628\u064e\u200c\u064e\u0628",
                // Devanagari ka virama ZWJ ssa, and ka virama ZWNJ ssa: A.1/A.2's first clause.
                "\u0915\u094d\u200d\u0937", "\u0915\u094d\u200c\u0937",
                // Malayalam chillu written with virama + ZWJ.
                "\u0d23\u0d4d\u200d",
                // Visible, and in no invisible class: NBSP, ideographic space, braille blank
                // (the homoglyph class this rule does not claim to cover), an emoji.
                "a\u00a0b", "a\u3000b", "a\u2800b", "\ud83d\ude00"};
        for (String name : allowed) {
            assertEquals(-1, InvisibleCharacters.firstRefused(name),
                    "refused: " + escaped(name));
        }
    }

    @Test
    public void theRangeSearchFindsBothEndsAndNothingBetween() {
        int[] ranges = {0x10, 0x12, 0x20, 0x20};
        for (int cp : new int[] {0x10, 0x11, 0x12, 0x20}) {
            assertEquals(true, InvisibleCharacters.in(ranges, cp), Integer.toHexString(cp));
        }
        for (int cp : new int[] {0x0F, 0x13, 0x1F, 0x21}) {
            assertEquals(false, InvisibleCharacters.in(ranges, cp), Integer.toHexString(cp));
        }
    }

    private static String escaped(String text) {
        StringBuilder out = new StringBuilder();
        text.codePoints().forEach(cp -> out.append(String.format("U+%04X ", cp)));
        return out.toString().trim();
    }
}
