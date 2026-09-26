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

/**
 * Which code points may not appear in a published name because they render as nothing.
 *
 * <p>The rule, decided by the user on 2026-09-26 and recorded in the extraction contract:
 * a name may not contain a Default_Ignorable_Code_Point (Unicode's own set for "renders as
 * nothing": zero-width characters, variation selectors, the combining grapheme joiner,
 * Hangul fillers, tag characters...) nor a character of general category Cf, Zl or Zp
 * (the bidi controls, BOM, interlinear annotation, line and paragraph separators). Two
 * names that differ only by such a character look identical wherever they are listed, and
 * the bidi controls reorder what is around them.
 *
 * <p><b>The exception is the one the internet's domain-name rules make</b> (RFC 5892,
 * Appendix A, "ContextJ"). ZERO WIDTH NON-JOINER and ZERO WIDTH JOINER are written inside
 * ordinary words in Persian and in the Indic scripts, so they are allowed exactly where
 * those rules allow them: either joiner directly after a virama, or a non-joiner between
 * two Arabic-script letters that would otherwise join (transparent marks between are
 * skipped). Anywhere else, in an emoji sequence or between Latin letters for instance, a
 * joiner is only a way to make two names look alike, and it is refused.
 *
 * <p>Deliberately outside this rule: homoglyphs. A Cyrillic "a", a different space
 * character, or U+2800 BRAILLE PATTERN BLANK are visible characters that happen to look
 * like others. That is a separate class, not addressed by T5, and the contract says so
 * rather than implying this rule covers it.
 *
 * <p>The tables are generated from Unicode {@value UnicodeTables#UNICODE_VERSION}, the
 * version the build's JDK implements, so the rule does not move when the JDK does; see
 * dev/unicode/generate_invisible_tables.py.
 */
public final class InvisibleCharacters {

    private static final int ZWNJ = 0x200C;
    private static final int ZWJ = 0x200D;

    private InvisibleCharacters() {
    }

    /** The first code point in {@code text} this rule refuses, or -1 when there is none. */
    public static int firstRefused(String text) {
        int[] points = text.codePoints().toArray();
        for (int i = 0; i < points.length; i++) {
            int cp = points[i];
            if (!in(UnicodeTables.REFUSED, cp)) {
                continue;
            }
            if ((cp == ZWNJ || cp == ZWJ) && allowedByContextJ(points, i)) {
                continue;
            }
            return cp;
        }
        return -1;
    }

    /** RFC 5892 Appendix A.1 (ZWNJ) and A.2 (ZWJ). */
    private static boolean allowedByContextJ(int[] points, int at) {
        if (at > 0 && in(UnicodeTables.VIRAMA, points[at - 1])) {
            return true;
        }
        if (points[at] == ZWJ) {
            return false;
        }
        // (Joining_Type:{L,D})(Joining_Type:T)* ZWNJ (Joining_Type:T)*(Joining_Type:{R,D})
        int before = at - 1;
        while (before >= 0 && in(UnicodeTables.TRANSPARENT, points[before])) {
            before--;
        }
        int after = at + 1;
        while (after < points.length && in(UnicodeTables.TRANSPARENT, points[after])) {
            after++;
        }
        return before >= 0 && after < points.length
                && in(UnicodeTables.JOINS_FORWARD, points[before])
                && in(UnicodeTables.JOINS_BACKWARD, points[after]);
    }

    /** Binary search over sorted, inclusive {@code first, last} pairs. */
    static boolean in(int[] ranges, int cp) {
        int low = 0;
        int high = ranges.length / 2 - 1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            if (cp < ranges[2 * mid]) {
                high = mid - 1;
            } else if (cp > ranges[2 * mid + 1]) {
                low = mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }
}
