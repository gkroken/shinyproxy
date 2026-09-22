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

/**
 * A bundle was refused, and this says which rule refused it.
 *
 * <p>An exception rather than a returned result on purpose. A rejection is an expected
 * outcome, not an exceptional one, but a returned {@code Optional} can be dropped by a
 * caller that forgets to look at it, and a dropped rejection here is an accepted attack.
 * Thrown, it can only be discarded deliberately.
 *
 * <p>The message is safe to log and to show a publisher: {@link #render(byte[])} escapes
 * the member name, because a name carrying control characters or invalid UTF-8 is exactly
 * the kind this class is usually reporting.
 */
public class BundleRejection extends RuntimeException {

    private final BundleRule rule;

    public BundleRejection(BundleRule rule, String detail) {
        super(rule.ruleName() + ": " + detail);
        this.rule = rule;
    }

    public BundleRule rule() {
        return rule;
    }

    /**
     * A member name in a form that is safe to put in a log line, an HTTP response or a
     * terminal.
     *
     * <p>Printable ASCII passes through; everything else becomes {@code \xNN} per byte.
     * Deliberately not a UTF-8 decode with replacement characters: the name may not be
     * valid UTF-8 at all, and a replacement character would render two different hostile
     * names identically.
     */
    public static String render(byte[] name) {
        StringBuilder out = new StringBuilder(name.length + 8);
        for (byte b : name) {
            int c = b & 0xFF;
            if (c == '\\') {
                out.append("\\\\");
            } else if (c >= 0x20 && c < 0x7F) {
                out.append((char) c);
            } else {
                out.append(String.format("\\x%02x", c));
            }
        }
        return out.toString();
    }

    /**
     * The same rendering, kept inside a budget of characters.
     *
     * <p>A budget in CHARACTERS rather than bytes because that is what makes a message long:
     * {@link #render} turns one byte outside printable ASCII into four, so a bound on bytes
     * bounds the output only for input that was never the problem. When the budget clips,
     * an ellipsis marks it, so the reader is told the evidence was cut rather than left to
     * reconcile it with a count (findings 525c504-F1 and -F2).
     *
     * @param keepTail true to render the END of the input, for cases where the bytes next
     *                 to the truncation point are the informative ones
     */
    public static String renderBounded(byte[] name, int budget, boolean keepTail) {
        String whole = render(name);
        if (whole.length() <= budget) {
            return whole;
        }
        // Cut on a rendered-character boundary by rebuilding, so an escape is never halved.
        StringBuilder out = new StringBuilder();
        if (keepTail) {
            for (int i = name.length - 1; i >= 0; i--) {
                String piece = render(new byte[] {name[i]});
                if (out.length() + piece.length() > budget) {
                    break;
                }
                out.insert(0, piece);
            }
            return "\u2026" + out;
        }
        for (byte b : name) {
            String piece = render(new byte[] {b});
            if (out.length() + piece.length() > budget) {
                break;
            }
            out.append(piece);
        }
        return out + "\u2026";
    }
}
