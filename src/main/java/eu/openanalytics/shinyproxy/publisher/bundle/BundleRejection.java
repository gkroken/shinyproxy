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

import java.nio.charset.StandardCharsets;

/**
 * A bundle was refused, and this says which rule refused it.
 *
 * <p>An exception rather than a returned result on purpose. A rejection is an expected
 * outcome, not an exceptional one, but a returned {@code Optional} can be dropped by a
 * caller that forgets to look at it, and a dropped rejection here is an accepted attack.
 * Thrown, it can only be discarded deliberately.
 *
 * <p><b>The message is printable ASCII, whatever it was built from.</b> It is logged, sent
 * to a publisher and shown in terminals, and the names it quotes are exactly the hostile
 * ones this class usually reports. The guarantee used to rest on every call site
 * remembering {@link #render(byte[])}; about forty sites quoted a decoded name raw, so a
 * member called {@code app/ok<U+202E>txt.R} put a bidi override into the log line that
 * refused it (finding t5-e5e3071-F2). Now the constructor escapes the whole detail, so a
 * site that forgets, and text the class does not control (an exception's message from the
 * OS or the schema validator, which may quote the name again), cannot undo it.
 *
 * <p>Call sites still quote names with {@link #quote(String)} or {@link #render(byte[])},
 * and not only for tidiness: those escape a backslash as well, so a name that literally
 * contains the four characters {@code \x85} is not confused with one holding U+0085.
 */
public class BundleRejection extends RuntimeException {

    private final BundleRule rule;

    public BundleRejection(BundleRule rule, String detail) {
        super(rule.ruleName() + ": " + printable(detail));
        this.rule = rule;
    }

    /**
     * The detail with every character outside printable ASCII written as {@code \xNN}, one
     * per UTF-8 byte, the same spelling {@link #render(byte[])} uses. A backslash is left
     * alone, because the detail is already text in which rendered names have escaped
     * theirs; rendering it again would double every escape a call site made.
     */
    public static String printable(String detail) {
        StringBuilder out = new StringBuilder(detail.length() + 8);
        for (int i = 0; i < detail.length(); ) {
            int cp = detail.codePointAt(i);
            i += Character.charCount(cp);
            if (cp >= 0x20 && cp < 0x7F) {
                out.append((char) cp);
            } else {
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                    out.append(String.format("\\x%02x", b & 0xFF));
                }
            }
        }
        return out.toString();
    }

    /** A decoded name, quoted the way {@link #render(byte[])} quotes raw bytes. */
    public static String quote(String name) {
        return render(name.getBytes(StandardCharsets.UTF_8));
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
     * reconcile it with a count (findings 525c504-F1 and -F2). The mark is ASCII
     * {@code ...}, since the message it lands in is printable ASCII (t5-e5e3071-F2).
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
            return ELLIPSIS + out;
        }
        for (byte b : name) {
            String piece = render(new byte[] {b});
            if (out.length() + piece.length() > budget) {
                break;
            }
            out.append(piece);
        }
        return out + ELLIPSIS;
    }

    /** What {@link #renderBounded} puts where it clipped. */
    public static final String ELLIPSIS = "...";
}
