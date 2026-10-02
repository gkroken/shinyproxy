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
package eu.openanalytics.shinyproxy.publisher.recipe;

import eu.openanalytics.shinyproxy.publisher.bundle.BundleRejection;
import eu.openanalytics.shinyproxy.publisher.recipe.LockRejection.Reason;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Python recipe's lockfile policy ({@code pip-hashed}): an uploaded
 * {@code requirements.lock} must be a complete transitive lock of exact versions with
 * approved SHA-256 hashes, and nothing else (WORKPLAN-BUNDLES.md: "Reject editable/VCS/URL
 * requirements, recursive includes, index overrides, unhashed dependencies and source
 * distributions initially; restore hash-verified wheels only").
 *
 * <p>A requirements file is a little language that pip interprets, and most of it is
 * dangerous here: {@code -r}/{@code -c} include other files, {@code --index-url},
 * {@code --extra-index-url}, {@code -f} and {@code --trusted-host} move resolution elsewhere,
 * {@code -e} and direct references ({@code name @ url}, paths, VCS URLs) bypass the index,
 * and per-requirement options change how a package is built. So this accepts exactly one
 * line form,
 * <pre>name[extras]==version --hash=sha256:&lt;64 lowercase hex&gt; ...</pre>
 * with pip's comment and line-continuation rules, and refuses everything else by name. The
 * build installs from {@link PipLock#render()}, never from the upload, with the server's
 * own {@code --index-url --require-hashes --only-binary=:all: --no-deps}; source
 * distributions are refused by {@code --only-binary} at restore.
 *
 * <p>Extras are accepted and dropped: under {@code --no-deps} an extra installs nothing,
 * and the packages it would have pulled in must be locked lines of their own. Environment
 * markers are refused in this version ({@link Reason#MARKER_UNSUPPORTED}); evaluating them
 * would mean modelling PEP 508's marker grammar, and a lock for one exact Python on one
 * architecture does not need them.
 */
public final class PipLockPolicy {

    /** The framework the Python Shiny recipe launches; the lock must contain it. */
    public static final String FRAMEWORK = "shiny";

    static final int MAX_BYTES = 4 * 1024 * 1024;
    static final int MAX_REQUIREMENTS = 4000;
    static final int MAX_HASHES = 256;

    /** PEP 508 project name, optional extras, '==', a version without wildcards. */
    private static final Pattern PINNED = Pattern.compile(
            "([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?:\\[([A-Za-z0-9._,-]*)\\])?"
            + "==([A-Za-z0-9.!+_-]+)");
    /** A project name followed by anything at all: told apart for a better refusal. */
    private static final Pattern NAMED = Pattern.compile(
            "[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?(?:\\[[^\\]]*\\])?\\s*(?:[<>=!~].*)?");
    private static final Pattern HASH = Pattern.compile("--hash=sha256:([0-9a-f]{64})");
    /** pip's comment rule: '#' at the start of a line or after whitespace, to end of line. */
    private static final Pattern COMMENT = Pattern.compile("(^|\\s+)#.*$");
    private static final Pattern RUNS = Pattern.compile("[-_.]+");

    private PipLockPolicy() {
    }

    /** One locked package: its normalised name, exact version and approved hashes. */
    public record Pinned(String name, String version, SortedSet<String> sha256) {

        public Pinned {
            sha256 = Collections.unmodifiableSortedSet(new TreeSet<>(sha256));
        }
    }

    /** A lock that passed, keyed by normalised name. */
    public record PipLock(SortedMap<String, Pinned> requirements) {

        public PipLock {
            requirements = Collections.unmodifiableSortedMap(new TreeMap<>(requirements));
        }

        /** The canonical requirements file the build installs from. */
        public byte[] render() {
            StringBuilder out = new StringBuilder();
            for (Pinned p : requirements.values()) {
                out.append(p.name()).append("==").append(p.version());
                for (String h : p.sha256()) {
                    out.append(" \\\n    --hash=sha256:").append(h);
                }
                out.append('\n');
            }
            return out.toString().getBytes(StandardCharsets.US_ASCII);
        }
    }

    /**
     * The lock, read under the one accepted line form.
     *
     * @throws LockRejection naming the first rule it breaks, with its line number
     */
    public static PipLock check(byte[] lock) {
        if (lock.length > MAX_BYTES) {
            throw new LockRejection(Reason.TOO_LARGE,
                    "requirements.lock is " + lock.length + " bytes; the limit is " + MAX_BYTES);
        }
        SortedMap<String, Pinned> pinned = new TreeMap<>();
        for (Logical line : logicalLines(decode(lock))) {
            Pinned p = checkLine(line);
            if (pinned.put(p.name(), p) != null) {
                throw new LockRejection(Reason.DUPLICATE, line.where() + ": "
                        + BundleRejection.quote(p.name()) + " is locked twice");
            }
            if (pinned.size() > MAX_REQUIREMENTS) {
                throw new LockRejection(Reason.TOO_LARGE, "requirements.lock has more than "
                        + MAX_REQUIREMENTS + " requirements");
            }
        }
        if (!pinned.containsKey(FRAMEWORK)) {
            throw new LockRejection(Reason.FRAMEWORK_MISSING,
                    "requirements.lock does not contain " + FRAMEWORK);
        }
        return new PipLock(pinned);
    }

    /** PEP 503 normalisation: lower case, every run of '-', '_' and '.' one '-'. */
    static String normalise(String name) {
        return RUNS.matcher(name).replaceAll("-").toLowerCase(Locale.ROOT);
    }

    private record Logical(int number, String text) {
        String where() {
            return "requirements.lock line " + number;
        }
    }

    private static Pinned checkLine(Logical line) {
        String text = line.text();
        String where = line.where();
        if (text.startsWith("-")) {
            throw new LockRejection(Reason.OPTION_REFUSED, where + ": option "
                    + BundleRejection.quote(text.split("\\s+|=", 2)[0])
                    + " is not accepted; the server sets the index and pip's options");
        }
        if (text.contains(";")) {
            throw new LockRejection(Reason.MARKER_UNSUPPORTED, where
                    + ": environment markers are not supported");
        }
        String[] tokens = text.split("\\s+");
        // A ':' outside the hashes is a scheme (file:, git+https:, https:); '@' a PEP 508
        // direct reference; a leading '.' or '/' a path.
        if (text.contains("@") || tokens[0].contains(":") || text.startsWith(".")
                || text.startsWith("/") || text.contains("\\")) {
            throw new LockRejection(Reason.NOT_FROM_REPOSITORY, where
                    + ": a direct reference (URL, VCS or path) is not accepted");
        }
        Matcher m = PINNED.matcher(tokens[0]);
        if (!m.matches()) {
            String requirement = text.replaceAll("\\s+--.*$", "");
            if (NAMED.matcher(requirement).matches()) {
                throw new LockRejection(Reason.NOT_PINNED, where + ": "
                        + BundleRejection.quote(requirement)
                        + " is not one exact version (name==version)");
            }
            throw new LockRejection(Reason.BAD_NAME, where + ": "
                    + BundleRejection.quote(tokens[0]) + " is not a requirement");
        }
        String version = m.group(3);
        SortedSet<String> hashes = new TreeSet<>();
        for (int i = 1; i < tokens.length; i++) {
            Matcher h = HASH.matcher(tokens[i]);
            if (h.matches()) {
                hashes.add(h.group(1));
            } else if (tokens[i].startsWith("--hash=")) {
                throw new LockRejection(Reason.UNHASHED, where + ": "
                        + BundleRejection.quote(tokens[i])
                        + " is not a sha256 hash in lowercase hex");
            } else {
                throw new LockRejection(Reason.OPTION_REFUSED, where + ": "
                        + BundleRejection.quote(tokens[i]) + " is not accepted after a requirement");
            }
        }
        if (hashes.isEmpty()) {
            throw new LockRejection(Reason.UNHASHED, where + ": "
                    + BundleRejection.quote(tokens[0]) + " has no --hash=sha256");
        }
        if (hashes.size() > MAX_HASHES) {
            throw new LockRejection(Reason.TOO_LARGE, where + ": more than " + MAX_HASHES
                    + " hashes");
        }
        return new Pinned(normalise(m.group(1)), version, hashes);
    }

    /**
     * pip's reading: continuation lines joined ('\' at the very end), comments removed, blank
     * lines skipped. Each logical line keeps the number of its first physical line. As in
     * pip's join_lines, a comment line is never a continuation, even when it ends in '\':
     * read otherwise, it would swallow the requirement on the next line.
     */
    private static List<Logical> logicalLines(String text) {
        List<Logical> out = new ArrayList<>();
        String[] physical = text.split("\n", -1);
        StringBuilder current = null;
        int start = 0;
        for (int i = 0; i < physical.length; i++) {
            String line = physical[i];
            if (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1);
            }
            if (current == null) {
                current = new StringBuilder();
                start = i + 1;
            }
            if (line.endsWith("\\") && !line.strip().startsWith("#")) {
                current.append(line, 0, line.length() - 1).append(' ');
                continue;
            }
            current.append(line);
            String logical = COMMENT.matcher(current).replaceFirst("").strip();
            if (!logical.isEmpty()) {
                out.add(new Logical(start, logical));
            }
            current = null;
        }
        if (current != null) {
            throw new LockRejection(Reason.SYNTAX, "requirements.lock ends in a line continuation");
        }
        return out;
    }

    /**
     * Strict UTF-8, then printable ASCII plus tab and LF, and CR only before LF. A bare CR is
     * a line break to pip (it splits with str.splitlines) and not to this reader, so it is
     * refused rather than read differently.
     */
    private static String decode(byte[] lock) {
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(lock)).toString();
        } catch (CharacterCodingException e) {
            throw new LockRejection(Reason.SYNTAX, "requirements.lock is not valid UTF-8");
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean crlf = c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n';
            if (!(c >= 0x20 && c < 0x7F) && c != '\t' && c != '\n' && !crlf) {
                throw new LockRejection(Reason.SYNTAX, String.format(
                        "requirements.lock contains U+%04X; only printable ASCII is accepted",
                        (int) c));
            }
        }
        return text;
    }
}
