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

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Every member seen so far, and what it collides with.
 *
 * <p>The path rules in {@link MemberPath} judge one name at a time. These are the rules that
 * only exist between members, and an archive can satisfy every one of the former and none of
 * the latter: two entries at the same path, {@code App.R} beside {@code app.R}, a file where
 * another member's parent directory has to be.
 *
 * <p><b>Nothing here is resolved by ordering.</b> Last-entry-wins is the default behaviour of
 * most extractors and it means what was validated is not what ends up on disk — the first
 * entry is checked, the second overwrites it, and a reader of the manifest and a reader of
 * the filesystem disagree. A repeated path is refused whichever copy came first, and a file
 * that appears before the directory it contradicts is refused as surely as one that appears
 * after.
 *
 * <p><b>Case is preserved and collisions are refused.</b> {@code App.R} and {@code app.R} are
 * two files on the filesystems this runs on and one file on the one a publisher develops on.
 * Neither name is altered — lower-casing the second would publish a path its author never
 * wrote — so the bundle is refused and the publisher decides which name they meant.
 *
 * <p><b>Unicode aliases never reach here</b>, because {@link MemberPath} refuses anything not
 * in NFC at parse. The corpus's {@code dup-nfc-alias} — the same name in NFC and NFD, byte
 * different and identical after normalisation — is therefore a PATH_NOT_NFC rejection rather
 * than a collision, which is the earlier and more specific answer. This class folds case and
 * nothing else; if the NFC rule were ever relaxed, this would silently stop covering it, so
 * the two tests say so in each other's terms.
 *
 * <p>Keyed on the whole member path rather than the payload-relative one: {@code manifest.json}
 * and the {@code app} directory header both have an empty payload path, and they are not the
 * same member.
 */
public final class MemberIndex {

    /** What a path is known to be. */
    private enum Kind {
        /** A regular file. */
        FILE,
        /** A directory with a header of its own. */
        DIRECTORY,
        /** A directory nobody declared, implied by a member beneath it. */
        IMPLIED
    }

    /**
     * @param because for an IMPLIED directory, the member that made it one — so that either
     *                order of a file/parent conflict names the member inside, rather than
     *                one order explaining itself and the other saying only that something
     *                was seen
     */
    private record Entry(String path, Kind kind, String because) { }

    private final Map<String, Entry> byFoldedPath = new HashMap<>();

    /**
     * Records one member, or refuses it against what is already here.
     *
     * @throws BundleRejection naming the rule and both paths involved
     */
    public void add(MemberPath member) {
        String path = member.memberPath();
        Kind kind = member.isDirectory() ? Kind.DIRECTORY : Kind.FILE;
        Entry existing = byFoldedPath.get(fold(path));

        if (existing != null) {
            requireSameSpelling(existing, path);
            switch (existing.kind()) {
                case FILE -> {
                    if (kind == Kind.FILE) {
                        throw duplicate(path, "a regular member");
                    }
                    throw kindConflict(path, "a file", "a directory");
                }
                case DIRECTORY -> {
                    if (kind == Kind.DIRECTORY) {
                        throw duplicate(path, "a directory header");
                    }
                    throw kindConflict(path, "a directory", "a file");
                }
                case IMPLIED -> {
                    if (kind == Kind.FILE) {
                        // Something beneath it is already a member, so this path is a
                        // directory whether or not anyone said so.
                        throw mustBeADirectory(path, existing.because());
                    }
                    // An explicit header for a directory that was already implied: ordinary,
                    // and the corpus's pos-explicit-dir-headers does exactly this.
                }
            }
        }
        byFoldedPath.put(fold(path), new Entry(path, kind, null));
        claimParents(member);
    }

    /**
     * Marks every directory above this member as a directory.
     *
     * <p>This is what makes the file-before-parent case ordering-independent: the parents are
     * claimed when the deep member arrives, so a later file at one of those paths meets an
     * IMPLIED entry, and an earlier one is already a FILE when the deep member claims it.
     */
    private void claimParents(MemberPath member) {
        List<String> segments = member.payloadSegments();
        if (member.role() != MemberPath.Role.PAYLOAD) {
            return;
        }
        StringBuilder path = new StringBuilder(MemberPath.PAYLOAD_ROOT);
        // The payload root itself, then each directory below it, excluding the member.
        claimAsDirectory(path.toString(), member.memberPath());
        for (int i = 0; i < segments.size() - 1; i++) {
            path.append('/').append(segments.get(i));
            claimAsDirectory(path.toString(), member.memberPath());
        }
    }

    private void claimAsDirectory(String path, String because) {
        Entry existing = byFoldedPath.get(fold(path));
        if (existing == null) {
            byFoldedPath.put(fold(path), new Entry(path, Kind.IMPLIED, because));
            return;
        }
        requireSameSpelling(existing, path);
        if (existing.kind() == Kind.FILE) {
            throw mustBeADirectory(path, because);
        }
    }

    private void requireSameSpelling(Entry existing, String path) {
        if (!existing.path().equals(path)) {
            throw new BundleRejection(BundleRule.MEMBER_CASE_COLLISION,
                    "'" + path + "' and '" + existing.path() + "' differ only by case. They"
                            + " are two members on this filesystem and one on a"
                            + " case-insensitive one, so which file the bundle contains"
                            + " depends on where it is unpacked");
        }
    }

    private static BundleRejection duplicate(String path, String what) {
        return new BundleRejection(BundleRule.DUPLICATE_MEMBER,
                "'" + path + "' appears twice as " + what + ". Whichever copy an extractor"
                        + " keeps, it is not the one that was validated");
    }

    /** The file/parent conflict, worded the same whichever of the two arrived first. */
    private static BundleRejection mustBeADirectory(String path, String because) {
        return new BundleRejection(BundleRule.MEMBER_KIND_CONFLICT,
                "'" + path + "' is a regular member and also has to be a directory, because '"
                        + because + "' is inside it");
    }

    private static BundleRejection kindConflict(String path, String was, String now) {
        return new BundleRejection(BundleRule.MEMBER_KIND_CONFLICT,
                "'" + path + "' is " + was + " and also " + now + "; one path cannot be both");
    }

    /**
     * The key two members collide on.
     *
     * <p>Case folding only. NFC is already required by {@link MemberPath}, so a decomposed
     * alias never reaches this map, and folding anything else here would start altering
     * names rather than comparing them.
     *
     * <p>Package-private because the manifest's inventory (S3) must collide on exactly the
     * same key as the archive's members: two definitions of "the same path" would let a
     * name through one that the other refuses.
     */
    static String fold(String path) {
        return path.toLowerCase(Locale.ROOT);
    }

    /** How many distinct members have been recorded, implied directories excluded. */
    public int size() {
        return (int) byFoldedPath.values().stream()
                .filter(entry -> entry.kind() != Kind.IMPLIED)
                .count();
    }
}
