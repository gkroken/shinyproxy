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

import eu.openanalytics.shinyproxy.publisher.storage.ObjectKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Two containment rules live in this repository, and this is what notices if they part.
 *
 * <p>{@link ObjectKeys#validatedRenditionPath} guards a rendition output file on its way
 * into an object key; {@link MemberPath} guards a tar member name on its way out of an
 * archive. They are separate implementations on purpose — one takes bytes with tar's
 * conventions and operator-configured bounds, the other takes a decoded string bounded by
 * what a key leaves room for — and finding 34182de-F1 was that ObjectKeys still claimed
 * the extractor shared its rule.
 *
 * <p>Saying "they are separate" in a comment is not enough on its own. Both refuse the same
 * containment attacks today, and without this nothing would fail on the day one of them
 * stopped. Each case below is given in each side's own spelling, because the same defect
 * reaches them in different forms: a tar member carries the payload prefix, a rendition
 * path does not.
 *
 * <p>The accepted list is not decoration. A rule that refused everything would satisfy
 * every refusal below, and the two would then "agree" while neither worked.
 */
public class ContainmentRulesAgreeTest {

    /** A defect, spelled for the key builder and for the extractor. */
    private record Case(String what, String renditionPath, String memberName) { }

    private static final List<Case> REFUSED_BY_BOTH = List.of(
            new Case("a '..' segment", "a/../b.txt", "app/a/../b.txt"),
            new Case("a '.' segment", "a/./b.txt", "app/a/./b.txt"),
            new Case("an empty segment", "a//b.txt", "app/a//b.txt"),
            new Case("an absolute path", "/etc/passwd", "/etc/passwd"),
            new Case("a backslash", "a\\b.txt", "app/a\\b.txt"),
            new Case("a control character", "a\u0001b.txt", "app/a\u0001b.txt"),
            new Case("a decomposed name", "café.txt", "app/café.txt"),
            // As a REGULAR member. A tar directory header may carry one, which is the
            // domain difference asserted separately below; a rendition path never may.
            new Case("a trailing slash on a file", "a/b/", "app/a/b/"),
            new Case("an empty path", "", ""));

    private static final List<Case> ACCEPTED_BY_BOTH = List.of(
            new Case("a plain file", "app.R", "app/app.R"),
            new Case("a nested file", "www/style.css", "app/www/style.css"),
            new Case("spaces", "a file with spaces.txt", "app/a file with spaces.txt"),
            new Case("non-ASCII in NFC", "café.txt", "app/café.txt"),
            new Case("a composed script", "日本語/ページ.html", "app/日本語/ページ.html"),
            // Literal percent sequences: text on both sides, decoded by neither.
            new Case("percent text", "%2e%2e.txt", "app/%2e%2e.txt"));

    @Test
    public void bothRefuseEveryContainmentAttack() {
        for (Case c : REFUSED_BY_BOTH) {
            assertThrows(IllegalArgumentException.class,
                    () -> ObjectKeys.validatedRenditionPath(c.renditionPath()),
                    "ObjectKeys accepted " + c.what() + ": '" + c.renditionPath() + "'");
            assertThrows(BundleRejection.class,
                    () -> parseMember(c.memberName()),
                    "MemberPath accepted " + c.what() + ": '" + c.memberName() + "'");
        }
    }

    @Test
    public void bothAcceptAnOrdinaryPath() {
        for (Case c : ACCEPTED_BY_BOTH) {
            try {
                ObjectKeys.validatedRenditionPath(c.renditionPath());
            } catch (RuntimeException ex) {
                fail("ObjectKeys refused " + c.what() + " ('" + c.renditionPath() + "'): "
                        + ex.getMessage());
            }
            try {
                assertEquals(c.renditionPath(), parseMember(c.memberName()).payloadPath(),
                        "the two disagree about what the path IS, not only about whether it"
                                + " is allowed");
            } catch (BundleRejection ex) {
                fail("MemberPath refused " + c.what() + " ('" + c.memberName() + "'): "
                        + ex.getMessage());
            }
        }
    }

    @Test
    public void theOneDifferenceIsDeliberateAndIsWrittenDown() {
        // The extractor has bounds an operator sets; the key builder has a byte budget and
        // no depth rule at all. This is the only place the two part today, and it is
        // asserted so that adding a depth rule to ObjectKeys — or dropping the extractor's —
        // fails here and makes someone update the comment in ObjectKeys rather than leaving
        // two rules quietly diverging again.
        String deep = "d/".repeat((int) ExtractionLimits.defaults().maxDepth() + 1) + "x.txt";

        ObjectKeys.validatedRenditionPath(deep);   // no depth bound: accepted by design

        BundleRejection ex = assertThrows(BundleRejection.class, () -> parseMember("app/" + deep));
        assertEquals(BundleRule.PATH_TOO_DEEP, ex.rule());
        assertTrue(ex.getMessage().contains("configured"), ex.getMessage());
    }

    /**
     * Always as a regular member.
     *
     * <p>The first version of this helper inferred the directory flag from a trailing
     * slash, so the trailing-slash case parsed as a legitimate directory header and the
     * test reported a divergence that was really my own helper reading the input as
     * something else. A shared rule has to be given to both sides as the same thing.
     */
    @Test
    public void aDirectoryHeaderIsTarsAloneAndNotTheKeyBuilders() {
        // The other deliberate difference. tar spells "this is a directory" with a trailing
        // slash, so MemberPath accepts one on a directory header and strips it; a rendition
        // path has no directories to declare and refuses the same spelling outright.
        MemberPath directory = MemberPath.parse("app/www/".getBytes(StandardCharsets.UTF_8),
                true, ExtractionLimits.defaults());
        assertEquals("www", directory.payloadPath());
        assertTrue(directory.isDirectory());

        assertThrows(IllegalArgumentException.class,
                () -> ObjectKeys.validatedRenditionPath("www/"),
                "a rendition path has no directory headers, so a trailing slash is a defect");
    }

    private static MemberPath parseMember(String name) {
        return MemberPath.parse(name.getBytes(StandardCharsets.UTF_8), false,
                ExtractionLimits.defaults());
    }
}
