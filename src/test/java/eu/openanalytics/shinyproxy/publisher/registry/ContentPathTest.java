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
package eu.openanalytics.shinyproxy.publisher.registry;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Locale;

/** The path rules, away from any database. */
public class ContentPathTest {

    @Test
    public void normalisationLowerCasesAndKeepsSegments() {
        Assertions.assertEquals("finance/quarterly", ContentPath.normalise("Finance/Quarterly"));
        Assertions.assertEquals("a/b/c", ContentPath.normalise("  A/B/C  "));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "a/b/c/d",            // too many segments
        "/leading",
        "trailing/",
        "a//b",               // empty segment
        "-leading-hyphen",
        "has space",
        "has_underscore",
        "UPPER CASE",
        "rapport\u00e9",       // non-ASCII
        "\u0130stanbul"        // dotted capital I: the Turkish case that breaks lower()
    })
    public void malformedPathsAreRejected(String path) {
        Assertions.assertThrows(IllegalArgumentException.class, () -> ContentPath.normalise(path),
            "'" + path + "' should not be a valid path");
    }

    @Test
    public void blankAndNullAreRejected() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> ContentPath.normalise(null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> ContentPath.normalise("   "));
    }

    /**
     * The reason ASCII is enforced rather than merely preferred.
     *
     * <p>Under a Turkish locale {@code "I".toLowerCase()} is a dotless {@code 'ı'}, and the
     * same divergence exists between database collations. If non-ASCII paths were allowed, the
     * uniqueness key would mean different things on different installations — two paths
     * distinct on one server and colliding on another. Refusing non-ASCII removes the question
     * instead of answering it per deployment.
     */
    // Declares what this test mutates. Locale.setDefault is JVM-global, and the
    // save/restore below is sufficient only while the suite runs sequentially — which
    // it does today, and which is exactly the thing someone changes to speed up 245
    // tests. The failure would then be intermittent and would land on whichever test
    // happened to read the locale, pointing nowhere near here (fa1ccdf-F1).
    @Test
    @ResourceLock(Resources.LOCALE)
    public void normalisationDoesNotDependOnTheDefaultLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(new Locale("tr", "TR"));
            Assertions.assertEquals("import", ContentPath.normalise("IMPORT"),
                "normalisation used the default locale, so the uniqueness key is not portable");
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    public void nestingIsDetectedInBothDirections() {
        Assertions.assertTrue(ContentPath.conflicts("team", "team/reports"));
        Assertions.assertTrue(ContentPath.conflicts("team/reports", "team"));
        Assertions.assertTrue(ContentPath.conflicts("a/b/c", "a"));
    }

    @Test
    public void siblingsAndPrefixesThatAreNotSegmentBoundariesDoNotConflict() {
        Assertions.assertFalse(ContentPath.conflicts("team", "team-reports"),
            "a shared textual prefix is not a shared subtree");
        Assertions.assertFalse(ContentPath.conflicts("team/a", "team/b"));
        Assertions.assertFalse(ContentPath.conflicts("team", "team"),
            "equality is ordinary uniqueness, reported separately for a better message");
    }

}
