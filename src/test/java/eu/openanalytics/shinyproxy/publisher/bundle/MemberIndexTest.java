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

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The rules that only exist between members, driven by T2's duplicate group.
 *
 * <p>Every fixture in that group is here under its own name: dup-regular, dup-manifest,
 * dup-file-then-dir, dup-dir-then-file, dup-case-alias, dup-file-before-parent,
 * dup-repeated-directory — and dup-nfc-alias, which is asserted to be refused EARLIER, by
 * the NFC rule, so that the day someone relaxes that rule this test says what stopped
 * covering it.
 *
 * <p>Both orders are tested for every ordering-sensitive case. An index that refused a
 * conflict only when the members arrived in one order would pass half of these and leave
 * the publisher's archive to decide.
 */
public class MemberIndexTest {

    private static final ExtractionLimits LIMITS = ExtractionLimits.defaults();

    private static MemberPath path(String name) {
        return MemberPath.parse(name.getBytes(StandardCharsets.UTF_8), name.endsWith("/"), LIMITS);
    }

    private static MemberIndex indexOf(String... names) {
        MemberIndex index = new MemberIndex();
        for (String name : names) {
            index.add(path(name));
        }
        return index;
    }

    private static BundleRule ruleFor(String... names) {
        return assertThrows(BundleRejection.class, () -> indexOf(names),
                "accepted: " + String.join(", ", names)).rule();
    }

    @Test
    public void anOrdinaryBundleHasNoCollisions() {
        MemberIndex index = indexOf("manifest.json", "app/", "app/app.R", "app/renv.lock",
                                    "app/www/", "app/www/style.css", "app/R/helpers.R");
        assertEquals(7, index.size());

        // pos-implicit-dirs-only: no directory headers at all, and the parents are still
        // claimed. If they were not, the conflict cases below would be untestable.
        assertEquals(3, indexOf("manifest.json", "app/deep/nested/file.txt",
                                "app/other.txt").size());
    }

    @Test
    public void aRepeatedPathIsRefusedWhicheverCopyCameFirst() {
        assertEquals(BundleRule.DUPLICATE_MEMBER, ruleFor("app/app.R", "app/app.R"));
        assertEquals(BundleRule.DUPLICATE_MEMBER, ruleFor("manifest.json", "manifest.json"));
        assertEquals(BundleRule.DUPLICATE_MEMBER, ruleFor("app/www/", "app/www/"));

        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> indexOf("app/a.txt", "app/a.txt"));
        assertTrue(ex.getMessage().contains("not the one that was validated"), ex.getMessage());
    }

    @Test
    public void onePathIsNotBothAFileAndADirectory() {
        assertEquals(BundleRule.MEMBER_KIND_CONFLICT, ruleFor("app/x", "app/x/"));
        assertEquals(BundleRule.MEMBER_KIND_CONFLICT, ruleFor("app/x/", "app/x"));
    }

    @Test
    public void aFileWhereAParentMustBeIsRefusedInEitherOrder() {
        // dup-file-before-parent. Ordering decides whether a careless extractor writes the
        // file and then fails to descend, or creates the directory and then truncates it
        // with the file, so both orders have to be refused.
        assertEquals(BundleRule.MEMBER_KIND_CONFLICT, ruleFor("app/a/b.txt", "app/a"));
        assertEquals(BundleRule.MEMBER_KIND_CONFLICT, ruleFor("app/a", "app/a/b.txt"));

        // And several levels up, where a check of the immediate parent alone would miss it.
        assertEquals(BundleRule.MEMBER_KIND_CONFLICT,
                ruleFor("app/a/b/c/d.txt", "app/a/b"));
        assertEquals(BundleRule.MEMBER_KIND_CONFLICT,
                ruleFor("app/a/b", "app/a/b/c/d.txt"));

        // Both orders name the member that forced the directory, rather than one order
        // explaining itself and the other saying only that something was seen.
        for (String[] order : new String[][] {{"app/a/b.txt", "app/a"}, {"app/a", "app/a/b.txt"}}) {
            BundleRejection ex = assertThrows(BundleRejection.class, () -> indexOf(order));
            assertTrue(ex.getMessage().contains("is inside it")
                            && ex.getMessage().contains("app/a/b.txt"),
                    "the conflicting member is not named: " + ex.getMessage());
        }
    }

    @Test
    public void namesDifferingOnlyByCaseAreTwoFilesHereAndOneElsewhere() {
        // dup-case-alias: App.R beside app.R.
        assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor("app/app.R", "app/App.R"));
        assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor("app/App.R", "app/app.R"));
        assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor("app/www/", "app/WWW/"));
        // A collision between a directory and a file that differ only by case is still a
        // case collision, reported before the kind conflict, because the name is the thing
        // the publisher has to change.
        assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor("app/x/", "app/X"));

        BundleRejection ex = assertThrows(BundleRejection.class,
                () -> indexOf("app/app.R", "app/App.R"));
        assertTrue(ex.getMessage().contains("app/App.R") && ex.getMessage().contains("app/app.R"),
                "both spellings belong in the message, or the publisher has to guess which"
                        + " two files collided: " + ex.getMessage());
    }

    @Test
    public void caseFoldingIsTheSameWhateverTheHostLocaleIs() {
        // The plain case first: two spellings of one name collide under an ordinary locale.
        assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor("app/INDEX.html", "app/index.html"));

        // And under a Turkish one, where "I".toLowerCase() is a DOTLESS i and INDEX.html
        // stops folding onto index.html. A bundle refused in Oslo and accepted in Istanbul
        // is the bug; Locale.ROOT at the fold is what prevents it.
        //
        // 5704bfd-F1: the first version of this test named the problem in its title and its
        // comment and never set a locale, so it held under toLowerCase() as well as
        // toLowerCase(Locale.ROOT) and the mutation it claimed to kill survived. Setting the
        // default is the whole test.
        Locale previous = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("tr"));
            assertNotEquals("I".toLowerCase(), "I".toLowerCase(Locale.ROOT),
                    "the Turkish default did not take effect on this JVM, so everything"
                            + " below would pass against a locale-dependent fold too");

            assertEquals(BundleRule.MEMBER_CASE_COLLISION,
                    ruleFor("app/INDEX.html", "app/index.html"));
            assertEquals(BundleRule.MEMBER_CASE_COLLISION, ruleFor("app/I.txt", "app/i.txt"));
        } finally {
            Locale.setDefault(previous);
        }
    }

    @Test
    public void aDecomposedAliasIsRefusedEarlierThanThis() {
        // Written as escapes on purpose. As literal characters these two are visually
        // identical and behave oppositely, so a reader of the file sees one string twice
        // and two contradictory assertions (5704bfd-F2).
        String decomposed = "app/cafe\u0301.txt";    // e + U+0301 COMBINING ACUTE
        String composed = "app/caf\u00e9.txt";      // U+00E9 LATIN SMALL LETTER E WITH ACUTE

        // That they are an ALIAS is the property this test is named for, so it is asserted
        // rather than described: different bytes, one name after normalisation. Without
        // this, an unrelated non-NFC string would satisfy everything below and the test
        // would have stopped covering dup-nfc-alias without failing.
        assertNotEquals(decomposed, composed);
        assertEquals(composed, Normalizer.normalize(decomposed, Normalizer.Form.NFC));

        // dup-nfc-alias never reaches the index: MemberPath refuses NFD at parse, which is
        // the more specific answer. Asserted here as well as there so that relaxing the NFC
        // rule fails a test that says what it was covering.
        assertEquals(BundleRule.PATH_NOT_NFC,
                assertThrows(BundleRejection.class, () -> path(decomposed)).rule());
        assertEquals(1, indexOf(composed).size(),
                "one member, with the payload root implied rather than counted");
    }

    @Test
    public void anExplicitHeaderForAnAlreadyImpliedDirectoryIsOrdinary() {
        // pos-explicit-dir-headers: app/ and app/sub/ declared after members beneath them.
        indexOf("app/sub/app.R", "app/", "app/sub/");
        indexOf("app/", "app/sub/", "app/sub/app.R");
        // But declaring the same header twice is still a duplicate.
        assertEquals(BundleRule.DUPLICATE_MEMBER,
                ruleFor("app/sub/app.R", "app/sub/", "app/sub/"));
    }

    @Test
    public void theManifestAndThePayloadRootAreDifferentMembers() {
        // Both have an empty payload-relative path, which is why the index keys on the whole
        // member path. Keyed on the payload path they would collide with each other.
        MemberIndex index = indexOf("manifest.json", "app/");
        assertEquals(2, index.size());
    }
}
