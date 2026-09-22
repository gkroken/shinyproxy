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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import eu.openanalytics.shinyproxy.publisher.bundle.ExtractionLimits.Bound;
import eu.openanalytics.shinyproxy.publisher.bundle.ExtractionLimits.LimitConfigurationException;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The limits are configuration, and configuration is untrusted input.
 *
 * <p>Two things these tests are arranged to avoid. First, every refusal case is paired with
 * the acceptance immediately beside it — {@code absolute_max} accepted, {@code absolute_max
 * + 1} refused — because a class that refused everything would satisfy a page of refusal
 * assertions and nothing else. Second, nothing here restates a number from the spec file:
 * the expectations are read from {@code spec/extraction-limits-v1.json} on disk, so a test
 * that passed while the packaged copy went stale is not possible.
 */
public class ExtractionLimitsTest {

    private static final Path SPEC_FILE = Path.of("spec", "extraction-limits-v1.json");

    private static JsonNode specOnDisk() throws Exception {
        return new ObjectMapper().readTree(Files.readString(SPEC_FILE));
    }

    @Test
    public void thePackagedSpecIsTheFileInSpec() throws Exception {
        assertNotNull(ExtractionLimits.class.getResourceAsStream(ExtractionLimits.SPEC_RESOURCE),
                ExtractionLimits.SPEC_RESOURCE + " is not on the test classpath: the"
                        + " <resources> entry that packages spec/ has been lost");

        JsonNode bounds = specOnDisk().path("bounds");
        Map<String, Long> resolved = ExtractionLimits.defaults().asMap();

        TreeSet<String> inFile = new TreeSet<>();
        bounds.fieldNames().forEachRemaining(inFile::add);
        assertEquals(inFile, new TreeSet<>(resolved.keySet()),
                "the spec file and the Bound enum describe different sets of limits");

        for (String name : inFile) {
            assertEquals(bounds.path(name).path("default").asLong(), resolved.get(name),
                    name + ": the default in use is not the default in spec/");
        }
    }

    @Test
    public void eachBoundAcceptsItsAbsoluteMaximumAndRefusesOneMore() {
        for (Bound bound : Bound.values()) {
            long max = ExtractionLimits.declaration(bound).absoluteMax();

            ExtractionLimits atMax = ExtractionLimits.fromOverrides(
                    Map.of(bound.specName(), Long.toString(max)));
            assertEquals(max, atMax.get(bound),
                    bound.specName() + ": the absolute maximum itself must be settable,"
                            + " or the bound is really max - 1");

            LimitConfigurationException refused = assertThrows(LimitConfigurationException.class,
                    () -> ExtractionLimits.fromOverrides(
                            Map.of(bound.specName(), Long.toString(max + 1))),
                    bound.specName() + ": a value above the absolute maximum was accepted");
            assertTrue(refused.getMessage().contains(bound.propertyName()),
                    "the refusal does not name the property an operator would have to fix: "
                            + refused.getMessage());
            assertTrue(refused.getMessage().contains(Long.toString(max + 1)),
                    "the refusal does not quote the value that was refused, which is how a"
                            + " clamp would read too: " + refused.getMessage());
        }
    }

    @Test
    public void anOverLargeValueIsNotQuietlyClamped() {
        long max = ExtractionLimits.declaration(Bound.MAX_ENTRIES).absoluteMax();
        try {
            ExtractionLimits clamped = ExtractionLimits.fromOverrides(
                    Map.of("max_entries", Long.toString(max * 4)));
            fail("startup continued with max_entries = " + clamped.maxEntries()
                    + " after being asked for " + (max * 4) + "; a clamped limit is one the"
                    + " operator believes is in force and is not");
        } catch (LimitConfigurationException expected) {
            assertTrue(expected.getMessage().contains("clamped"), expected.getMessage());
        }
    }

    @Test
    public void everyBoundRefusesZeroAndNegativeAndNonNumeric() {
        for (Bound bound : Bound.values()) {
            for (String bad : new String[] {"0", "-1", "", " ", "1.5", "0x10", "unlimited",
                                            "9223372036854775808"}) {
                LimitConfigurationException ex = assertThrows(LimitConfigurationException.class,
                        () -> ExtractionLimits.fromOverrides(Map.of(bound.specName(), bad)),
                        bound.specName() + " accepted " + describe(bad));
                assertTrue(ex.getMessage().contains(bound.propertyName()),
                        "refusal of " + describe(bad) + " does not name the property: "
                                + ex.getMessage());
            }
        }
    }

    @Test
    public void aSettableValueIsActuallyUsed() {
        // The counterweight to every refusal above: a class that threw on all input would
        // pass them and fail this.
        ExtractionLimits limits = ExtractionLimits.fromOverrides(
                Map.of("max_file_bytes", "4096", "max-entries", "7"));
        assertEquals(4096L, limits.maxFileBytes(), "the spec spelling did not bind");
        assertEquals(7L, limits.maxEntries(), "the relaxed spelling did not bind");
        assertEquals(ExtractionLimits.declaration(Bound.MAX_DEPTH).defaultValue(),
                limits.maxDepth(), "an untouched bound did not keep its default");
    }

    @Test
    public void anUnknownKeyStopsStartupRatherThanBeingIgnored() {
        LimitConfigurationException ex = assertThrows(LimitConfigurationException.class,
                () -> ExtractionLimits.fromOverrides(Map.of("max_file_byte", "4096")));
        assertTrue(ex.getMessage().contains("max_file_byte"), ex.getMessage());
        assertTrue(ex.getMessage().contains("max_file_bytes"),
                "the refusal should show the spelling that was meant: " + ex.getMessage());
    }

    @Test
    public void aLimitsPayloadMustCarryEveryBound() {
        Map<String, Long> full = ExtractionLimits.defaults().asMap();

        assertEquals(full, ExtractionLimits.fromJson(json(full)).asMap(),
                "a complete payload did not round-trip");

        for (Bound bound : Bound.values()) {
            Map<String, Long> missing = new LinkedHashMap<>(full);
            missing.remove(bound.specName());
            LimitConfigurationException ex = assertThrows(LimitConfigurationException.class,
                    () -> ExtractionLimits.fromJson(json(missing)),
                    "a payload without " + bound.specName() + " was accepted, which would let"
                            + " a corpus profile silently mix with these defaults");
            assertTrue(ex.getMessage().contains(bound.specName()), ex.getMessage());
        }
    }

    @Test
    public void aLimitsPayloadIsValidatedLikeConfiguration() {
        Map<String, Long> full = ExtractionLimits.defaults().asMap();
        Map<String, Long> hostile = new LinkedHashMap<>(full);
        hostile.put("max_entries",
                ExtractionLimits.declaration(Bound.MAX_ENTRIES).absoluteMax() + 1);

        assertThrows(LimitConfigurationException.class, () -> ExtractionLimits.fromJson(json(hostile)),
                "the JSON entry point is a way past the absolute maxima");
        assertThrows(LimitConfigurationException.class, () -> ExtractionLimits.fromJson("[1]"));
        assertThrows(LimitConfigurationException.class, () -> ExtractionLimits.fromJson("not json"));
    }

    @Test
    public void aSpecThatDisagreesWithTheCodeIsRefused() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode good = specOnDisk();
        assertEquals(Bound.values().length, ExtractionLimits.parseSpec(good, "on disk").size(),
                "the file on disk does not parse cleanly, so the cases below prove nothing");

        // A bound the file declares and no Bound implements: nothing would enforce it.
        JsonNode extra = mapper.readTree(Files.readString(SPEC_FILE)
                .replace("\"max_depth\":", "\"max_deepness\":"));
        assertTrue(assertThrows(LimitConfigurationException.class,
                () -> ExtractionLimits.parseSpec(extra, "mutated"))
                .getMessage().contains("max_deepness"));

        // A bound the code implements and the file drops. Removed rather than renamed: a
        // rename trips the unknown-bound rule above, and would have been this case passing
        // for the previous case's reason.
        JsonNode dropped = mapper.readTree(Files.readString(SPEC_FILE));
        ((ObjectNode) dropped.path("bounds")).remove("max_depth");
        assertTrue(assertThrows(LimitConfigurationException.class,
                () -> ExtractionLimits.parseSpec(dropped, "mutated"))
                .getMessage().contains("max_depth"));

        // A default above its own absolute maximum: unreachable configuration.
        JsonNode incoherent = mapper.readTree(Files.readString(SPEC_FILE)
                .replace("\"default\": 32,", "\"default\": 9999,"));
        assertTrue(assertThrows(LimitConfigurationException.class,
                () -> ExtractionLimits.parseSpec(incoherent, "mutated"))
                .getMessage().contains("incoherent"));

        // A default that is not a number at all.
        JsonNode textual = mapper.readTree(Files.readString(SPEC_FILE)
                .replace("\"default\": 32,", "\"default\": \"32\","));
        assertTrue(assertThrows(LimitConfigurationException.class,
                () -> ExtractionLimits.parseSpec(textual, "mutated"))
                .getMessage().contains("integral"));

        assertThrows(LimitConfigurationException.class,
                () -> ExtractionLimits.parseSpec(mapper.readTree("{}"), "empty"));
    }

    private static String describe(String value) {
        return value.isBlank() ? "blank value '" + value + "'" : "'" + value + "'";
    }

    private static String json(Map<String, Long> values) {
        StringBuilder out = new StringBuilder("{");
        values.forEach((k, v) -> out.append(out.length() > 1 ? "," : "")
                .append('"').append(k).append("\":").append(v));
        return out.append('}').toString();
    }
}
