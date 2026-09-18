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
package eu.openanalytics.shinyproxy.publisher.storage;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The AWS SDK must be on this classpath exactly once, at one version.
 *
 * <p>ContainerProxy 1.2.4 already brings the whole SDK in transitively at 2.31.21 —
 * {@code s3} itself, plus {@code sso}, {@code sts}, {@code ecs} and their protocol modules
 * — which is not obvious from this repository's {@code pom.xml} and was not noticed until
 * the resolved list was actually read. So declaring {@code s3} at the newest release did
 * not add a module beside the engine's: it <em>upgraded the engine's own</em> {@code s3}
 * to 2.55.0 and left the rest at 2.31.21, putting 2.55.0 {@code sdk-core} underneath
 * service modules compiled against 2.31.21. AWS ships a BOM to prevent exactly that, and
 * mixing 2.x module versions is unsupported.
 *
 * <p>Nothing else in the build would notice. Maven's nearest-wins mediation resolves a
 * mixed set silently and the jar builds, so the failure would arrive at runtime as a
 * {@code NoSuchMethodError} from a service module calling a core method that moved — most
 * likely on the first real upload, against a real bucket.
 *
 * <p>This test reads the surefire classpath rather than the pom, so it checks what will
 * actually be loaded rather than what was declared.
 */
class AwsSdkClasspathTest {

    private static final Pattern SDK_JAR =
            Pattern.compile("^(.*)-(\\d+\\.\\d+\\.\\d+(?:-[A-Za-z0-9.]+)?)\\.jar$");

    /** module name -> version, for every awssdk jar on the test classpath. */
    private Map<String, String> sdkArtifacts() {
        Map<String, String> found = new LinkedHashMap<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            // The group directory is what identifies an SDK artifact; a jar called
            // "s3-2.31.21.jar" could belong to anyone.
            String normalised = entry.replace(File.separatorChar, '/');
            if (!normalised.contains("/software/amazon/awssdk/")) {
                continue;
            }
            String name = normalised.substring(normalised.lastIndexOf('/') + 1);
            Matcher m = SDK_JAR.matcher(name);
            if (m.matches()) {
                found.put(m.group(1), m.group(2));
            }
        }
        return found;
    }

    @Test
    @DisplayName("every awssdk artifact on the classpath is at one single version")
    void sdkIsNotMixedAcrossVersions() {
        Map<String, String> artifacts = sdkArtifacts();

        // Without this the loop below passes for free on an empty map, which is the shape
        // this project has produced at three levels already.
        assertFalse(artifacts.isEmpty(),
                "found no software.amazon.awssdk jars on the test classpath; the probe has "
                        + "broken and the version check below would assert nothing");
        // s3 reaches the classpath through ContainerProxy whether or not this repository
        // declares it, so its absence means the probe broke rather than that a declaration
        // was dropped.
        assertTrue(artifacts.containsKey("s3"),
                "no s3 module on the classpath; ContainerProxy brings one transitively and "
                        + "pom.xml pins it, so the classpath probe has broken: "
                        + artifacts.keySet());

        TreeSet<String> versions = new TreeSet<>(artifacts.values());
        if (versions.size() > 1) {
            // Name the minority modules: those are the ones to align, and a bare
            // "expected 1 but was 2" would send the next reader back to dependency:tree.
            List<String> detail = new ArrayList<>();
            for (String version : versions) {
                List<String> modules = new ArrayList<>();
                artifacts.forEach((module, v) -> {
                    if (v.equals(version)) {
                        modules.add(module);
                    }
                });
                detail.add(version + " -> " + modules);
            }
            assertEquals(1, versions.size(),
                    "the AWS SDK is on this classpath at " + versions.size() + " different "
                            + "versions. Service modules are compiled against their own "
                            + "core, so a mixed set fails at runtime, not at build time. "
                            + "ContainerProxy contributes s3, sso, sts and ecs "
                            + "transitively, so aws-sdk.version in pom.xml must match "
                            + "whatever the engine brings.\n  "
                            + String.join("\n  ", detail));
        }

        assertEquals(1, versions.size());
    }

    @Test
    @DisplayName("the engine still contributes the modules the pin is aligned to")
    void theEnginesModulesAreIncluded() {
        Map<String, String> artifacts = sdkArtifacts();
        // These arrive ONLY through ContainerProxy -- s3 is deliberately not in this list,
        // because it is declared here as well and so its absence would mean something
        // different. If these vanish, the version this project pins is no longer
        // constrained by the engine and the choice should be revisited deliberately rather
        // than inherited from a stale comment in the pom.
        for (String engineModule : new String[]{"sso", "sts", "ecs"}) {
            assertTrue(artifacts.containsKey(engineModule),
                    "ContainerProxy no longer contributes " + engineModule + "; "
                            + "aws-sdk.version is pinned to match the engine and that "
                            + "reason may no longer apply. Present: " + artifacts.keySet());
        }
    }

    @Test
    @DisplayName("s3 is DECLARED here, not merely inherited from the engine")
    void s3IsDeclaredAndNotOnlyInherited() throws IOException {
        // The classpath cannot show this. The engine supplies s3 at 2.31.21 whether or not
        // this repository declares it, so deleting the dependency block leaves every
        // classpath assertion green -- verified, and it is why this test reads the pom
        // (finding ba06976-F1). Without it, a later cleanup that removes the block as
        // redundant silently returns this project to inheriting whatever ContainerProxy
        // happens to bring, which is the situation the declaration exists to end.
        Path pom = Path.of("pom.xml");
        assertTrue(Files.exists(pom), "pom.xml not found; this test cannot check what it "
                + "cannot read");
        String text = Files.readString(pom, StandardCharsets.UTF_8);

        Matcher m = Pattern.compile(
                "<dependency>\\s*<groupId>software\\.amazon\\.awssdk</groupId>\\s*"
                        + "<artifactId>s3</artifactId>\\s*<version>([^<]+)</version>",
                Pattern.DOTALL).matcher(text);
        assertTrue(m.find(),
                "pom.xml does not declare software.amazon.awssdk:s3 with an explicit "
                        + "version. It would still be on the classpath -- ContainerProxy "
                        + "brings it -- but at whatever version the engine happens to use, "
                        + "which is what this declaration exists to stop.");
        assertEquals("${aws-sdk.version}", m.group(1),
                "s3 is declared with a literal version rather than ${aws-sdk.version}; the "
                        + "property is what keeps s3 and url-connection-client aligned");

        assertTrue(text.contains("<artifactId>url-connection-client</artifactId>"),
                "url-connection-client is the one artifact this repository actually adds to "
                        + "the runtime classpath, and the HTTP client is selected explicitly "
                        + "because several are present; it must stay declared");
    }
}
