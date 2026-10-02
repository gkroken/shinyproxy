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
package eu.openanalytics.shinyproxy.publisher.worker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * GatewayConfig against the squid.conf files dev/egress_gateway.py -- the rule the T5 gate
 * measured -- writes for the same inputs (dev/fixtures/worker/squid-confs.json, regenerated
 * by dev/worker-artifacts.py --write).
 */
public class GatewayConfigTest {

    @Test
    public void everyConfigurationIsByteForByteThePythonRule() throws IOException {
        JsonNode cases = new ObjectMapper().readTree(Path.of("dev/fixtures/worker/squid-confs.json").toFile())
                .path("cases");
        assertEquals(4, cases.size());
        for (JsonNode c : cases) {
            assertEquals(c.path("conf").asText(), GatewayConfig.squidConf(c.path("registry").asText(),
                    strings(c.path("repos")), strings(c.path("private_mirrors")),
                    strings(c.path("dns_nameservers"))), c.toString());
        }
    }

    @Test
    public void aHostNameCannotWriteSquidSyntax() {
        // A host name is written into squid's configuration language: a space adds an ACL
        // value, a newline a directive, a leading '-' an option.
        List<String> hostile = List.of("pypi.org\nhttp_access allow all", "pypi.org all",
                "pypi.org\r", "-n", ".pypi.org", "pypi..org", "pypi.org.", "*.pypi.org",
                "pypi.org#x", "", "a".repeat(64) + ".org", "10.0.0.1/8", "[::1]");
        for (String h : hostile) {
            assertThrows(IllegalArgumentException.class,
                    () -> GatewayConfig.squidConf("registry", List.of(h), List.of()), h);
            assertThrows(IllegalArgumentException.class,
                    () -> GatewayConfig.squidConf("registry", List.of(), List.of(h)), h);
            assertThrows(IllegalArgumentException.class,
                    () -> GatewayConfig.squidConf(h, List.of(), List.of()), h);
        }
        for (String dns : List.of("10.0.0.1\nhttp_access allow all", "10.0.0.1 10.0.0.2", "resolver",
                "256.1.1.1", "10.0.0.1:53", "[::1]", "fe80::1%eth0", "", "1.2.3",
                // f5015b6-F2: hex digits and colons that are not an address
                "::::", ":".repeat(23), "fffff::1", "1::2::3", ":::", ":1::", "1::2:",
                "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8", "::ffff:1.2.3.4")) {
            assertThrows(IllegalArgumentException.class, () -> GatewayConfig.squidConf("registry",
                    List.of(), List.of(), List.of(dns)), dns);
        }
        for (String dns : List.of("::", "::1", "fd00::53", "2001:db8::", "1:2:3:4:5:6:7:8",
                "1::8", "FE80:0:0:0:0:0:0:1", "1:2:3:4:5:6::8")) {
            assertTrue(GatewayConfig.squidConf("registry", List.of(), List.of(), List.of(dns))
                    .contains("dns_nameservers " + dns + "\n"), dns);
        }
        String conf = GatewayConfig.squidConf("registry", List.of("cloud.r-project.org", "pypi.org"),
                List.of("forge"));
        assertTrue(conf.lines().noneMatch(l -> l.equals("http_access allow all")));
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        array.forEach(n -> out.add(n.asText()));
        return out;
    }
}
