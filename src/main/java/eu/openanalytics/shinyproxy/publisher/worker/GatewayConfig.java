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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * The build worker's egress gateway configuration (squid), as dev/egress_gateway.py's
 * squid_conf(weaken=None) writes it -- the rule the T5 gate measured, first match wins:
 * metadata deny; to_localhost deny; CONNECT only to 443; the registry on its port; declared
 * private mirrors on the repository ports; every private or non-public destination deny
 * (rebinding); public repositories by exact name (-n: never by reverse DNS) on the
 * repository ports; deny all. See that module's docstring for why each rule exists.
 *
 * <p>{@code GatewayConfigTest} holds this to squid.conf files the Python module generated
 * (dev/fixtures/worker/squid-*.conf, by dev/worker-artifacts.py --write), byte for byte.
 *
 * <p>Host names are written into squid's configuration language, so each is checked
 * against a strict DNS-name grammar first: a space would add an ACL value, a newline a
 * directive.
 */
public final class GatewayConfig {

    public static final int PORT = 8888;
    static final List<String> METADATA_ADDRESSES = List.of("fd00:ec2::254/128", "100.100.100.200/32");
    static final List<Integer> REPO_PORTS = List.of(80, 443);
    static final List<String> EMBEDDED_IPV4_PREFIXES = List.of("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16");
    static final List<String> PRIVATE_DESTINATIONS = List.of("10.0.0.0/8", "172.16.0.0/12",
            "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "0.0.0.0/8", "198.18.0.0/15",
            "224.0.0.0/4", "240.0.0.0/4", "fc00::/7", "fec0::/10", "::1/128");
    /** A DNS name: dot-separated labels of letters, digits and inner hyphens. */
    private static final Pattern HOST = Pattern.compile(
            "(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            + "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");

    private GatewayConfig() {
    }

    /** The squid.conf text for this registry and these public repositories and private mirrors. */
    public static String squidConf(String registry, List<String> repos, List<String> privateMirrors) {
        for (String host : concat(List.of(registry), repos, privateMirrors)) {
            if (!HOST.matcher(host).matches()) {
                throw new IllegalArgumentException("not a host name: " + host);
            }
        }
        List<String> lines = new ArrayList<>();
        lines.add("http_port " + PORT);
        lines.add("acl metadata dst 169.254.0.0/16 fe80::/10 " + String.join(" ", METADATA_ADDRESSES));
        lines.add("acl repo_ports port " + String.join(" ", REPO_PORTS.stream().map(String::valueOf).toList()));
        lines.add("acl SSL_ports port 443");
        lines.add("acl CONNECT method CONNECT");
        lines.add("acl registry dstdomain -n " + registry);
        // The registry's port is fixed at 5000, as in the measured rule; a deployment whose
        // registry listens elsewhere needs the rule (and its probe) extended first.
        lines.add("acl registry_port port 5000");
        lines.add("acl private_dst dst " + String.join(" ", concat(PRIVATE_DESTINATIONS, EMBEDDED_IPV4_PREFIXES)));
        if (!privateMirrors.isEmpty()) {
            lines.add("acl private_mirrors dstdomain -n " + String.join(" ", privateMirrors));
        }
        if (!repos.isEmpty()) {
            lines.add("acl repos dstdomain -n " + String.join(" ", repos));
        }
        lines.add("http_access deny metadata");
        lines.add("http_access deny to_localhost");
        lines.add("http_access deny CONNECT !SSL_ports");
        lines.add("http_access allow registry registry_port");
        if (!privateMirrors.isEmpty()) {
            lines.add("http_access allow private_mirrors repo_ports");
        }
        lines.add("http_access deny private_dst");
        if (!repos.isEmpty()) {
            lines.add("http_access allow repos repo_ports");
        }
        lines.addAll(List.of("http_access deny all", "cache deny all", "access_log stdio:/dev/stdout",
                "cache_log stdio:/dev/stderr", "pid_filename none", "coredump_dir /tmp"));
        return String.join("\n", lines) + "\n";
    }

    @SafeVarargs
    private static List<String> concat(List<String>... lists) {
        List<String> out = new ArrayList<>();
        for (List<String> l : lists) {
            out.addAll(l);
        }
        return out;
    }
}
