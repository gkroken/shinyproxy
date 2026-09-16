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
package eu.openanalytics.shinyproxy.publisher.web;

import eu.openanalytics.shinyproxy.publisher.registry.ContentPath;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Turns a request under {@code /c/} into the content that owns it, plus the part of the URL
 * that belongs to the content rather than to Skald.
 *
 * <p><b>Longest prefix, not exact match.</b> Content owns its whole subtree: a Quarto site
 * published at {@code finance/report} serves {@code chapter2.html} and {@code styles.css}
 * beneath itself, and a Shiny app's own routes live there too. So {@code /c/finance/report/
 * chapter2.html} has to resolve to that content with {@code chapter2.html} left over.
 *
 * <p>Because {@code ContentAdminService.claimPath} refuses a path that nests inside another,
 * at most one registered path can ever be a prefix of a given request — so "longest" is
 * really "the only one". It is still written as longest-wins rather than assuming a single
 * row, because the alternative is a resolver whose correctness depends on a rule enforced
 * somewhere else, and that rule was not airtight until the advisory lock landed.
 *
 * <p><b>Retired paths are matched too</b>, and that is what makes a rename safe for links
 * that were already shared. A retired row keeps its subtree reserved precisely so that
 * {@code /c/old-name/chapter2.html} can be answered — redirected to the same page under the
 * new name, or reported {@code 410 Gone} if the content was deleted. If retired rows were
 * skipped here, the reservation would exist in the write path and mean nothing at read time.
 */
@Component
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentPathResolver {

    /**
     * The one registered path that is a prefix of the request, with whatever followed it.
     *
     * @param path       the registered path, in the publisher's own capitalisation
     * @param contentId  null for a path reserved by content that has since been deleted
     * @param current    false for a path left behind by a rename
     * @param remainder  the rest of the request, with no leading slash; empty for the root
     */
    public record Resolution(String path, UUID contentId, boolean current, String remainder) {
    }

    private final JdbcTemplate jdbc;

    public ContentPathResolver(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * @param requestPath the URL after {@code /c/}, with no leading slash; may be empty
     * @return the match, or null when nothing is registered at or above this path — which
     *         includes an intermediate level such as {@code /c/etl/} when only
     *         {@code etl/fetchFromA} and {@code etl/fetchFromB} are published. Nothing can be
     *         published at {@code etl} itself, so that level is a 404 today; spine #4 replaces
     *         it with a generated index of the content beneath it that the viewer may see.
     */
    public Resolution resolve(String requestPath) {
        if (requestPath == null || requestPath.isBlank()) {
            return null;
        }
        String relative = requestPath.startsWith("/") ? requestPath.substring(1) : requestPath;
        String key = relative.toLowerCase(Locale.ROOT);

        // Only the first MAX_SEGMENTS segments can name content; the rest belongs to it.
        String[] segments = key.split("/");
        List<String> candidates = new ArrayList<>();
        StringBuilder candidate = new StringBuilder();
        for (int i = 0; i < Math.min(segments.length, ContentPath.MAX_SEGMENTS); i++) {
            if (i > 0) {
                candidate.append('/');
            }
            candidate.append(segments[i]);
            candidates.add(candidate.toString());
        }
        if (candidates.isEmpty()) {
            return null;
        }

        // Longest first, so the single legal match is found without scanning the table.
        String placeholders = String.join(",", Collections.nCopies(candidates.size(), "?"));
        List<Resolution> found = jdbc.query("""
            SELECT path, path_key, content_id, is_current FROM skald.content_path
            WHERE path_key IN (%s)
            ORDER BY length(path_key) DESC
            LIMIT 1
            """.formatted(placeholders),
            (rs, rowNum) -> {
                // Sliced off the ORIGINAL request, not the lower-cased key: only the part that
                // names content is case-insensitive. What follows is the content's own URL
                // space -- an asset filename, a Quarto page, a Plumber route -- where case is
                // significant and lower-casing it would 404 on `chapter2.HTML`.
                int matchedLength = rs.getString("path_key").length();
                String remainder = relative.length() > matchedLength
                    ? relative.substring(matchedLength + 1) : "";
                return new Resolution(rs.getString("path"), (UUID) rs.getObject("content_id"),
                    rs.getBoolean("is_current"), remainder);
            },
            candidates.toArray());

        return found.isEmpty() ? null : found.get(0);
    }

}
