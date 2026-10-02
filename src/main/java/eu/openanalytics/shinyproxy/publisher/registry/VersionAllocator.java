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

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.UUID;

/**
 * The one place a content_version number is allocated, for the legacy direct-image endpoint
 * and for a build's success alike (WORKPLAN-BUNDLES.md T6 step 5: "allocate a version through
 * the shared allocator"). Version numbers follow allocation order, so a build's number follows
 * its SUCCESS, not its upload or start (decision 4), and no number is ever reused.
 *
 * <p>Must run inside the caller's transaction. It takes the content row's lock -- the
 * coordination lock admission and deletion share -- so two allocations for one item
 * serialise instead of reading the same max(version).
 */
public final class VersionAllocator {

    /** A version that was inserted: its row id and its number. */
    public record Allocated(UUID id, int version) { }

    private final JdbcTemplate jdbc;

    public VersionAllocator(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Locks the content row and inserts the next version. Empty if the content item does not
     * exist (deleted meanwhile): the caller decides what that means.
     *
     * @param buildId the build that produced it, or null for a direct-image version
     */
    public java.util.Optional<Allocated> allocate(UUID contentId, String image, String specJson,
                                                  String createdBy, UUID buildId) {
        List<String> locked = jdbc.queryForList(
                "SELECT id::text FROM skald.content WHERE id = ? FOR UPDATE", String.class, contentId);
        if (locked.isEmpty()) {
            return java.util.Optional.empty();
        }
        Integer version = jdbc.queryForObject("SELECT COALESCE(max(version), 0) + 1"
                + " FROM skald.content_version WHERE content_id = ?", Integer.class, contentId);
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO skald.content_version (id, content_id, version, image, spec_json,"
                + " created_by, build_id) VALUES (?, ?, ?, ?, ?::jsonb, ?, ?)",
                id, contentId, version, image, specJson == null ? "{}" : specJson, createdBy, buildId);
        return java.util.Optional.of(new Allocated(id, version));
    }
}
