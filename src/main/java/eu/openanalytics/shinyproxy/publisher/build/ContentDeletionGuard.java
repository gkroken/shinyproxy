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
package eu.openanalytics.shinyproxy.publisher.build;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.UUID;

/**
 * The build side of deleting a content item, run INSIDE the deletion's transaction before
 * anything is removed (WORKPLAN-BUNDLES.md T6, "V2 and lifecycle", deletion paragraph):
 * <ol>
 *   <li>the content row's lock -- the coordination lock admission, version allocation and a
 *       build's success all take first. An admission waiting on it while the item is deleted
 *       finds no content afterwards and is refused cleanly (CONTENT_NOT_FOUND), instead of
 *       inserting a build for a deleted item;</li>
 *   <li>refuse while any build is unfinished (QUEUED, RUNNING, PUBLISHING): a running
 *       worker's results would have nowhere to go, and a PUBLISHING one may be mid-way to a
 *       version. The publisher cancels or waits;</li>
 *   <li>every LIVE artifact record of the item becomes DELETE_PENDING, in this same
 *       transaction, before the cascade removes the rows that described it. The records
 *       carry the content id as a plain value, so they survive the cascade and cleanup can
 *       still find what to remove.</li>
 * </ol>
 * Deliberately NOT here: ContentAdminService's live-proxy re-check, which coordinates with
 * ContainerProxy's in-memory store and which no database lock can serialise (the plan says
 * so, and the service already does it).
 */
public final class ContentDeletionGuard {

    /** Deletion refused because builds of the item are not finished. */
    public static final class BuildsInProgress extends RuntimeException {
        private final List<UUID> builds;

        BuildsInProgress(List<UUID> builds) {
            super("this content has " + builds.size() + " unfinished build(s) (" + builds
                    + "); cancel them or wait for them to finish before deleting");
            this.builds = List.copyOf(builds);
        }

        public List<UUID> builds() {
            return builds;
        }
    }

    private final JdbcTemplate jdbc;

    public ContentDeletionGuard(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * Locks, checks and enqueues cleanup. Must be called in the deletion's transaction.
     *
     * @return false if the content item does not exist (nothing to guard)
     * @throws BuildsInProgress if any build of the item is unfinished
     */
    public boolean prepare(UUID contentId) {
        if (jdbc.queryForList("SELECT id FROM skald.content WHERE id = ? FOR UPDATE",
                contentId).isEmpty()) {
            return false;
        }
        List<UUID> unfinished = jdbc.queryForList("SELECT id FROM skald.build WHERE content_id = ?"
                + " AND state IN ('QUEUED', 'RUNNING', 'PUBLISHING') ORDER BY created_at",
                UUID.class, contentId);
        if (!unfinished.isEmpty()) {
            throw new BuildsInProgress(unfinished);
        }
        jdbc.update("UPDATE skald.artifact SET state = 'DELETE_PENDING', delete_requested_at = now()"
                + " WHERE subject_content_id = ? AND state = 'LIVE'", contentId);
        return true;
    }
}
