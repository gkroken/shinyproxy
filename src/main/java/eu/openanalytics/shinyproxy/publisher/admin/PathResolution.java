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
package eu.openanalytics.shinyproxy.publisher.admin;

/**
 * The answer to "what is at this path?".
 *
 * <p>{@code pathIsCurrent} is false when the caller asked by a path that has since been
 * renamed away. The content is still returned — the API follows renames for the same reason a
 * browser gets a 301, so that a rename does not silently break existing scripts — but a client
 * that notices can update what it stored.
 */
public record PathResolution(ContentSummary content, boolean pathIsCurrent) {
}
