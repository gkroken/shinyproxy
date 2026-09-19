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

/**
 * The log is over. Immutable once written.
 *
 * <p>Carries what the plan names: "last sequence, byte count, build outcome and
 * completeness/truncation flags".
 *
 * @param generation   the lease generation that completed the build
 * @param lastSequence the last chunk a reader may fetch; like {@link LogIndex}, the end of
 *                     a contiguous run and not the highest sequence present
 * @param bytes        total bytes across those chunks
 * @param outcome      the build's terminal state, from spec/lifecycle-v1.json
 * @param complete     whether every chunk the writer produced is present. False means the
 *                     log itself is missing pieces, which is different from a build that
 *                     failed: the build may have been fine and the log lost
 * @param truncated    whether the writer stopped recording because a limit was reached,
 *                     which is a decision the platform made rather than a loss
 */
public record LogFinal(long generation, long lastSequence, long bytes, String outcome,
                       boolean complete, boolean truncated) {
}
