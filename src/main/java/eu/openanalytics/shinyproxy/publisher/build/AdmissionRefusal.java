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

/**
 * Why a build request was not admitted. Each reason carries the HTTP status T8's transport
 * maps it to, so the decision is made once, here, and the transport only renders it.
 */
public final class AdmissionRefusal extends RuntimeException {

    public enum Reason {
        /** The idempotency key is not 1-200 printable ASCII characters. */
        KEY_INVALID(400),
        /** No such content item. */
        CONTENT_NOT_FOUND(404),
        /** No such bundle FOR THIS CONTENT ITEM: another item's bundle is not found here. */
        BUNDLE_NOT_FOUND(404),
        /** The bundle exists but is not VALIDATED, so there is nothing safe to build. */
        BUNDLE_NOT_VALIDATED(409),
        /** The key was used before for different inputs (lifecycle: key + inputs). */
        KEY_REUSED_WITH_DIFFERENT_INPUTS(409),
        /** The publisher already holds the configured number of unfinished builds. */
        PUBLISHER_LIMIT(429),
        /** The global queue is at capacity. */
        QUEUE_FULL(503);

        private final int httpStatus;

        Reason(int httpStatus) {
            this.httpStatus = httpStatus;
        }

        public int httpStatus() {
            return httpStatus;
        }
    }

    private final Reason reason;

    public AdmissionRefusal(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
