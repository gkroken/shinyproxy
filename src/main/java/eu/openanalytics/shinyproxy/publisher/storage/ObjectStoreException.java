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
 * A storage operation failed, and the caller must treat that as a failure.
 *
 * <p>Unchecked because there is nothing useful a caller can do except abandon the operation
 * and report it. The one thing it must not do is continue as though the write succeeded:
 * the plan requires a MinIO outage to be "an explicit storage failure" with "no filesystem
 * durability fallback", and an exception that is easy to swallow is how a fallback appears
 * without anyone deciding to add one.
 */
public class ObjectStoreException extends RuntimeException {

    public ObjectStoreException(String message) {
        super(message);
    }

    public ObjectStoreException(String message, Throwable cause) {
        super(message, cause);
    }
}
