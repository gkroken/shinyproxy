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
package eu.openanalytics.shinyproxy.publisher.recipe;

import eu.openanalytics.shinyproxy.publisher.bundle.BundleRejection;

/**
 * A lockfile was refused, and this says why. Thrown, like {@link BundleRejection}, so a
 * refusal cannot be dropped by a caller that forgets to look; and its message is printable
 * ASCII whatever it quotes, because it quotes uploaded text.
 */
public class LockRejection extends RuntimeException {

    /** Why a lockfile was refused. The code is stable; the detail is for people. */
    public enum Reason {
        /** Bigger than the policy reads, by bytes, entries or hashes. */
        TOO_LARGE("lock-too-large"),
        /** Not the format at all: invalid JSON, duplicate keys, invalid UTF-8, bad syntax. */
        SYNTAX("lock-syntax"),
        /** A field or top-level section this policy does not model. */
        UNKNOWN_FIELD("lock-unknown-field"),
        /** The lock is for a different language version than the manifest names. */
        RUNTIME_MISMATCH("lock-runtime-mismatch"),
        /** A package from anywhere but the configured repository: VCS, URL, local, other. */
        NOT_FROM_REPOSITORY("lock-not-from-repository"),
        /** A package or version name outside the accepted grammar. */
        BAD_NAME("lock-bad-name"),
        /** A requirement that is not one exact version. */
        NOT_PINNED("lock-not-pinned"),
        /** A requirement without an approved SHA-256 hash. */
        UNHASHED("lock-unhashed"),
        /** A pip option line: index overrides, includes, editables, find-links and the rest. */
        OPTION_REFUSED("lock-option-refused"),
        /** An environment marker, which this version of the policy does not evaluate. */
        MARKER_UNSUPPORTED("lock-marker-unsupported"),
        /** The same package twice. */
        DUPLICATE("lock-duplicate"),
        /** The lock does not contain the framework the recipe launches. */
        FRAMEWORK_MISSING("lock-framework-missing");

        private final String code;

        Reason(String code) {
            this.code = code;
        }

        public String code() {
            return code;
        }
    }

    private final Reason reason;

    public LockRejection(Reason reason, String detail) {
        super(reason.code() + ": " + BundleRejection.printable(detail));
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
