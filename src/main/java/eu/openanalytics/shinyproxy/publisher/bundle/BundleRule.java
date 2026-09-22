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
package eu.openanalytics.shinyproxy.publisher.bundle;

/**
 * Why a bundle was refused, in a form a publisher can act on.
 *
 * <p>The plan's rule for the semantic validator — "a rejection names its rule", because
 * "S5: entrypoint `dashboards` contains neither `app.R` nor both `ui.R` and `server.R`" is
 * actionable and "invalid bundle" sends someone to an administrator — applies just as much
 * to extraction, which is where most refusals will happen. These are the names.
 *
 * <p>They are deliberately identifiers rather than numbers. S1-S11 are numbered because the
 * plan numbers them; nothing numbers these, and an invented numbering would have to be
 * remembered by everyone reading a rejection. {@code PATH_TRAVERSAL} does not.
 *
 * <p>This enum is publisher-visible once T6 puts rejections on the admin transport, so
 * adding to it is ordinary and renaming a member is a breaking change.
 */
public enum BundleRule {

    // ---- member paths, as they stream past ---------------------------------------------
    /** The member has no name at all. */
    PATH_EMPTY,
    /** A NUL byte inside the name field, with the rest of the field still there. */
    PATH_NUL,
    /** A control character, which corrupts any log or terminal that echoes the name. */
    PATH_CONTROL_CHARACTER,
    /** Not valid UTF-8, so the name has no defined normalisation and readers disagree. */
    PATH_NOT_UTF8,
    /** Valid UTF-8 but not in NFC. Rejected rather than normalised: see {@link MemberPath}. */
    PATH_NOT_NFC,
    /** A backslash: a literal character here, a separator to anything that later runs on Windows. */
    PATH_BACKSLASH,
    /** An absolute path. */
    PATH_ABSOLUTE,
    /** A Windows drive designator, which is absolute on the system that understands it. */
    PATH_DRIVE_LETTER,
    /** A {@code ..} segment. */
    PATH_TRAVERSAL,
    /** A {@code .} segment. */
    PATH_DOT_SEGMENT,
    /** An empty segment, from a doubled or trailing separator. */
    PATH_EMPTY_SEGMENT,
    /** A trailing slash on something that is not a directory header. */
    PATH_TRAILING_SLASH,
    /** One segment longer than the configured maximum. */
    PATH_SEGMENT_TOO_LONG,
    /** The whole payload-relative path longer than the configured maximum. */
    PATH_TOO_LONG,
    /** More path segments than the configured maximum. */
    PATH_TOO_DEEP,

    // ---- archive layout ----------------------------------------------------------------
    /** A member that is neither the manifest nor under the payload root. */
    LAYOUT_UNEXPECTED_MEMBER;

    /** The identifier a publisher sees, which is the enum's own name. */
    public String ruleName() {
        return name();
    }
}
