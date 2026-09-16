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

import eu.openanalytics.containerproxy.model.spec.AccessControl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Projects a content item's owner, visibility mode and {@code content_acl} rows into the
 * {@link AccessControl} that ContainerProxy already knows how to evaluate.
 *
 * <p>This is the <em>only</em> place registry authorization is expressed. It does not decide
 * anything: {@code AccessControlEvaluationService} makes every decision, exactly as it does
 * for a YAML-configured spec. Keeping the projection in one pure function is what makes the
 * deny cases testable without booting a request.
 *
 * <h2>The one rule that matters</h2>
 *
 * <p>An {@link AccessControl} with no users, no groups and no expression means
 * <em>unrestricted</em>, not <em>denied</em> — {@code AccessControlEvaluationService
 * .hasNoAccessControl()} returns true for it and {@code checkAccess} then returns true for
 * any authenticated principal. So the dangerous failure here is not throwing, it is
 * <b>returning an empty object</b>. Every branch below therefore produces an
 * {@code AccessControl} carrying an explicit positive or negative statement, and
 * {@link #denyEveryone} is the fallback for anything unrecognised.
 */
public final class AccessControlProjector {

    public static final String VISIBILITY_ACL_ONLY = "acl_only";
    public static final String VISIBILITY_ALL_AUTHENTICATED = "all_authenticated";
    public static final String VISIBILITY_ANONYMOUS = "anonymous";

    /**
     * Any principal that got as far as being evaluated. ContainerProxy rejects an
     * {@code AnonymousAuthenticationToken} before any expression runs whenever the
     * authentication backend has authorization, so "anyone" here means "any authenticated
     * user" without the expression having to say so.
     *
     * <p>An empty {@code AccessControl} would behave identically, and is deliberately not
     * used: it is indistinguishable from a projection bug, whereas this is a statement of
     * intent that a test can assert on and an operator can recognise in a debugger.
     */
    static final String ALLOW_ANY_AUTHENTICATED = "true";

    /** Denies everyone, including the owner. Never satisfiable, by construction. */
    static final String DENY_EVERYONE = "false";

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessControlProjector.class);

    private static final String[] NO_PRINCIPALS = new String[0];

    private AccessControlProjector() {
    }

    /**
     * @param slug       identifies the content item in log messages only
     * @param visibility one of the three modes the {@code content_visibility_known} CHECK
     *                   constraint permits
     * @param owner      {@code content.owner}; NOT NULL in the schema
     * @param aclUsers   {@code content_acl.principal} where {@code principal_type = 'user'}
     * @param aclGroups  {@code content_acl.principal} where {@code principal_type = 'group'}
     */
    public static AccessControl project(String slug, String visibility, String owner,
                                        String[] aclUsers, String[] aclGroups) {
        if (visibility == null) {
            LOGGER.error("Content '{}' has no visibility mode; denying all access. This row " +
                "violates the content_visibility_known constraint.", slug);
            return denyEveryone();
        }

        switch (visibility) {
            case VISIBILITY_ACL_ONLY:
                return aclOnly(slug, owner, aclUsers, aclGroups);

            case VISIBILITY_ALL_AUTHENTICATED:
                return allAuthenticated();

            case VISIBILITY_ANONYMOUS:
                // Not reachable through spec-level access control at all. ContainerProxy's
                // AccessControlEvaluationService.checkAccess short-circuits an
                // AnonymousAuthenticationToken to false whenever the authentication backend
                // has authorization -- before users, groups or expression are consulted -- so
                // no AccessControl this method could return would grant an unauthenticated
                // visitor. Serving genuinely public content needs a route that permits
                // anonymous requests, which spine #5 (static documents) is where it belongs.
                //
                // Content is created through the admin endpoint, which rejects this value at
                // write. Reaching here means a row was inserted some other way, so this denies
                // rather than quietly downgrading to "authenticated users only" -- a publisher
                // who asked for public and silently got something else is the failure mode
                // this project refuses elsewhere (WORKPLAN-REGISTRY.md decision 2).
                LOGGER.error("Content '{}' has visibility 'anonymous', which Skald cannot yet " +
                    "serve; denying all access. Anonymous access is not implemented -- see " +
                    "docs/UPSTREAM_CHANGES.md. This row should have been rejected on write.", slug);
                return denyEveryone();

            default:
                LOGGER.error("Content '{}' has unknown visibility '{}'; denying all access.",
                    slug, visibility);
                return denyEveryone();
        }
    }

    /**
     * The owner plus everyone named in {@code content_acl}.
     *
     * <p>Both {@code viewer} and {@code editor} grants are included: they differ in what the
     * holder may change, not in whether they may open the content. Enforcing that difference
     * belongs to the write path, not here.
     */
    private static AccessControl aclOnly(String slug, String owner, String[] aclUsers, String[] aclGroups) {
        Set<String> users = new LinkedHashSet<>();
        addNonBlank(users, owner);
        addAllNonBlank(users, aclUsers);

        Set<String> groups = new LinkedHashSet<>();
        addAllNonBlank(groups, aclGroups);

        if (users.isEmpty() && groups.isEmpty()) {
            // Unreachable while content.owner is NOT NULL, which is exactly why it is checked:
            // an AccessControl with nothing in it means UNRESTRICTED, so the one way to turn
            // acl_only into a leak is to let this method return an empty object.
            LOGGER.error("Content '{}' is acl_only but resolves to no principals at all " +
                "(owner '{}'); denying all access rather than leaving it unrestricted.", slug, owner);
            return denyEveryone();
        }

        AccessControl accessControl = new AccessControl();
        accessControl.setUsers(users.toArray(NO_PRINCIPALS));
        accessControl.setGroups(groups.toArray(NO_PRINCIPALS));
        return accessControl;
    }

    private static AccessControl allAuthenticated() {
        AccessControl accessControl = new AccessControl();
        accessControl.setExpression(ALLOW_ANY_AUTHENTICATED);
        return accessControl;
    }

    private static AccessControl denyEveryone() {
        AccessControl accessControl = new AccessControl();
        accessControl.setExpression(DENY_EVERYONE);
        return accessControl;
    }

    private static void addAllNonBlank(Set<String> target, String[] values) {
        if (values == null) {
            return;
        }
        for (String value : values) {
            addNonBlank(target, value);
        }
    }

    private static void addNonBlank(Set<String> target, String value) {
        if (value != null && !value.isBlank()) {
            target.add(value);
        }
    }

}
