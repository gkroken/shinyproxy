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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.List;

/**
 * Shape tests for the projection itself. {@code ContentAccessControlTest} proves the
 * decisions that come out of these objects; this file proves the objects are the ones
 * intended, including for inputs the schema should make impossible.
 */
public class AccessControlProjectorTest {

    private static final String[] NONE = new String[0];

    @Test
    public void aclOnlyGrantsTheOwnerAndEveryListedPrincipal() {
        AccessControl accessControl = AccessControlProjector.project(
            "report", AccessControlProjector.VISIBILITY_ACL_ONLY, "alice",
            new String[]{"bob"}, new String[]{"viewers"});

        Assertions.assertEquals(List.of("alice", "bob"), Arrays.asList(accessControl.getUsers()));
        Assertions.assertEquals(List.of("viewers"), Arrays.asList(accessControl.getGroups()));
        Assertions.assertFalse(accessControl.hasExpressionAccess(),
            "acl_only must be expressed as principals, not as an expression");
    }

    @Test
    public void theOwnerIsNotDuplicatedWhenAlsoNamedInTheAcl() {
        AccessControl accessControl = AccessControlProjector.project(
            "report", AccessControlProjector.VISIBILITY_ACL_ONLY, "alice",
            new String[]{"alice", "bob"}, NONE);

        Assertions.assertEquals(List.of("alice", "bob"), Arrays.asList(accessControl.getUsers()));
    }

    @Test
    public void aclOnlyWithNoGrantsStillNamesTheOwner() {
        AccessControl accessControl = AccessControlProjector.project(
            "report", AccessControlProjector.VISIBILITY_ACL_ONLY, "alice", NONE, NONE);

        Assertions.assertEquals(List.of("alice"), Arrays.asList(accessControl.getUsers()));
        Assertions.assertEquals(List.of(), Arrays.asList(accessControl.getGroups()));
    }

    @Test
    public void allAuthenticatedIsAnExplicitExpression() {
        AccessControl accessControl = AccessControlProjector.project(
            "report", AccessControlProjector.VISIBILITY_ALL_AUTHENTICATED, "alice", NONE, NONE);

        Assertions.assertEquals(AccessControlProjector.ALLOW_ANY_AUTHENTICATED,
            accessControl.getExpression());
        Assertions.assertFalse(accessControl.hasUserAccess());
        Assertions.assertFalse(accessControl.hasGroupAccess());
    }

    /**
     * The invariant everything else rests on.
     *
     * <p>{@code AccessControlEvaluationService.hasNoAccessControl()} treats an
     * {@link AccessControl} with no users, no groups and no expression as <em>unrestricted</em>
     * and lets every authenticated principal through. So the way to leak registry content is
     * not to throw — it is to return an empty object. No input may produce one.
     */
    @ParameterizedTest
    @ValueSource(strings = {"acl_only", "all_authenticated", "anonymous", "nonsense", ""})
    public void noInputEverProducesAnUnrestrictedAccessControl(String visibility) {
        for (String owner : new String[]{"alice", "", "   ", null}) {
            AccessControl accessControl =
                AccessControlProjector.project("report", visibility, owner, NONE, NONE);

            Assertions.assertTrue(
                accessControl.hasUserAccess() || accessControl.hasGroupAccess()
                    || accessControl.hasExpressionAccess(),
                "visibility '" + visibility + "' with owner '" + owner
                    + "' projected to an EMPTY AccessControl, which means unrestricted access");
        }
    }

    @Test
    public void aNullVisibilityDeniesRatherThanDefaulting() {
        AccessControl accessControl =
            AccessControlProjector.project("report", null, "alice", NONE, NONE);

        Assertions.assertEquals(AccessControlProjector.DENY_EVERYONE, accessControl.getExpression());
    }

    /**
     * Not a statement that anonymous content should be denied forever — a statement that while
     * Skald cannot serve it, it must not quietly become something else. See
     * {@code ContentAccessControlTest} for why the projection cannot grant it, and
     * {@code docs/UPSTREAM_CHANGES.md} for what implementing it would take.
     */
    @Test
    public void anonymousVisibilityDeniesEveryoneIncludingTheOwner() {
        AccessControl accessControl = AccessControlProjector.project(
            "public-thing", AccessControlProjector.VISIBILITY_ANONYMOUS, "alice",
            new String[]{"bob"}, new String[]{"viewers"});

        Assertions.assertEquals(AccessControlProjector.DENY_EVERYONE, accessControl.getExpression());
        Assertions.assertFalse(accessControl.hasUserAccess(),
            "an unservable mode must not fall back to granting the owner");
        Assertions.assertFalse(accessControl.hasGroupAccess());
    }

    @Test
    public void blankPrincipalsAreDroppedRatherThanGrantedToEveryone() {
        AccessControl accessControl = AccessControlProjector.project(
            "report", AccessControlProjector.VISIBILITY_ACL_ONLY, "alice",
            new String[]{"", "   ", null, "bob"}, new String[]{""});

        Assertions.assertEquals(List.of("alice", "bob"), Arrays.asList(accessControl.getUsers()));
        Assertions.assertEquals(List.of(), Arrays.asList(accessControl.getGroups()));
    }

    /** An owner-less acl_only row cannot be satisfied, so it must deny rather than open up. */
    @Test
    public void aclOnlyWithNothingAtAllDenies() {
        AccessControl accessControl = AccessControlProjector.project(
            "report", AccessControlProjector.VISIBILITY_ACL_ONLY, null, NONE, NONE);

        Assertions.assertEquals(AccessControlProjector.DENY_EVERYONE, accessControl.getExpression());
    }

}
