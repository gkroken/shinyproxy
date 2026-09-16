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
package eu.openanalytics.shinyproxy.publisher.web;

import eu.openanalytics.containerproxy.security.ICustomSecurityConfig;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import javax.inject.Inject;

/**
 * Lets requests for {@code /c/**} reach {@link ContentController}, which decides them.
 *
 * <p>Registered through {@code ICustomSecurityConfig}, the same collected-bean seam
 * {@code UISecurityConfig} uses, so it applies before {@code WebSecurityConfig} adds
 * {@code anyRequest().fullyAuthenticated()} — the matcher below would otherwise never be
 * consulted for a signed-out visitor.
 *
 * <p><b>Why {@code permitAll} and not {@code authenticated()}.</b> Two of ADR-0011's five path
 * rules cannot be expressed in a matcher. A signed-in visitor without a grant must get
 * <b>404, not 403</b>, and a signed-out one must be sent to log in and then returned <b>to the
 * content they asked for</b>. A matcher denial produces 403 and discards the destination, so
 * both decisions have to belong to the controller — which means the request has to arrive
 * there.
 *
 * <p><b>Why that is not a hole.</b> Permitting the route permits reaching the handler, not
 * reaching content. Every path through {@link ContentController} that serves anything goes via
 * {@code proxyService.getUserSpec}, which is {@code canAccess}: the same single authorization
 * service the {@code /app} route uses (CLAUDE.md — every authorization decision goes through
 * one service). And an unauthenticated caller carries an {@code AnonymousAuthenticationToken},
 * which {@code AccessControlEvaluationService.checkAccess} refuses before any user, group or
 * expression is consulted whenever the backend has authorization. So the sign-in check in the
 * controller decides *how* a signed-out visitor is turned away, not *whether* — if it were
 * removed entirely, content would still not be served. The deny tests cover both layers.
 *
 * <p>Spine #5's anonymous access attaches here: minting a per-session guest identity for
 * content whose visibility is {@code anonymous} is a filter on this same route, and this is
 * the seam that already lets an unauthenticated request get far enough to be given one.
 */
@Component
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentSecurityConfig implements ICustomSecurityConfig {

    @Inject
    private HandlerMappingIntrospector handlerMappingIntrospector;

    @Override
    public void apply(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz.requestMatchers(contentRoutes()).permitAll());
    }

    private RequestMatcher contentRoutes() {
        return new MvcRequestMatcher(handlerMappingIntrospector, ContentController.PREFIX + "**");
    }

}
