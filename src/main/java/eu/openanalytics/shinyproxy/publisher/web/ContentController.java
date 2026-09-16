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

import eu.openanalytics.containerproxy.ContainerProxyException;
import eu.openanalytics.containerproxy.model.runtime.Proxy;
import eu.openanalytics.containerproxy.model.runtime.ProxyStatus;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.PublicPathKey;
import eu.openanalytics.containerproxy.model.runtime.runtimevalues.RuntimeValue;
import eu.openanalytics.containerproxy.model.spec.ProxySpec;
import eu.openanalytics.containerproxy.util.ProxyMappingManager;
import eu.openanalytics.shinyproxy.controllers.BaseController;
import eu.openanalytics.shinyproxy.runtimevalues.AppInstanceKey;
import eu.openanalytics.shinyproxy.publisher.registry.ContentSpecRepository;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.inject.Inject;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static eu.openanalytics.containerproxy.ui.AuthController.AUTH_SUCCESS_URL_SESSION_ATTR;

/**
 * Serves published content at the publisher's own URL.
 *
 * <p>{@code /c/<path>/} is the address a publisher chooses and shares. It is deliberately not
 * a redirect to {@code /app/<specId>}: the spec id is version-qualified, so anything a viewer
 * copies out of their address bar there dies at the next publish, and Shiny's own bookmark
 * URLs die with it. Resolving the active version per request is what makes the published link
 * survive activation and rollback. Spine #5's static documents have no {@code /app} page at
 * all — they are served from object storage with no container — so in-place serving is the
 * only shape that works for both.
 *
 * <h2>What each outcome means, and why</h2>
 *
 * <table border="1">
 *   <tr><td>nothing registered at or above the path</td><td>404</td></tr>
 *   <tr><td>path reserved by content since deleted</td><td><b>410 Gone</b>, never a redirect
 *       to whoever holds the name next</td></tr>
 *   <tr><td>path left behind by a rename</td><td><b>301</b> to the same place under the new
 *       name, <em>including the sub-path</em></td></tr>
 *   <tr><td>not signed in</td><td>login, then back to the content</td></tr>
 *   <tr><td>signed in, not permitted</td><td><b>404, not 403</b></td></tr>
 * </table>
 *
 * <p><b>The 301 carries the sub-path.</b> {@code /c/old/chapter2.html} redirects to
 * {@code /c/new/chapter2.html}, not to {@code /c/new/}. A deep link into a Quarto site or a
 * Shiny route is exactly the kind of link people paste, and dropping the tail would turn
 * "your link still works" into "your link takes you to the front page". This is also why a
 * retired path keeps its whole subtree reserved rather than only its own key.
 *
 * <p><b>404 rather than 403 for a permitted-but-not-for-you request</b> (ADR-0011 rule 5).
 * 403 confirms that content exists at a URL someone guessed or was forwarded, and the index
 * already hides content a user may not see, so 403 here would contradict it.
 *
 * <h2>Authorization</h2>
 *
 * <p>Every decision goes through {@code proxyService.getUserSpec}, which is the same
 * {@code canAccess} the {@code /app} route uses — no second rule to drift. The security
 * configuration deliberately permits {@code /c/**} so that this method can answer 404 and
 * drive the login redirect itself; a matcher denial would produce 403 and lose the
 * destination. That is safe rather than merely convenient: an unauthenticated caller is an
 * {@code AnonymousAuthenticationToken}, and {@code AccessControlEvaluationService.checkAccess}
 * refuses those before any expression runs whenever the backend has authorization, so even a
 * bug in the sign-in check below cannot serve content.
 */
@Controller
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentController extends BaseController {

    /** The one prefix all published content lives under (ADR-0011 rule 1). */
    public static final String PREFIX = "/c/";

    @Inject
    private ProxyMappingManager mappingManager;

    @Inject
    private ContentPathResolver resolver;

    @Inject
    private ContentSpecRepository repository;

    @RequestMapping(value = PREFIX + "**")
    public void serve(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        String requestPath = pathAfterPrefix(request);
        ContentPathResolver.Resolution resolution = resolver.resolve(requestPath);
        if (resolution == null) {
            error(request, response, HttpStatus.NOT_FOUND);
            return;
        }

        if (resolution.contentId() == null) {
            // Reserved, with nothing behind it. Gone, not missing: the difference is the promise
            // that nobody else will ever answer here.
            error(request, response, HttpStatus.GONE);
            return;
        }

        if (!isSignedIn()) {
            redirectToLogin(request, response);
            return;
        }

        String specId = repository.findActiveSpecId(resolution.contentId());
        if (specId == null) {
            // The path is claimed but no version has been activated yet.
            error(request, response, HttpStatus.NOT_FOUND);
            return;
        }

        // getUserSpec applies canAccess. Null covers both "no such spec" and "not yours", and
        // both answer 404 -- see the class comment.
        ProxySpec spec = proxyService.getUserSpec(specId);
        if (spec == null) {
            error(request, response, HttpStatus.NOT_FOUND);
            return;
        }

        // Only now. Redirecting a retired path BEFORE this point answered 301 with the new
        // address to anyone who asked -- including a signed-out caller and a signed-in one the
        // content is not shared with, who correctly got 404 at the current address and were
        // then handed it by the old one. The redirect is a statement about content the caller
        // may not know exists, so it has to be authorized like any other.
        if (!resolution.current()) {
            redirectToCurrentPath(resolution, request, response);
            return;
        }

        if (resolution.remainder().isEmpty() && !request.getRequestURI().endsWith("/")) {
            // Without the trailing slash the app's own relative links resolve one level too
            // high. Upstream's app routes do the same thing for the same reason.
            // The query has to come along: /c/report?tab=2 losing ?tab=2 breaks exactly the
            // shared links with state in them that this URL exists to keep working.
            response.sendRedirect(withQuery(request.getRequestURI() + "/", request));
            return;
        }

        Proxy proxy = getOrStart(spec, resolution);
        if (proxy == null) {
            error(request, response, HttpStatus.SERVICE_UNAVAILABLE);
            return;
        }
        mappingManager.dispatchAsync(proxy, resolution.remainder(), request, response);
    }

    // ------------------------------------------------------------------ outcomes

    /**
     * Follows a rename, keeping whatever the viewer was actually asking for.
     *
     * <p>Looked up rather than derived: the row we matched is retired, so the current path is
     * wherever the content lives now, which may itself have been renamed more than once.
     */
    private void redirectToCurrentPath(ContentPathResolver.Resolution retired,
                                       HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {

        List<String> current = repository.findCurrentPath(retired.contentId());
        if (current.isEmpty()) {
            error(request, response, HttpStatus.NOT_FOUND);
            return;
        }
        // Assembled as a string rather than through UriComponentsBuilder.path(): the remainder
        // is already percent-encoded, and the builder would encode it a second time, turning a
        // link to `a%23b` into one to `a%2523b`.
        String target = ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString()
            + PREFIX + current.get(0)
            + (retired.remainder().isEmpty() ? "/" : "/" + retired.remainder());

        response.setStatus(HttpStatus.MOVED_PERMANENTLY.value());
        response.setHeader("Location", withQuery(target, request));
    }

    /** Appends the request's query string, untouched, when there is one. */
    private static String withQuery(String url, HttpServletRequest request) {
        String query = request.getQueryString();
        return (query == null || query.isEmpty()) ? url : url + "?" + query;
    }

    /**
     * Sends an unauthenticated visitor to sign in, and brings them back here afterwards.
     *
     * <p>Spring's saved request is not enough on its own: {@code UISecurityConfig} replaces the
     * success handler's redirect strategy with one that only restores a destination when
     * {@code AppRequestInfo.fromURI} recognises it, which means {@code /app*} and nothing else
     * (upstream #30648, #28624). Verified against the dev stack — a deep link to {@code /admin}
     * or to {@code /c/...} lands on the index after signing in, while {@code /app/hello} does
     * not. Rather than widen that rule, which would mean a diff against an upstream file, we
     * set the same session attribute it sets.
     *
     * <p><b>What guards it, stated accurately.</b> {@code AuthController} checks the stored
     * value {@code startsWith} this application's base URL — a string prefix test, not a
     * parsed-origin comparison. Both that base and the value stored here are reconstructed
     * from the request, so both reflect the {@code Host} header: sending
     * {@code Host: caller-chosen.invalid} puts that host in the redirect, demonstrated against
     * the live stack. URL reconstruction is not validation, and an earlier version of this
     * comment claimed it was.
     *
     * <p>What actually holds is narrower. A browser sets {@code Host} from the authority of
     * the URL it is visiting, so an attacker cannot choose it for someone else's request; and
     * because {@code AuthController} derives its comparison base from the same request, a
     * value stored under one host does not survive a check made under another. Neither is a
     * property of this method, and neither survives a reverse proxy that forwards an
     * unvalidated {@code Host} — which is the deployment assumption Skald inherits from every
     * absolute URL ContainerProxy builds, not one this route introduces. Host allow-listing
     * belongs at the proxy; see spine #9.
     */
    private void redirectToLogin(HttpServletRequest request, HttpServletResponse response)
        throws IOException {

        // getRequestURL() already carries scheme, host, port AND the context path, exactly once.
        // Feeding getRequestURI() into fromCurrentContextPath() added the context path a second
        // time, so with a context of /skald a visitor was sent back to /skald/skald/c/... and
        // got a 404 after signing in. Invisible on the dev stack, which has no context path.
        String destination = withQuery(request.getRequestURL().toString(), request);
        request.getSession(true).setAttribute(AUTH_SUCCESS_URL_SESSION_ATTR, destination);

        response.sendRedirect(ServletUriComponentsBuilder.fromCurrentContextPath()
            .path("/login").build().toUriString());
    }

    /**
     * Answers with a status the caller can act on, and the platform's error page when the
     * caller is a browser.
     *
     * <p><b>The status is set here, not by the forward.</b> Forwarding to {@code /error} with
     * {@code ERROR_STATUS_CODE} set — which is what upstream's app controllers do — does not
     * change the response status: a browser gets the error page with <b>200</b>. Upstream is
     * not bitten by that because {@code /app_direct/{specId}/**} is refused by a security
     * matcher before its controller runs, so its own forward is never the thing producing the
     * 403. Measured, not assumed: before this, {@code /c/nope} answered 404 to {@code curl} and
     * 200 to {@code Accept: text/html}.
     *
     * <p><b>410 cannot go through {@code /error} at all.</b> {@code ErrorController}'s JSON
     * branch understands 400, 401, 403, 404 and 405, and falls through to
     * {@code ApiResponse.error("unrecoverable error")} with a 500 for anything else — so a
     * deleted path reported itself as a server fault. Only the HTML branch is reused, since it
     * renders whatever status it is given; the JSON shape is written here.
     */
    private void error(HttpServletRequest request, HttpServletResponse response, HttpStatus status)
        throws ServletException, IOException {

        response.setStatus(status.value());
        if (wantsHtml(request)) {
            request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, status.value());
            request.getRequestDispatcher("/error").forward(request, response);
            return;
        }
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"status\":\"fail\",\"data\":\"" + reasonFor(status) + "\"}");
    }

    private static String reasonFor(HttpStatus status) {
        return switch (status) {
            case GONE -> "this content has been deleted, and its address stays reserved";
            case NOT_FOUND -> "no content at this address";
            case SERVICE_UNAVAILABLE -> "the content could not be started";
            default -> status.getReasonPhrase().toLowerCase(Locale.ROOT);
        };
    }

    /** A browser names HTML explicitly; API clients and curl send a wildcard or JSON. */
    private static boolean wantsHtml(HttpServletRequest request) {
        String accept = request.getHeader(HttpHeaders.ACCEPT);
        return accept != null && accept.contains(MediaType.TEXT_HTML_VALUE);
    }

    // ------------------------------------------------------------------ internals

    /**
     * The part of the request after {@code /c/}, undecoded segments included.
     *
     * <p><b>Undecoded, deliberately.</b> {@code getRequestURI()} is raw per the servlet spec,
     * and it is passed on raw — the sub-path belongs to the content, not to us, and decoding it
     * changes what the container is asked for. This used to run it through
     * {@code URI.create(...).getPath()}, which decodes: {@code chapter%20one.html} arrived as
     * {@code chapter one.html}, {@code a%23b} as a fragment delimiter, and {@code a%3Fb} as a
     * real {@code ?}, so everything after it was silently reinterpreted as a query string. The
     * javadoc claimed the opposite of what the code did. Upstream's {@code AppRequestInfo}
     * splits the raw URI for the same reason.
     *
     * <p>A percent-encoded <em>content</em> segment simply fails to match, because stored path
     * keys are plain lower-case ASCII — which is a 404 rather than a way in.
     */
    private String pathAfterPrefix(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (!contextPath.isEmpty() && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }
        return uri.startsWith(PREFIX) ? uri.substring(PREFIX.length()) : "";
    }

    private boolean isSignedIn() {
        Authentication auth = userService.getCurrentAuth();
        return auth != null && auth.isAuthenticated()
            && !(auth instanceof AnonymousAuthenticationToken);
    }

    /**
     * The viewer's own container for this content, started if they do not have one.
     *
     * <p>Modelled on {@code AppDirectController.getOrStart}, including its wait: a first
     * request has to block until the container is reachable, because there is no app page here
     * to show a spinner on.
     */
    private Proxy getOrStart(ProxySpec spec, ContentPathResolver.Resolution resolution) {
        Proxy proxy = findUserProxy(spec.getId(), DEFAULT_INSTANCE);
        if (proxy == null) {
            if (!validateMaxInstances(spec)) {
                throw new ContainerProxyException("Cannot start '" + resolution.path()
                    + "': the maximum number of instances of this content is already running");
            }
            List<RuntimeValue> runtimeValues = shinyProxySpecProvider.getRuntimeValues(spec);
            runtimeValues.add(new RuntimeValue(PublicPathKey.inst, publicPath(resolution)));
            // Without this the proxy is unfindable afterwards, and every later request tries to
            // start another one until max-instances refuses: UserAndAppNameAndInstanceNameProxyIndex
            // matches on AppInstanceKey, so a proxy started without it never matches any key.
            // The symptom is a first request that works and a second that 500s.
            runtimeValues.add(new RuntimeValue(AppInstanceKey.inst, DEFAULT_INSTANCE));

            String id = UUID.randomUUID().toString();
            try {
                proxyService.startProxy(userService.getCurrentAuth(), spec, runtimeValues, id, null).run();
            } catch (Throwable t) {
                throw new ContainerProxyException("Failed to start '" + resolution.path() + "'", t);
            }
            proxy = proxyService.getUserProxy(id);
        }
        return awaitUp(proxy);
    }

    private Proxy awaitUp(Proxy proxy) {
        if (proxy == null) {
            return null;
        }
        for (int i = 0; i < STARTUP_WAIT_SECONDS && proxy.getStatus() == ProxyStatus.New; i++) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
            proxy = proxyService.getProxy(proxy.getId());
            if (proxy == null) {
                return null;
            }
        }
        return (proxy.getStatus() == ProxyStatus.Up) ? proxy : null;
    }

    /**
     * What the container is told its own address is, so that links it generates work.
     *
     * <p>This is the publisher's path, not {@code /app/<specId>} — which is the whole point:
     * a Shiny bookmark or a relative asset URL produced inside the container has to stay
     * inside the URL the viewer is actually on.
     */
    private String publicPath(ContentPathResolver.Resolution resolution) {
        return contextPathHelper.withEndingSlash() + PREFIX.substring(1) + resolution.path() + "/";
    }

    /** Matches upstream's default instance name for a single-instance app. */
    private static final String DEFAULT_INSTANCE = "_";

    /**
     * How long to keep polling a proxy that is still {@code New}, matching upstream's patience.
     *
     * <p>Not a request deadline: {@code startProxy(...).run()} above is synchronous, so a slow
     * image pull is already over by the time this loop is reached. It covers a proxy started
     * elsewhere and not yet up.
     */
    private static final int STARTUP_WAIT_SECONDS = 600;

}
