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

import eu.openanalytics.containerproxy.api.dto.ApiResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.List;
import java.util.UUID;

/**
 * Admin-only content registry endpoints (spine #1 task 7). No publisher API and no UI: this
 * exists so an administrator can put content into the registry over HTTP instead of SQL, and
 * so the smoke script can do the same.
 *
 * <p><b>Authorization is inherited, not re-implemented.</b> The path deliberately sits under
 * {@code /admin}, which {@code UISecurityConfig} already gates on
 * {@code userService.isAdmin(...)} for {@code /admin} and {@code /admin/**}. Adding a second
 * matcher for a second prefix would be a second place for an authorization rule to drift —
 * CLAUDE.md's "every authorization decision goes through one service". Spine #3's
 * {@code /__api__/v1} is a different surface with its own API-key auth, and is not this.
 *
 * <p><b>Why these endpoints only accept JSON.</b> ShinyProxy enables CSRF protection for
 * exactly one route — {@code WebSecurityConfig:136} restricts it to {@code POST /login} — so a
 * session-authenticated admin browsing a hostile page could otherwise be made to submit a form
 * that creates or deletes content. The three content types an HTML form can produce
 * ({@code application/x-www-form-urlencoded}, {@code multipart/form-data}, {@code text/plain})
 * are all refused with 415, and sending {@code application/json} cross-origin requires a CORS
 * preflight this application never grants.
 *
 * <p>That refusal has <b>two independent guards</b>, and it is worth knowing which is which.
 * {@code @RequestBody} binding already rejects those content types, because the only message
 * converter that can read a request body into these records is Jackson's, which declares
 * {@code application/json} alone — verified by mutation: dropping {@code consumes} below still
 * returns 415. The explicit {@code consumes} is therefore belt to that braces. It is kept
 * because it states the requirement where a reader will look for it, and because the implicit
 * guard depends on converter configuration that nothing in this repository owns: register a
 * form-aware converter, or switch a handler to {@code @ModelAttribute}, and the implicit guard
 * silently disappears while {@code consumes} does not.
 *
 * <p>Re-declaring {@code http.csrf(...)} from the {@code ICustomSecurityConfig} seam was
 * rejected: that matcher is global, our seam runs after upstream sets it, and getting it wrong
 * breaks login. Token auth for a real publishing API arrives in spine #3.
 */
@RestController
@RequestMapping("/admin/content")
@ConditionalOnProperty(name = "spring.datasource.url")
public class ContentAdminController {

    private final ContentAdminService service;

    public ContentAdminController(ContentAdminService service) {
        this.service = service;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<List<ContentSummary>>> list() {
        return ApiResponse.success(service.list());
    }

    /**
     * Looks content up by its path, following renames.
     *
     * <p>Mutating endpoints take the content id, because that is what does not move. This is how
     * a caller that only knows a name gets to one — and it resolves retired paths too, so a
     * rename does not silently break a script the way it would break a bookmark without a 301.
     * A path belonging to deleted content answers 410, never 404: the reservation is a promise
     * that nothing else will ever answer there.
     */
    @GetMapping(value = "/by-path", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<PathResolution>> byPath(@RequestParam String path) {
        return ApiResponse.success(service.resolveByPath(path));
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<ContentSummary>> create(@RequestBody CreateContentRequest request) {
        return ApiResponse.created(service.create(request));
    }

    @PostMapping(value = "/{id}/versions",
        consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<ContentSummary>> addVersion(@PathVariable UUID id,
                                                                 @RequestBody AddVersionRequest request) {
        return ApiResponse.created(service.addVersion(id, request));
    }

    /** Activation and rollback are the same operation; rollback names an older version. */
    @PutMapping(value = "/{id}/active-version",
        consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<ContentSummary>> activate(@PathVariable UUID id,
                                                               @RequestBody ActivateRequest request) {
        return ApiResponse.success(service.activate(id, request));
    }

    /** Moves content to a new path. The old one stays reserved and redirects here. */
    @PutMapping(value = "/{id}/path",
        consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<ContentSummary>> rename(@PathVariable UUID id,
                                                             @RequestBody RenameRequest request) {
        return ApiResponse.success(service.rename(id, request));
    }

    /**
     * A body-less method, so the JSON content type cannot be the CSRF defence here. It does not
     * need to be: {@code DELETE} is not a method an HTML form can issue, so it is not reachable
     * by the form-based cross-site POST that the rule above exists to stop.
     */
    @DeleteMapping(value = "/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable UUID id) {
        service.delete(id);
        return ApiResponse.success();
    }

    /** A malformed UUID in the path is a bad request, not an unrecoverable error. */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponse<Object>> handle(MethodArgumentTypeMismatchException e) {
        return ResponseEntity.badRequest().body(ApiResponse.errorBody(
            "'" + e.getValue() + "' is not a content id; mutating endpoints take the id from "
                + "GET /admin/content or GET /admin/content/by-path?path=..."));
    }

    /**
     * Refusals carry their reason in the body. These are operator-facing messages about
     * decisions recorded in the workplan, and a bare status code would send whoever hit one
     * looking through the schema for an explanation that is not there.
     */
    @ExceptionHandler(ContentAdminException.class)
    public ResponseEntity<ApiResponse<Object>> handle(ContentAdminException e) {
        return ResponseEntity.status(e.getStatus()).body(ApiResponse.errorBody(e.getMessage()));
    }

}
