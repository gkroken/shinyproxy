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
/**
 * Server-owned build recipes (WORKPLAN-BUNDLES.md "Base images, recipes and runtime
 * projection"; T7). An uploaded lockfile is read here under a strict policy and re-rendered
 * in a canonical form; the build consumes the server's rendering, never the upload, so
 * anything the policy did not model (an option line, a remote reference, a repository URL)
 * cannot reach the package manager by being ignored.
 */
package eu.openanalytics.shinyproxy.publisher.recipe;
