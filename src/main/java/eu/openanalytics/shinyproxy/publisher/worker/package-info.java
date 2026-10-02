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
 * The build worker's launch (WORKPLAN-BUNDLES.md "Build sandbox and dependency network";
 * T7 part 3): the isolation profile read from {@code spec/isolation-profile-v1.json} as ONE
 * policy object, and the trusted launcher that starts and disposes of one rootless BuildKit
 * worker per attempt.
 */
package eu.openanalytics.shinyproxy.publisher.worker;
