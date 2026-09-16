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

import java.util.List;

/**
 * What the admin endpoints return for one content item.
 *
 * <p>{@code id} is the stable identifier and the thing to store; {@code path} is display and
 * addressing, and may change.
 *
 * <p>{@code activeSpecId} is the ContainerProxy spec id of the active version. It is exposed
 * because an operator needs it: it is the {@code spec.id} metric tag, the Docker label value
 * and the {@code SHINYPROXY_SPEC_ID} inside the container, so anything from a dashboard to
 * {@code docker ps} shows it and there would otherwise be no way to map it back to content.
 * It is null until a version exists.
 */
public record ContentSummary(String id, String path, String title, String owner, String type,
                             String visibility, Integer activeVersion, String activeSpecId,
                             List<Integer> versions) {
}
