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
 * Skald's publishing layer: the content registry, publisher API, build pipeline,
 * scheduler and publisher UI.
 * <p>
 * Everything written for this fork lives under this package. It sits inside
 * {@code eu.openanalytics} because {@code ContainerProxyApplication} declares
 * {@code @ComponentScan("eu.openanalytics")} — beans outside that root are never
 * discovered. Copyright is asserted by the license header, not the package name.
 * <p>
 * Upstream classes are extended through their published seams wherever possible; any
 * change to an upstream class is recorded in {@code docs/UPSTREAM_CHANGES.md}.
 */
package eu.openanalytics.shinyproxy.publisher;
