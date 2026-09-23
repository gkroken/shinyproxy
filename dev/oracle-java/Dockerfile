#
# Skald - Copyright (C) 2026 Gard Kroken
# SPDX-License-Identifier: Apache-2.0
#

# The corpus oracle is Python and its subject is now Java, so the run needs both. The JRE
# is copied from the image dev/Dockerfile already uses rather than installed, so building
# this fetches nothing new and needs no network beyond what that image did.
#
# Built by dev/validate-oracle-java.sh; not used by anything else.
FROM eclipse-temurin:21-jre AS jre
FROM python:3.12-slim
COPY --from=jre /opt/java/openjdk /opt/java/openjdk
ENV JAVA_HOME=/opt/java/openjdk
