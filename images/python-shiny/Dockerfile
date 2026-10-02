# Skald trusted base: Python / Shiny (WORKPLAN-BUNDLES.md "Base images, recipes and runtime
# projection"; T7). Reviewed by hand; built by the operator when maintaining bases, never by
# an upload. images/catalog.json records what this resolves to.
#
# The upstream is pinned by digest (the multi-arch index digest of python:3.13.16-slim).
ARG UPSTREAM=python@sha256:5434c2206183169a6c2b11d6156b775a02cce9a2fd00f9482bb8b9bb785e9b3f
FROM ${UPSTREAM}

# pip is the upstream image's own (recorded in the catalog); no index is configured here. The
# server supplies the index and pip options per build (the plan's pip-hashed contract).
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# A fixed, unprivileged identity for both the build's restore step and the running app.
RUN groupadd --gid 10001 skald && useradd --uid 10001 --gid 10001 --no-create-home \
      --home-dir /app --shell /usr/sbin/nologin skald
