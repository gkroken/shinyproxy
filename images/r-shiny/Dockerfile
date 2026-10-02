# Skald trusted base: R / Shiny (WORKPLAN-BUNDLES.md "Base images, recipes and runtime
# projection"; T7). Reviewed by hand; built by the operator when maintaining bases, never by
# an upload. images/catalog.json records what this resolves to.
#
# The upstream is pinned by digest (the multi-arch index digest of rocker/r-ver:4.6.1).
ARG UPSTREAM=rocker/r-ver@sha256:4e6e6696ff54a86625c7f80046478e67014a2184e942b85eeff43db7b992d93e
FROM ${UPSTREAM}

# The repository this base is BUILT through -- the operator's configured mirror (forge in the
# dev stack). Used only to install renv below; a publisher's build gets its repository from the
# server, never from this image.
ARG CRAN_MIRROR
ARG RENV_VERSION=1.3.0
# The SHA-256 of CRAN's own renv_1.3.0.tar.gz (fetched from cloud.r-project.org, whose
# PACKAGES index gives MD5 c815ae95cfee17ea8fd34dfb89c5732e for it -- matched). renv is the
# toolchain every R build's restore runs, so the bytes are pinned, not just the version a
# DESCRIPTION claims (4dd3f76-F1).
ARG RENV_SHA256=c6dd55e6ad50e846bb91e2d2ced99b32c08a110dc9f5337cb7ea29749f049c5f

# rocker points R at Posit Package Manager (p3m.dev) and sets PPM's binary-selecting user
# agent in Rprofile.site. Skald does not use PPM (user decision 2026-10-02), and a default
# repository baked into the image is one a build could silently resolve against. Replaced
# with an Rprofile that sets no repository at all.
RUN printf 'options(download.file.method = "libcurl")\n' > /usr/local/lib/R/etc/Rprofile.site

# renv at an EXACT version, from the mirror's current tree or its Archive, verified against
# the pinned SHA-256 BEFORE anything of it runs (installing a source package runs its code).
# A mismatch fails the base build; so does a version that does not install exactly.
RUN test -n "$CRAN_MIRROR" && Rscript --vanilla -e ' \
      m <- sub("/$", "", Sys.getenv("CRAN_MIRROR")); f <- sprintf("renv_%s.tar.gz", Sys.getenv("RENV_VERSION")); \
      ok <- tryCatch({ download.file(sprintf("%s/src/contrib/%s", m, f), "/tmp/renv.tar.gz", quiet = TRUE); TRUE }, \
                     error = function(e) FALSE, warning = function(w) FALSE); \
      if (!ok) download.file(sprintf("%s/src/contrib/Archive/renv/%s", m, f), "/tmp/renv.tar.gz", quiet = TRUE)' \
 && echo "$RENV_SHA256  /tmp/renv.tar.gz" | sha256sum --check --strict - \
 && Rscript --vanilla -e 'install.packages("/tmp/renv.tar.gz", repos = NULL, type = "source"); \
      v <- Sys.getenv("RENV_VERSION"); \
      if (as.character(packageVersion("renv")) != v) stop("renv ", packageVersion("renv"), " is not ", v)' \
 && rm /tmp/renv.tar.gz

# A fixed, unprivileged identity for both the build's restore step and the running app.
RUN groupadd --gid 10001 skald && useradd --uid 10001 --gid 10001 --no-create-home \
      --home-dir /app --shell /usr/sbin/nologin skald
