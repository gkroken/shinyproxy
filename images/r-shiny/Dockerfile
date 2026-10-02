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

# rocker points R at Posit Package Manager (p3m.dev) and sets PPM's binary-selecting user
# agent in Rprofile.site. Skald does not use PPM (user decision 2026-10-02), and a default
# repository baked into the image is one a build could silently resolve against. Replaced
# with an Rprofile that sets no repository at all.
RUN printf 'options(download.file.method = "libcurl")\n' > /usr/local/lib/R/etc/Rprofile.site

# renv at an EXACT version, from the mirror's current tree or its Archive. A version that
# does not install exactly fails the base build rather than shipping a different renv.
RUN test -n "$CRAN_MIRROR" && Rscript --vanilla -e ' \
      m <- sub("/$", "", Sys.getenv("CRAN_MIRROR")); v <- Sys.getenv("RENV_VERSION"); \
      f <- sprintf("renv_%s.tar.gz", v); t <- file.path(tempdir(), f); \
      ok <- tryCatch({ download.file(sprintf("%s/src/contrib/%s", m, f), t, quiet = TRUE); TRUE }, \
                     error = function(e) FALSE, warning = function(w) FALSE); \
      if (!ok) download.file(sprintf("%s/src/contrib/Archive/renv/%s", m, f), t, quiet = TRUE); \
      install.packages(t, repos = NULL, type = "source"); \
      if (as.character(packageVersion("renv")) != v) stop("renv ", packageVersion("renv"), " is not ", v)'

# A fixed, unprivileged identity for both the build's restore step and the running app.
RUN groupadd --gid 10001 skald && useradd --uid 10001 --gid 10001 --no-create-home \
      --home-dir /app --shell /usr/sbin/nologin skald
