-- Skald content registry.
--
-- Everything lives in a dedicated `skald` schema rather than `public`, so that pointing
-- Skald and ContainerProxy's usage-statistics collector (which creates its own tables via
-- proxy.usage-stats-url) at one database cannot collide.
--
-- IDENTITY AND ADDRESS ARE SEPARATE, and that separation is the whole point of this schema.
--
--   ProxySpec.id     c<content.id as 32 hex>--v<n>   opaque, immutable, never reused
--   content_path     publisher-settable, renameable, its own rules
--
-- The first version of this schema derived the spec id from a user-visible slug. That was
-- wrong twice over. It made the id REUSABLE -- deleting content and re-creating the same
-- slug handed the new content the old spec id, and ContainerProxy memoises authorization
-- per (sessionId, specId) with no way to invalidate it, so a user who had access to the old
-- content silently kept it on the new one (reproduced live: a revoked user opened the app
-- and started a container). And it made the URL IMMUTABLE, because ContainerProxy's Proxy
-- rows persist only the spec id, so renaming would have orphaned every running container --
-- the ADR-0008 failure.
--
-- A spec id also travels further than a cache key: it is a Micrometer tag (`spec.id`), a
-- Docker label value and the SHINYPROXY_SPEC_ID environment variable inside every container.
-- Reusing one conflates two unrelated apps in metrics and history no matter what the cache
-- does, so uniqueness over time is correct on its own merits.
--
-- Kubernetes label values allow [a-zA-Z0-9]([-_.a-zA-Z0-9]*[a-zA-Z0-9])? up to 63
-- characters. "c" + 32 hex + "--v" + up to 9 digits = 45. ADR-0008 and WORKPLAN-REGISTRY
-- decision 4 are amended to record the format change; the `--v<n>` suffix convention and
-- the reason for it are unchanged.

CREATE SCHEMA IF NOT EXISTS skald;

CREATE TABLE skald.content (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    title              text        NOT NULL,
    owner              text        NOT NULL,
    type               text        NOT NULL,
    visibility         text        NOT NULL DEFAULT 'acl_only',
    active_version_id  uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT content_title_present CHECK (length(btrim(title)) > 0),
    CONSTRAINT content_type_known  CHECK (type IN (
        'shiny', 'quarto_static', 'rmarkdown_static', 'plumber', 'fastapi', 'data')),
    CONSTRAINT content_visibility_known CHECK (visibility IN (
        'acl_only', 'all_authenticated', 'anonymous'))
);

-- Every path this installation has ever served, current and retired, in one table so that
-- uniqueness can be enforced across both at once. A retired path must never become
-- available to different content: whoever inherited it would inherit its audience, and
-- every stale bookmark and link would land on them.
--
-- `content_id` is ON DELETE SET NULL and NOT cascade, deliberately. Cascading would delete
-- the reservation along with the content, and the retired path would silently become
-- available again -- which is the same inheritance bug this table exists to prevent, moved
-- from the spec id to the URL. A row with a NULL content_id is a reserved path with no
-- target: it answers 410 Gone, never 404 and never a redirect.
--
-- `path_key` is the normalised form and the uniqueness key. It is computed by the
-- application as an ASCII lower-casing and stored, rather than expressed as lower(path) in
-- an index: lower() is collation-dependent (in a Turkish collation 'I' lower-cases to a
-- dotless i), so a lower(path) unique index means different things on different installs.
-- The column is COLLATE "C" so comparison is byte-wise everywhere, and the CHECK below
-- refuses anything that is not already normalised.
CREATE TABLE skald.content_path (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    path        text        NOT NULL,
    path_key    text        COLLATE "C" NOT NULL UNIQUE,
    content_id  uuid        REFERENCES skald.content (id) ON DELETE SET NULL,
    is_current  boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz,

    -- Up to three segments, each one slug-shaped, ASCII only. The segment cap bounds how
    -- much of the URL space one content item can own and keeps resolution cheap.
    CONSTRAINT content_path_format CHECK (
        path_key ~ '^[a-z0-9][a-z0-9-]{0,49}(/[a-z0-9][a-z0-9-]{0,49}){0,2}$'),
    -- COLLATE "C" on the argument, not a bare lower(): a bare lower() would make this
    -- constraint itself collation-dependent, which is the problem it exists to avoid.
    -- Byte-wise ASCII lowering also means `path` can only differ from `path_key` in case.
    CONSTRAINT content_path_display_matches CHECK (lower(path COLLATE "C") = path_key),
    CONSTRAINT content_path_ascii CHECK (path ~ '^[A-Za-z0-9/-]+$'),
    CONSTRAINT content_path_retired_has_no_content CHECK (
        is_current OR content_id IS NULL OR retired_at IS NOT NULL)
);

-- Exactly one live path per content item. A rename retires the old row and inserts a new
-- one; it never mutates a path in place, because the old value is the 301 source.
CREATE UNIQUE INDEX content_path_one_current ON skald.content_path (content_id)
    WHERE is_current AND content_id IS NOT NULL;

CREATE INDEX content_path_content_idx ON skald.content_path (content_id);

-- Superseded versions stay resolvable while their containers live (ADR-0008), so versions
-- are never deleted when a new one is activated -- only pointed away from.
CREATE TABLE skald.content_version (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id  uuid        NOT NULL REFERENCES skald.content (id) ON DELETE CASCADE,
    version     integer     NOT NULL,
    image       text        NOT NULL,
    spec_json   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,

    CONSTRAINT content_version_unique   UNIQUE (content_id, version),
    CONSTRAINT content_version_positive CHECK (version > 0)
);

-- Circular by nature: a version belongs to content, and content points at its active
-- version. Added after both tables exist. Nullable because content is created before its
-- first version is built, and ON DELETE SET NULL so a version can be removed without
-- taking the content row with it.
ALTER TABLE skald.content
    ADD CONSTRAINT content_active_version_fk
    FOREIGN KEY (active_version_id) REFERENCES skald.content_version (id) ON DELETE SET NULL;

-- ACLs are projected into a synthesized ContainerProxy AccessControl at request time
-- (AccessControlProjector), so the projection itself needs no upstream change. Superseded
-- versions carry the content item's CURRENT ACL, not a snapshot, including for someone
-- holding a container started on an older version.
--
-- That is a statement about what is stored and read, NOT about when a change is observed.
-- ContainerProxy's ProxyAccessControlService memoises each authorization decision per
-- (sessionId, specId) with no invalidation path, and because the expiry is
-- expireAfterAccess rather than expireAfterWrite, a session that keeps using an app keeps
-- refreshing it -- so a revoked grant does not reach that session at all. See
-- docs/UPSTREAM_CHANGES.md section B. Whoever builds the ACL write path owns that problem.
CREATE TABLE skald.content_acl (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id      uuid        NOT NULL REFERENCES skald.content (id) ON DELETE CASCADE,
    principal_type  text        NOT NULL,
    principal       text        NOT NULL,
    permission      text        NOT NULL DEFAULT 'viewer',
    created_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT content_acl_unique         UNIQUE (content_id, principal_type, principal),
    CONSTRAINT content_acl_principal_type CHECK (principal_type IN ('user', 'group')),
    CONSTRAINT content_acl_permission     CHECK (permission IN ('viewer', 'editor'))
);

-- Secrets are encrypted at rest with a key from the environment, never stored here and
-- never logged. `value_encrypted` is ciphertext even when is_secret is false, so there is
-- exactly one read path and no plaintext column to leak into a log or a dump.
--
-- NOTE: this migration creates the TABLE only. There is no encryption code yet and nothing
-- writes to it -- whoever first does builds that path (CLAUDE.md security invariants).
CREATE TABLE skald.content_env (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id       uuid        NOT NULL REFERENCES skald.content (id) ON DELETE CASCADE,
    key              text        NOT NULL,
    value_encrypted  bytea       NOT NULL,
    is_secret        boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT content_env_unique     UNIQUE (content_id, key),
    CONSTRAINT content_env_key_format CHECK (key ~ '^[A-Za-z_][A-Za-z0-9_]*$')
);

-- Append-only. No updates, no deletes: an audit log that can be edited is not one.
-- (Nothing enforces that yet -- any code holding the JdbcTemplate can delete rows, and the
-- tests do. A restricted role or a rule belongs with the audit work in spine #9.)
--
-- `subject_id` is the content UUID, never the path. The path is mutable, so identifying the
-- subject by it would orphan every audit row written before a rename with no way to join
-- old to new -- the trail would silently stop being one. The path is carried in
-- `detail_json` as a human-readable label instead.
CREATE TABLE skald.audit_event (
    id            bigserial   PRIMARY KEY,
    actor         text        NOT NULL,
    action        text        NOT NULL,
    subject_type  text        NOT NULL,
    subject_id    text,
    detail_json   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX content_owner_idx           ON skald.content (owner);
CREATE INDEX content_version_content_idx ON skald.content_version (content_id);
CREATE INDEX content_acl_lookup_idx      ON skald.content_acl (principal_type, principal);
CREATE INDEX audit_event_subject_idx     ON skald.audit_event (subject_type, subject_id);
CREATE INDEX audit_event_at_idx          ON skald.audit_event (at DESC);
