-- Skald content registry.
--
-- Everything lives in a dedicated `skald` schema rather than `public`, so that pointing
-- Skald and ContainerProxy's usage-statistics collector (which creates its own tables via
-- proxy.usage-stats-url) at one database cannot collide.
--
-- Spec ids are `<slug>--v<n>` (WORKPLAN-REGISTRY.md decision 4). That string is persisted
-- in ContainerProxy's `Proxy` rows and in running containers' runtime values, so it is
-- effectively immutable once content exists. Kubernetes label values allow only
-- [a-zA-Z0-9]([-_.a-zA-Z0-9]*[a-zA-Z0-9])? and cap at 63 characters, which is why the slug
-- is constrained to 50: `<slug>--v<n>` must stay inside that budget even at high version
-- numbers.

CREATE SCHEMA IF NOT EXISTS skald;

CREATE TABLE skald.content (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug               text        NOT NULL UNIQUE,
    owner              text        NOT NULL,
    type               text        NOT NULL,
    visibility         text        NOT NULL DEFAULT 'acl_only',
    active_version_id  uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT content_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,49}$'),
    CONSTRAINT content_type_known  CHECK (type IN (
        'shiny', 'quarto_static', 'rmarkdown_static', 'plumber', 'fastapi', 'data')),
    CONSTRAINT content_visibility_known CHECK (visibility IN (
        'acl_only', 'all_authenticated', 'anonymous'))
);

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

-- ACLs are projected into a synthesized ContainerProxy AccessControl at request time, so
-- authorization needs no upstream change. Superseded versions carry the content item's
-- current ACL, not a snapshot -- a revoked grant takes effect immediately, including for
-- someone holding a container started on an older version.
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
