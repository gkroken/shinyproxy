-- Skald V2: bundles, build attempts, the version link, and the artifact ledger.
--
-- WORKPLAN-BUNDLES.md T6 ("V2 and lifecycle"); states and transitions are
-- spec/lifecycle-v1.json's and are not restated here. Forward-only. V1 is not altered
-- except for ONE nullable column on content_version, so every V1 row, id, path and
-- constraint survives, and V1's own checksum is untouched.
--
-- What is enforced HERE rather than only in Java, and why each one is worth a constraint:
--   * one QUEUED build per content item (a partial unique index): the supersede decision
--     of 2026-10-01 is a database fact, so two concurrent requests cannot both queue;
--   * the idempotency key is unique per content item and never expires (decision 5);
--   * a terminal state has a finish time, a running state has a lease, a success has an
--     image, a rejection names its rule: a row cannot claim a state it does not carry;
--   * content_version.build_id is UNIQUE: exactly one version per successful build.
-- What is NOT here: the transition graph itself. A CHECK cannot see the previous row, and
-- a trigger that re-encodes the graph would be a second copy of spec/lifecycle-v1.json to
-- drift; transitions are fenced UPDATEs in the coordinator (WHERE state = ... AND
-- lease_generation = ...), tested there.

-- One accepted upload. Its bytes are immutable once its receipt is committed.
CREATE TABLE skald.bundle (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id       uuid        NOT NULL REFERENCES skald.content (id) ON DELETE CASCADE,
    created_by       text        NOT NULL,
    state            text        NOT NULL DEFAULT 'UPLOADING',
    -- The raw upload as stored: server-generated object key, its digest and size.
    object_key       text        UNIQUE,
    object_sha256    text,
    object_bytes     bigint,
    -- What validation established: the manifest's digest and the inventory's totals.
    manifest_sha256  text,
    inventory_files  integer,
    inventory_bytes  bigint,
    -- A REJECTED bundle names the rule (BundleRule) that refused it.
    rejection_rule   text,
    rejection_detail text,
    upload_deadline  timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    CONSTRAINT bundle_state_known CHECK (state IN (
        'UPLOADING', 'VALIDATING', 'VALIDATED', 'REJECTED')),
    CONSTRAINT bundle_terminal_has_time CHECK (
        (state IN ('VALIDATED', 'REJECTED')) = (finished_at IS NOT NULL)),
    CONSTRAINT bundle_rejected_names_rule CHECK (
        (state = 'REJECTED') = (rejection_rule IS NOT NULL)),
    CONSTRAINT bundle_validated_is_complete CHECK (
        state <> 'VALIDATED' OR (object_key IS NOT NULL AND object_sha256 IS NOT NULL
            AND object_bytes IS NOT NULL AND manifest_sha256 IS NOT NULL
            AND inventory_files IS NOT NULL AND inventory_bytes IS NOT NULL)),
    CONSTRAINT bundle_digests_hex CHECK (
        (object_sha256 IS NULL OR object_sha256 ~ '^[0-9a-f]{64}$')
        AND (manifest_sha256 IS NULL OR manifest_sha256 ~ '^[0-9a-f]{64}$')),
    CONSTRAINT bundle_sizes_nonnegative CHECK (
        coalesce(object_bytes, 0) >= 0 AND coalesce(inventory_files, 0) >= 0
        AND coalesce(inventory_bytes, 0) >= 0)
);
CREATE INDEX bundle_content_idx ON skald.bundle (content_id);

-- One execution ATTEMPT. A retry is a new row with retry_of; a terminal state is final.
CREATE TABLE skald.build (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id         uuid        NOT NULL REFERENCES skald.content (id) ON DELETE CASCADE,
    bundle_id          uuid        NOT NULL REFERENCES skald.bundle (id) ON DELETE CASCADE,
    retry_of           uuid        REFERENCES skald.build (id) ON DELETE SET NULL,
    created_by         text        NOT NULL,
    -- Scoped to one content item; kept for the life of the row (decision 2026-10-01: keys
    -- are never expired, so a late HTTP retry behaves exactly as an early one).
    idempotency_key    text        NOT NULL,
    -- SHA-256 over the canonical inputs. Same key + same fingerprint returns the attempt;
    -- same key + different fingerprint is a 409.
    input_fingerprint  text        NOT NULL,
    state              text        NOT NULL DEFAULT 'QUEUED',
    -- Set when a newer request for the same content cancelled this one while QUEUED
    -- (decision 2026-10-01: a new request supersedes the queued one).
    superseded_by      uuid        REFERENCES skald.build (id) ON DELETE SET NULL,
    cancel_requested_at timestamptz,
    recipe             jsonb       NOT NULL DEFAULT '{}'::jsonb,
    effective_limits   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- The lease. generation is monotonic: every claim bumps it, and every state change a
    -- worker makes is conditional on the generation it was given, so a worker that lost its
    -- lease is fenced rather than merged.
    lease_owner        text,
    lease_expires_at   timestamptz,
    lease_generation   bigint      NOT NULL DEFAULT 0,
    worker_handle      text,
    deadline_at        timestamptz,
    output_image       text,
    error_code         text,
    error_detail       text,
    log_cursor         bigint      NOT NULL DEFAULT 0,
    log_complete       boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    started_at         timestamptz,
    publishing_at      timestamptz,
    finished_at        timestamptz,
    CONSTRAINT build_idempotency UNIQUE (content_id, idempotency_key),
    CONSTRAINT build_state_known CHECK (state IN (
        'QUEUED', 'RUNNING', 'PUBLISHING',
        'SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'INTERRUPTED')),
    CONSTRAINT build_terminal_has_time CHECK (
        (state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'INTERRUPTED'))
            = (finished_at IS NOT NULL)),
    CONSTRAINT build_running_is_leased CHECK (
        state NOT IN ('RUNNING', 'PUBLISHING')
            OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL
                AND lease_generation > 0)),
    CONSTRAINT build_succeeded_has_image CHECK (state <> 'SUCCEEDED' OR output_image IS NOT NULL),
    CONSTRAINT build_key_bounded CHECK (
        length(idempotency_key) BETWEEN 1 AND 200 AND idempotency_key ~ '^[\x21-\x7e]+$'),
    CONSTRAINT build_fingerprint_hex CHECK (input_fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT build_not_its_own_retry CHECK (retry_of IS NULL OR retry_of <> id),
    CONSTRAINT build_superseded_is_cancelled CHECK (
        superseded_by IS NULL OR state = 'CANCELLED')
);
-- The supersede rule, held by the database: at most one QUEUED attempt per content item.
CREATE UNIQUE INDEX build_one_queued_per_content ON skald.build (content_id)
    WHERE state = 'QUEUED';
CREATE INDEX build_queue_order ON skald.build (created_at) WHERE state = 'QUEUED';
CREATE INDEX build_active_by_actor ON skald.build (created_by)
    WHERE state IN ('QUEUED', 'RUNNING', 'PUBLISHING');
CREATE INDEX build_content_idx ON skald.build (content_id);

-- A managed version names the build that produced it. Old direct-image rows keep NULL.
ALTER TABLE skald.content_version
    ADD COLUMN build_id uuid UNIQUE REFERENCES skald.build (id);

-- The ledger and outbox of everything the platform put into object storage or a registry.
-- Not foreign keys on purpose: a record must SURVIVE the deletion of its content so that
-- cleanup can still find what to remove (the subject ids are kept as plain values).
-- One table with a state column, where the plan sketched `artifact` and `artifact_gc`: a
-- second table would mean moving a row between them in the content-deletion transaction,
-- and a record can then exist in neither or both; a state change cannot.
CREATE TABLE skald.artifact (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                 text        NOT NULL,
    ref                  text        NOT NULL UNIQUE,
    subject_content_id   uuid        NOT NULL,
    subject_bundle_id    uuid,
    subject_build_id     uuid,
    subject_version_id   uuid,
    digest               text,
    pinned               boolean     NOT NULL DEFAULT false,
    retain_until         timestamptz,
    state                text        NOT NULL DEFAULT 'LIVE',
    delete_requested_at  timestamptz,
    deleted_at           timestamptz,
    delete_attempts      integer     NOT NULL DEFAULT 0,
    last_error           text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT artifact_kind_known CHECK (kind IN ('bundle_object', 'build_log', 'image')),
    CONSTRAINT artifact_state_known CHECK (state IN ('LIVE', 'DELETE_PENDING', 'DELETED')),
    CONSTRAINT artifact_pending_has_time CHECK (
        state = 'LIVE' OR delete_requested_at IS NOT NULL),
    CONSTRAINT artifact_deleted_has_time CHECK ((state = 'DELETED') = (deleted_at IS NOT NULL))
);
CREATE INDEX artifact_cleanup_queue ON skald.artifact (delete_requested_at)
    WHERE state = 'DELETE_PENDING';
CREATE INDEX artifact_subject_content_idx ON skald.artifact (subject_content_id);
