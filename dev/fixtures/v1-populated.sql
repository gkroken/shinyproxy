-- A populated V1 database, for testing that V2 migrates real data rather than an empty
-- schema (WORKPLAN-BUNDLES.md T0/T6).
--
-- Apply to a database that Flyway has migrated to V1 and nothing further. It inserts only;
-- it creates no schema and alters nothing, so it stays valid after V2 exists and can be used
-- to build a pre-V2 database on demand.
--
-- The rows are chosen for what V2 must not break, not for realism. Every one of them is a
-- shape spine #1 either paid to establish or was corrected into:
--
--   * content with several versions and an active pointer that is NOT the highest number,
--     because rollback moves it backwards and a migration that assumes max(version) is
--     active would silently re-point live content (ADR-0008).
--   * a superseded version row that still exists, because superseded is not disposable.
--   * content with no version at all, whose path is claimed and which serves 404. A NOT NULL
--     added to content_version, or an inner join in a migration, must not lose it.
--   * a retired path and an orphaned path (content_id IS NULL, from deleted content). The
--     orphan is the 410 reservation, and it is exactly what a cascade would quietly eat
--     (ADR-0011 rule 3).
--   * a three-segment path and a case-preserving path, so path_key/path divergence and the
--     COLLATE "C" column survive.
--   * a content_env row. The table exists and nothing writes it; V2 must not assume it is
--     empty, and #3 owns its encryption.
--   * audit_event rows with real jsonb detail, including one for content that no longer
--     exists, since subject_id is a UUID and carries no foreign key on purpose.
--
-- UUIDs are fixed so assertions can name them. They are literals, never generated here.

BEGIN;

-- ---------------------------------------------------------------- content

INSERT INTO skald.content (id, title, owner, type, visibility, created_at, updated_at) VALUES
    ('11111111-1111-4111-8111-111111111111', 'Quarterly report', 'alice', 'shiny',            'acl_only',          now() - interval '30 days', now() - interval '2 days'),
    ('22222222-2222-4222-8222-222222222222', 'Team dashboard',   'bob',   'shiny',            'all_authenticated', now() - interval '20 days', now() - interval '20 days'),
    ('33333333-3333-4333-8333-333333333333', 'ETL fetch A',      'alice', 'quarto_static',    'acl_only',          now() - interval '10 days', now() - interval '10 days'),
    ('44444444-4444-4444-8444-444444444444', 'Never versioned',  'carol', 'plumber',          'acl_only',          now() - interval '5 days',  now() - interval '5 days'),
    ('55555555-5555-4555-8555-555555555555', 'Rolled back',      'alice', 'rmarkdown_static', 'acl_only',          now() - interval '40 days', now() - interval '1 day');

-- ---------------------------------------------------------------- versions

-- 11111111 is on its newest version; 55555555 has been rolled back to v1 of three, which is
-- the case a migration inferring "active == max(version)" gets wrong.
INSERT INTO skald.content_version (id, content_id, version, image, spec_json, created_at, created_by) VALUES
    ('aaaaaaa1-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 1, 'registry:5000/quarterly:1', '{}'::jsonb,                     now() - interval '30 days', 'alice'),
    ('aaaaaaa1-0000-4000-8000-000000000002', '11111111-1111-4111-8111-111111111111', 2, 'registry:5000/quarterly:2', '{}'::jsonb,                     now() - interval '2 days',  'alice'),
    ('aaaaaaa2-0000-4000-8000-000000000001', '22222222-2222-4222-8222-222222222222', 1, 'registry:5000/dashboard:1', '{"note":"legacy spec_json"}'::jsonb, now() - interval '20 days', 'bob'),
    ('aaaaaaa3-0000-4000-8000-000000000001', '33333333-3333-4333-8333-333333333333', 1, 'registry:5000/etl-a:1',     '{}'::jsonb,                     now() - interval '10 days', 'alice'),
    ('aaaaaaa5-0000-4000-8000-000000000001', '55555555-5555-4555-8555-555555555555', 1, 'registry:5000/rolled:1',    '{}'::jsonb,                     now() - interval '40 days', 'alice'),
    ('aaaaaaa5-0000-4000-8000-000000000002', '55555555-5555-4555-8555-555555555555', 2, 'registry:5000/rolled:2',    '{}'::jsonb,                     now() - interval '12 days', 'alice'),
    ('aaaaaaa5-0000-4000-8000-000000000003', '55555555-5555-4555-8555-555555555555', 3, 'registry:5000/rolled:3',    '{}'::jsonb,                     now() - interval '3 days',  'alice');

UPDATE skald.content SET active_version_id = 'aaaaaaa1-0000-4000-8000-000000000002' WHERE id = '11111111-1111-4111-8111-111111111111';
UPDATE skald.content SET active_version_id = 'aaaaaaa2-0000-4000-8000-000000000001' WHERE id = '22222222-2222-4222-8222-222222222222';
UPDATE skald.content SET active_version_id = 'aaaaaaa3-0000-4000-8000-000000000001' WHERE id = '33333333-3333-4333-8333-333333333333';
UPDATE skald.content SET active_version_id = 'aaaaaaa5-0000-4000-8000-000000000001' WHERE id = '55555555-5555-4555-8555-555555555555';
-- 44444444 keeps active_version_id NULL on purpose.

-- ---------------------------------------------------------------- paths

-- Live paths, one per content. `Finance/QuarterlyReport` keeps the publisher's capitals
-- while path_key is the lower-case matching key; `etl/fetchFromA` is nested two deep and
-- `team/reports/q1` three, the maximum.
INSERT INTO skald.content_path (id, path, path_key, content_id, is_current, created_at, retired_at) VALUES
    ('cccccccc-0000-4000-8000-000000000001', 'Finance/QuarterlyReport', 'finance/quarterlyreport', '11111111-1111-4111-8111-111111111111', true,  now() - interval '2 days',  NULL),
    ('cccccccc-0000-4000-8000-000000000002', 'team/reports/q1',         'team/reports/q1',         '22222222-2222-4222-8222-222222222222', true,  now() - interval '20 days', NULL),
    ('cccccccc-0000-4000-8000-000000000003', 'etl/fetchFromA',          'etl/fetchfroma',          '33333333-3333-4333-8333-333333333333', true,  now() - interval '10 days', NULL),
    ('cccccccc-0000-4000-8000-000000000004', 'never-versioned',         'never-versioned',         '44444444-4444-4444-8444-444444444444', true,  now() - interval '5 days',  NULL),
    ('cccccccc-0000-4000-8000-000000000005', 'rolled-back',             'rolled-back',             '55555555-5555-4555-8555-555555555555', true,  now() - interval '40 days', NULL);

-- A retired path: 11111111 used to live here, and this row is the 301 source.
INSERT INTO skald.content_path (id, path, path_key, content_id, is_current, created_at, retired_at) VALUES
    ('cccccccc-0000-4000-8000-000000000006', 'finance/old-report', 'finance/old-report', '11111111-1111-4111-8111-111111111111', false, now() - interval '30 days', now() - interval '2 days');

-- Orphaned reservations: the content was deleted, the path stays and answers 410. content_id
-- is NULL by ON DELETE SET NULL, which is the row a cascade would have destroyed.
INSERT INTO skald.content_path (id, path, path_key, content_id, is_current, created_at, retired_at) VALUES
    ('cccccccc-0000-4000-8000-000000000007', 'deleted-thing',     'deleted-thing',     NULL, false, now() - interval '60 days', now() - interval '15 days'),
    ('cccccccc-0000-4000-8000-000000000008', 'gone/sub-document', 'gone/sub-document', NULL, false, now() - interval '55 days', now() - interval '15 days');

-- ---------------------------------------------------------------- ACLs

INSERT INTO skald.content_acl (id, content_id, principal_type, principal, permission, created_at) VALUES
    ('dddddddd-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'user',  'bob',      'viewer', now() - interval '25 days'),
    ('dddddddd-0000-4000-8000-000000000002', '11111111-1111-4111-8111-111111111111', 'group', 'viewers',  'viewer', now() - interval '25 days'),
    ('dddddddd-0000-4000-8000-000000000003', '11111111-1111-4111-8111-111111111111', 'user',  'carol',    'editor', now() - interval '20 days'),
    ('dddddddd-0000-4000-8000-000000000004', '33333333-3333-4333-8333-333333333333', 'group', 'analysts', 'viewer', now() - interval '9 days');
-- 22222222 is all_authenticated and needs none; 44444444 and 55555555 are owner-only.

-- ---------------------------------------------------------------- env

-- The table exists and nothing writes it. Encryption is spine #3's, before the first write
-- or injection feature; this row only proves V2 does not assume the table is empty.
INSERT INTO skald.content_env (id, content_id, key, value_encrypted, is_secret, created_at, updated_at) VALUES
    ('eeeeeeee-0000-4000-8000-000000000001', '11111111-1111-4111-8111-111111111111', 'REPORT_REGION', '\x00'::bytea, false, now() - interval '25 days', now() - interval '25 days');

-- ---------------------------------------------------------------- audit

-- subject_id is the content UUID and deliberately carries no foreign key, so history
-- outlives the content it describes. The last row refers to content that is already gone.
INSERT INTO skald.audit_event (actor, action, subject_type, subject_id, detail_json, at) VALUES
    ('alice', 'content.create',      'content', '11111111-1111-4111-8111-111111111111', '{"path":"finance/old-report","title":"Quarterly report","owner":"alice","type":"shiny","visibility":"acl_only"}'::jsonb, now() - interval '30 days'),
    ('alice', 'content.version.add', 'content', '11111111-1111-4111-8111-111111111111', '{"version":"1","image":"registry:5000/quarterly:1"}'::jsonb,                                                              now() - interval '30 days'),
    ('alice', 'content.activate',    'content', '11111111-1111-4111-8111-111111111111', '{"version":"1"}'::jsonb,                                                                                                 now() - interval '30 days'),
    ('alice', 'content.rename',      'content', '11111111-1111-4111-8111-111111111111', '{"from":"finance/old-report","to":"Finance/QuarterlyReport"}'::jsonb,                                                     now() - interval '2 days'),
    ('alice', 'content.activate',    'content', '55555555-5555-4555-8555-555555555555', '{"version":"1"}'::jsonb,                                                                                                 now() - interval '1 day'),
    ('admin', 'content.delete',      'content', '99999999-9999-4999-8999-999999999999', '{}'::jsonb,                                                                                                              now() - interval '15 days');

COMMIT;
