PRAGMA application_id = 0x53454D44; -- SEMD
PRAGMA user_version = 1;

CREATE TABLE durable_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;
INSERT INTO durable_state VALUES (1, 0);

CREATE TABLE label (
    id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_uid TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    mechanism_text TEXT,
    evidence_step_ids TEXT NOT NULL CHECK (json_type(evidence_step_ids) = 'array'),
    labeller TEXT NOT NULL,
    taxonomy_version INTEGER NOT NULL,
    confidence REAL CHECK (confidence BETWEEN 0 AND 1),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE
) STRICT;

CREATE TABLE adjudication (
    id TEXT PRIMARY KEY,
    label_ids TEXT NOT NULL CHECK (json_type(label_ids) = 'array'),
    target_type TEXT NOT NULL,
    target_uid TEXT NOT NULL,
    field TEXT NOT NULL,
    final_value TEXT NOT NULL,
    adjudicator TEXT NOT NULL,
    reason TEXT,
    taxonomy_version INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL UNIQUE
) STRICT;

-- Explicit duplicate checks also refuse INSERT OR REPLACE on connections
-- where SQLite's recursive triggers are disabled.
CREATE TRIGGER label_no_replace BEFORE INSERT ON label
WHEN EXISTS (SELECT 1 FROM label WHERE id = NEW.id OR revision = NEW.revision)
BEGIN SELECT RAISE(ABORT, 'label is insert-only'); END;
CREATE TRIGGER label_no_update BEFORE UPDATE ON label
BEGIN SELECT RAISE(ABORT, 'label is insert-only'); END;
CREATE TRIGGER label_no_delete BEFORE DELETE ON label
BEGIN SELECT RAISE(ABORT, 'label is insert-only'); END;
CREATE TRIGGER adjudication_no_replace BEFORE INSERT ON adjudication
WHEN EXISTS (SELECT 1 FROM adjudication WHERE id = NEW.id OR revision = NEW.revision)
BEGIN SELECT RAISE(ABORT, 'adjudication is insert-only'); END;
CREATE TRIGGER adjudication_no_update BEFORE UPDATE ON adjudication
BEGIN SELECT RAISE(ABORT, 'adjudication is insert-only'); END;
CREATE TRIGGER adjudication_no_delete BEFORE DELETE ON adjudication
BEGIN SELECT RAISE(ABORT, 'adjudication is insert-only'); END;

CREATE TABLE link (
    id TEXT PRIMARY KEY,
    from_type TEXT NOT NULL CHECK (from_type IN ('session', 'segment')),
    from_id TEXT NOT NULL,
    change_id TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('trailer', 'commit', 'push', 'branch', 'mention', 'semantic')),
    evidence TEXT NOT NULL CHECK (evidence IN ('produced', 'mentioned')),
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1)
) STRICT;

CREATE TABLE lane (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    root_session_id TEXT NOT NULL,
    work_item_id TEXT
) STRICT;

CREATE TABLE work_item (
    id TEXT PRIMARY KEY,
    tracker TEXT NOT NULL,
    ref TEXT NOT NULL,
    value_class TEXT,
    size TEXT,
    priority TEXT,
    opened_at INTEGER NOT NULL,
    closed_at INTEGER
) STRICT;

CREATE TABLE change (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT NOT NULL,
    opened_at INTEGER NOT NULL,
    merged_at INTEGER,
    reverted_at INTEGER
) STRICT;

CREATE TABLE outcome (
    id TEXT PRIMARY KEY,
    change_id TEXT NOT NULL,
    ci_on_merge INTEGER CHECK (ci_on_merge IN (0, 1)),
    later_fix_change_id TEXT,
    escaped_defect INTEGER CHECK (escaped_defect IN (0, 1)),
    survival_30d INTEGER CHECK (survival_30d IN (0, 1)),
    window_closed_at INTEGER
) STRICT;

CREATE TABLE intervention (
    id TEXT PRIMARY KEY,
    lever TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    primary_metric TEXT NOT NULL,
    guardrails TEXT NOT NULL,
    preregistered_at INTEGER NOT NULL
) STRICT;

CREATE TABLE assignment (
    id TEXT PRIMARY KEY,
    intervention_id TEXT NOT NULL,
    unit_type TEXT NOT NULL,
    unit_id TEXT NOT NULL,
    arm TEXT NOT NULL,
    assigned_at INTEGER NOT NULL
) STRICT;

CREATE TABLE column_class (
    table_name TEXT NOT NULL,
    column_name TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('categorical', 'body')),
    PRIMARY KEY (table_name, column_name)
) STRICT;
INSERT INTO column_class VALUES
    ('durable_state', 'singleton', 'categorical'),
    ('durable_state', 'revision', 'categorical'),
    ('label', 'id', 'categorical'),
    ('label', 'target_type', 'categorical'),
    ('label', 'target_uid', 'categorical'),
    ('label', 'field', 'categorical'),
    ('label', 'value', 'categorical'),
    ('label', 'mechanism_text', 'body'),
    ('label', 'evidence_step_ids', 'categorical'),
    ('label', 'labeller', 'categorical'),
    ('label', 'taxonomy_version', 'categorical'),
    ('label', 'confidence', 'categorical'),
    ('label', 'created_at', 'categorical'),
    ('label', 'revision', 'categorical'),
    ('adjudication', 'id', 'categorical'),
    ('adjudication', 'label_ids', 'categorical'),
    ('adjudication', 'target_type', 'categorical'),
    ('adjudication', 'target_uid', 'categorical'),
    ('adjudication', 'field', 'categorical'),
    ('adjudication', 'final_value', 'categorical'),
    ('adjudication', 'adjudicator', 'categorical'),
    ('adjudication', 'reason', 'body'),
    ('adjudication', 'taxonomy_version', 'categorical'),
    ('adjudication', 'created_at', 'categorical'),
    ('adjudication', 'revision', 'categorical'),
    ('link', 'id', 'categorical'),
    ('link', 'from_type', 'categorical'),
    ('link', 'from_id', 'categorical'),
    ('link', 'change_id', 'categorical'),
    ('link', 'method', 'categorical'),
    ('link', 'evidence', 'categorical'),
    ('link', 'confidence', 'categorical'),
    ('lane', 'id', 'categorical'),
    ('lane', 'title', 'body'),
    ('lane', 'root_session_id', 'categorical'),
    ('lane', 'work_item_id', 'categorical'),
    ('work_item', 'id', 'categorical'),
    ('work_item', 'tracker', 'categorical'),
    ('work_item', 'ref', 'categorical'),
    ('work_item', 'value_class', 'categorical'),
    ('work_item', 'size', 'categorical'),
    ('work_item', 'priority', 'categorical'),
    ('work_item', 'opened_at', 'categorical'),
    ('work_item', 'closed_at', 'categorical'),
    ('change', 'id', 'categorical'),
    ('change', 'repo', 'categorical'),
    ('change', 'kind', 'categorical'),
    ('change', 'ref', 'categorical'),
    ('change', 'opened_at', 'categorical'),
    ('change', 'merged_at', 'categorical'),
    ('change', 'reverted_at', 'categorical'),
    ('outcome', 'id', 'categorical'),
    ('outcome', 'change_id', 'categorical'),
    ('outcome', 'ci_on_merge', 'categorical'),
    ('outcome', 'later_fix_change_id', 'categorical'),
    ('outcome', 'escaped_defect', 'categorical'),
    ('outcome', 'survival_30d', 'categorical'),
    ('outcome', 'window_closed_at', 'categorical'),
    ('intervention', 'id', 'categorical'),
    ('intervention', 'lever', 'categorical'),
    ('intervention', 'hypothesis', 'body'),
    ('intervention', 'primary_metric', 'categorical'),
    ('intervention', 'guardrails', 'body'),
    ('intervention', 'preregistered_at', 'categorical'),
    ('assignment', 'id', 'categorical'),
    ('assignment', 'intervention_id', 'categorical'),
    ('assignment', 'unit_type', 'categorical'),
    ('assignment', 'unit_id', 'categorical'),
    ('assignment', 'arm', 'categorical'),
    ('assignment', 'assigned_at', 'categorical'),
    ('column_class', 'table_name', 'categorical'),
    ('column_class', 'column_name', 'categorical'),
    ('column_class', 'class', 'categorical');
