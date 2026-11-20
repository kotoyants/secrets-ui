-- +goose Up
-- Persisted audit trail for the admin Audit page. Never contains secret values:
-- details hold key names, tags, role names and similar metadata only.
CREATE TABLE audit_events (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     BIGINT      REFERENCES users (id) ON DELETE SET NULL,
    actor_email  TEXT        NOT NULL,
    action       TEXT        NOT NULL CHECK (action <> ''),
    target_type  TEXT        NOT NULL DEFAULT '',
    target_id    TEXT        NOT NULL DEFAULT '',
    -- Display name of the target at the time of the event (secret namespace/name,
    -- role name, user email), so it survives renames and deletes.
    target_label TEXT        NOT NULL DEFAULT '',
    result       TEXT        NOT NULL,
    ip           TEXT        NOT NULL DEFAULT '',
    details      JSONB       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX audit_events_ts_idx ON audit_events (ts);

-- +goose Down
DROP TABLE audit_events;
