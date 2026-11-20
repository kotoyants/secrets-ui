-- name: InsertAuditEvent :exec
INSERT INTO audit_events (actor_id, actor_email, action, target_type, target_id, target_label, result, ip, details)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListAuditEvents :many
-- Newest first, keyset-paginated by id (before_id = 0 starts from the newest).
-- Empty text filters and NULL dates match everything; text filters are case-insensitive substrings.
SELECT id, ts, actor_id, actor_email, action, target_type, target_id, target_label, result, ip, details
FROM audit_events
WHERE (@before_id::bigint = 0 OR id < @before_id)
  AND (@actor::text = '' OR strpos(lower(actor_email), lower(@actor)) > 0)
  AND (@action::text = '' OR action = @action)
  AND (@secret::text = '' OR (target_type = 'secret' AND strpos(lower(target_label), lower(@secret)) > 0))
  AND (sqlc.narg(since)::timestamptz IS NULL OR ts >= sqlc.narg(since))
  AND (sqlc.narg(until)::timestamptz IS NULL OR ts < sqlc.narg(until))
ORDER BY id DESC
LIMIT @lim;

-- name: DeleteAuditEventsBefore :execrows
DELETE FROM audit_events WHERE ts < $1;
