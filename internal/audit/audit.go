// Package audit writes security-relevant events as structured JSON lines to stdout
// and persists the admin-relevant ones (see Persisted) to the database for the
// Audit page. Audit events must never contain secret values.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// Actions.
const (
	ActionLogin       = "login"
	ActionLoginDenied = "login_denied"
	ActionLogout      = "logout"

	ActionSecretImport     = "secret.import"
	ActionSecretUnimport   = "secret.unimport"
	ActionSecretTagsUpdate = "secret.tags_update"
	ActionSecretReveal     = "secret.reveal"
	ActionSecretUpdate     = "secret.update"

	ActionRoleCreate = "role.create"
	ActionRoleUpdate = "role.update"
	ActionRoleDelete = "role.delete"

	ActionUserRoleAssign = "user.role_assign"
	ActionUserRoleRemove = "user.role_remove"
	ActionUserDisable    = "user.disable"
	ActionUserEnable     = "user.enable"
)

// Results.
const (
	ResultSuccess = "success"
	ResultDenied  = "denied"
	ResultError   = "error"
)

// Event is one audit record.
type Event struct {
	ActorID    int64
	ActorEmail string
	Action     string
	TargetType string
	TargetID   string
	// TargetLabel is the target's display name at the time of the event
	// (secret "namespace/name", role name, user email).
	TargetLabel string
	Result      string // defaults to ResultSuccess
	IP          string
	Details     map[string]any // must not contain secret values
}

// persisted lists the actions stored in the database (shown on the Audit page).
// Reveals and logins stay stdout-only.
var persisted = []string{
	ActionSecretUpdate, ActionSecretImport, ActionSecretUnimport, ActionSecretTagsUpdate,
	ActionRoleCreate, ActionRoleUpdate, ActionRoleDelete,
	ActionUserRoleAssign, ActionUserRoleRemove, ActionUserDisable, ActionUserEnable,
}

// Persisted returns the actions stored in the database, in display order.
func Persisted() []string { return slices.Clone(persisted) }

// IsPersisted reports whether action is stored in the database.
func IsPersisted(action string) bool { return slices.Contains(persisted, action) }

// Store is the database sink for persisted events (implemented by store.Store).
type Store interface {
	InsertAuditEvent(ctx context.Context, arg db.InsertAuditEventParams) error
}

// Logger writes audit events.
type Logger struct {
	l  *slog.Logger
	db Store
}

// New returns an audit logger writing through l.
func New(l *slog.Logger) *Logger { return &Logger{l: l} }

// WithStore returns a copy of a that also persists the actions in Persisted to st.
func (a *Logger) WithStore(st Store) *Logger { return &Logger{l: a.l, db: st} }

// Log writes e as a single "audit" log line with audit=true and, for persisted
// actions, stores it in the database. A failed insert is logged as an error but
// does not fail the caller: the change has already happened and the stdout line
// remains the source of truth.
func (a *Logger) Log(ctx context.Context, e Event) {
	if e.Result == "" {
		e.Result = ResultSuccess
	}
	a.write(ctx, e)
	if a.db != nil && IsPersisted(e.Action) {
		if err := a.persist(ctx, e); err != nil {
			a.l.ErrorContext(ctx, "persist audit event", "action", e.Action, "err", err)
		}
	}
}

func (a *Logger) persist(ctx context.Context, e Event) error {
	details := []byte("{}")
	if len(e.Details) > 0 {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return fmt.Errorf("encode details: %w", err)
		}
	}
	var actor *int64
	if e.ActorID != 0 {
		actor = &e.ActorID
	}
	// Detached from request cancellation: the change it records has already happened.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return a.db.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		ActorID: actor, ActorEmail: e.ActorEmail, Action: e.Action,
		TargetType: e.TargetType, TargetID: e.TargetID, TargetLabel: e.TargetLabel,
		Result: e.Result, Ip: e.IP, Details: details,
	})
}

func (a *Logger) write(ctx context.Context, e Event) {
	attrs := []slog.Attr{
		slog.Bool("audit", true),
		slog.String("action", e.Action),
		slog.String("result", e.Result),
	}
	if e.ActorID != 0 {
		attrs = append(attrs, slog.Int64("actor_id", e.ActorID))
	}
	if e.ActorEmail != "" {
		attrs = append(attrs, slog.String("actor_email", e.ActorEmail))
	}
	if e.TargetType != "" {
		attrs = append(attrs, slog.String("target_type", e.TargetType), slog.String("target_id", e.TargetID))
	}
	if e.TargetLabel != "" {
		attrs = append(attrs, slog.String("target_label", e.TargetLabel))
	}
	if e.IP != "" {
		attrs = append(attrs, slog.String("ip", e.IP))
	}
	if len(e.Details) > 0 {
		attrs = append(attrs, slog.Any("details", e.Details))
	}
	a.l.LogAttrs(ctx, slog.LevelInfo, "audit", attrs...)
}

// ClientIP returns the client address of r (host part of RemoteAddr).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
