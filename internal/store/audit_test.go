package store

import (
	"slices"
	"testing"
	"time"

	"github.com/kotoyants/secrets-ui/internal/store/db"
)

func TestAuditEvents(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	u, _, err := s.LoginUser(ctx, LoginProfile{Email: "alice@corp.com"}, false)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(email, action, targetType, label string) {
		t.Helper()
		var actor *int64
		if email == u.Email {
			actor = &u.ID
		}
		if err := s.InsertAuditEvent(ctx, db.InsertAuditEventParams{
			ActorID: actor, ActorEmail: email, Action: action, TargetType: targetType,
			TargetID: "1", TargetLabel: label, Result: "success", Details: []byte(`{"tags":["a"]}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("alice@corp.com", "secret.update", "secret", "front/API")       // id 1
	insert("bob@corp.com", "role.create", "role", "front-api")             // id 2
	insert("alice@corp.com", "secret.tags_update", "secret", "back/db")    // id 3
	insert("Bob@Corp.com", "secret.import", "secret", "front/api-gateway") // id 4

	list := func(p db.ListAuditEventsParams) []int64 {
		t.Helper()
		if p.Lim == 0 {
			p.Lim = 100
		}
		events, err := s.ListAuditEvents(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		ids := []int64{}
		for _, e := range events {
			ids = append(ids, e.ID)
		}
		return ids
	}
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	tests := []struct {
		name string
		p    db.ListAuditEventsParams
		want []int64
	}{
		{"all newest first", db.ListAuditEventsParams{}, []int64{4, 3, 2, 1}},
		{"actor substring, case-insensitive", db.ListAuditEventsParams{Actor: "BOB@"}, []int64{4, 2}},
		{"action exact", db.ListAuditEventsParams{Action: "secret.update"}, []int64{1}},
		{"secret label substring, secrets only", db.ListAuditEventsParams{Secret: "api"}, []int64{4, 1}},
		{"combined", db.ListAuditEventsParams{Actor: "alice", Secret: "front"}, []int64{1}},
		{"keyset page", db.ListAuditEventsParams{BeforeID: 3, Lim: 1}, []int64{2}},
		{"limit", db.ListAuditEventsParams{Lim: 2}, []int64{4, 3}},
		{"since", db.ListAuditEventsParams{Since: &past}, []int64{4, 3, 2, 1}},
		{"since future", db.ListAuditEventsParams{Since: &future}, []int64{}},
		{"until past", db.ListAuditEventsParams{Until: &past}, []int64{}},
		{"until future", db.ListAuditEventsParams{Until: &future}, []int64{4, 3, 2, 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := list(tt.p); !slices.Equal(got, tt.want) {
				t.Errorf("ids = %v, want %v", got, tt.want)
			}
		})
	}

	// Deleting the actor keeps the event (actor_id becomes NULL, email stays).
	if _, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListAuditEvents(ctx, db.ListAuditEventsParams{Action: "secret.update", Lim: 1})
	if err != nil || len(events) != 1 || events[0].ActorID != nil || events[0].ActorEmail != "alice@corp.com" {
		t.Fatalf("after user delete: %+v, %v", events, err)
	}

	// Retention.
	if n, err := s.DeleteAuditEventsBefore(ctx, past); err != nil || n != 0 {
		t.Errorf("delete before past = %d, %v", n, err)
	}
	if n, err := s.DeleteAuditEventsBefore(ctx, future); err != nil || n != 4 {
		t.Errorf("delete before future = %d, %v", n, err)
	}
}

func TestAuditEventsRejectsNonObjectDetails(t *testing.T) {
	s := newStore(t)
	err := s.InsertAuditEvent(t.Context(), db.InsertAuditEventParams{
		ActorEmail: "a@x.com", Action: "role.create", Result: "success", Details: []byte(`[]`),
	})
	if err == nil {
		t.Fatal("array details accepted")
	}
}
