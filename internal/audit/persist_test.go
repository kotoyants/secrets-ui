package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kotoyants/secrets-ui/internal/store/db"
)

type fakeStore struct {
	got []db.InsertAuditEventParams
	err error
}

func (f *fakeStore) InsertAuditEvent(_ context.Context, p db.InsertAuditEventParams) error {
	f.got = append(f.got, p)
	return f.err
}

func TestPersistOnlySelectedActions(t *testing.T) {
	tests := []struct {
		action  string
		persist bool
	}{
		{ActionSecretUpdate, true}, {ActionSecretImport, true}, {ActionSecretUnimport, true},
		{ActionSecretTagsUpdate, true}, {ActionRoleCreate, true}, {ActionRoleUpdate, true},
		{ActionRoleDelete, true}, {ActionUserRoleAssign, true}, {ActionUserRoleRemove, true},
		{ActionUserDisable, true}, {ActionUserEnable, true},
		{ActionSecretReveal, false}, {ActionLogin, false}, {ActionLoginDenied, false}, {ActionLogout, false},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			st := &fakeStore{}
			New(slog.New(slog.DiscardHandler)).WithStore(st).Log(t.Context(), Event{Action: tt.action})
			if got := len(st.got) == 1; got != tt.persist {
				t.Errorf("persisted = %v, want %v", got, tt.persist)
			}
			if IsPersisted(tt.action) != tt.persist {
				t.Errorf("IsPersisted = %v", !tt.persist)
			}
		})
	}
}

func TestPersistFields(t *testing.T) {
	st := &fakeStore{}
	var buf bytes.Buffer
	New(slog.New(slog.NewJSONHandler(&buf, nil))).WithStore(st).Log(t.Context(), Event{
		ActorID: 7, ActorEmail: "a@x.com", Action: ActionSecretUpdate, TargetType: "secret", TargetID: "3",
		TargetLabel: "front/api", IP: "10.0.0.1", Details: map[string]any{"changed": []string{"TOKEN"}},
	})
	if len(st.got) != 1 {
		t.Fatalf("inserts = %d", len(st.got))
	}
	p := st.got[0]
	if p.ActorID == nil || *p.ActorID != 7 || p.ActorEmail != "a@x.com" || p.Action != ActionSecretUpdate ||
		p.TargetType != "secret" || p.TargetID != "3" || p.TargetLabel != "front/api" ||
		p.Result != ResultSuccess || p.Ip != "10.0.0.1" {
		t.Errorf("params = %+v", p)
	}
	var d map[string][]string
	if err := json.Unmarshal(p.Details, &d); err != nil || d["changed"][0] != "TOKEN" {
		t.Errorf("details = %s (%v)", p.Details, err)
	}
	if !strings.Contains(buf.String(), `"target_label":"front/api"`) {
		t.Errorf("stdout line missing target_label: %s", buf.String())
	}

	// No actor and no details: NULL actor, empty JSON object.
	New(slog.New(slog.DiscardHandler)).WithStore(st).Log(t.Context(), Event{Action: ActionRoleDelete})
	if p := st.got[1]; p.ActorID != nil || string(p.Details) != "{}" {
		t.Errorf("params = %+v, details %s", p, p.Details)
	}
}

func TestPersistFailureIsLoggedNotFatal(t *testing.T) {
	st := &fakeStore{err: errors.New("db down")}
	var buf bytes.Buffer
	New(slog.New(slog.NewJSONHandler(&buf, nil))).WithStore(st).Log(t.Context(), Event{Action: ActionRoleCreate})
	out := buf.String()
	if !strings.Contains(out, `"msg":"audit"`) || !strings.Contains(out, `"msg":"persist audit event"`) ||
		!strings.Contains(out, "db down") {
		t.Errorf("log = %s", out)
	}
}

type fakePruner struct {
	cutoffs chan time.Time
}

func (f *fakePruner) DeleteAuditEventsBefore(_ context.Context, ts time.Time) (int64, error) {
	f.cutoffs <- ts
	return 1, nil
}

func TestRunRetention(t *testing.T) {
	p := &fakePruner{cutoffs: make(chan time.Time, 10)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		RunRetention(ctx, p, 24*time.Hour, time.Millisecond, slog.New(slog.DiscardHandler))
		close(done)
	}()
	for range 2 { // runs at start, then on every tick
		select {
		case ts := <-p.cutoffs:
			if d := time.Since(ts); d < 24*time.Hour || d > 25*time.Hour {
				t.Errorf("cutoff %v ago, want ~24h", d)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("retention did not run")
		}
	}
	cancel()
	<-done
}

func TestRunRetentionDisabled(t *testing.T) {
	p := &fakePruner{cutoffs: make(chan time.Time, 1)}
	RunRetention(t.Context(), p, 0, time.Millisecond, slog.New(slog.DiscardHandler)) // returns immediately
	if len(p.cutoffs) != 0 {
		t.Error("pruned with retention disabled")
	}
}
