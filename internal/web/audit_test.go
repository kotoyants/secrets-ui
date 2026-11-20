package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// auditRows returns the actions listed in the Audit page table, in order.
func auditRows(body string) []string {
	var out []string
	for _, part := range strings.Split(body, "<td><code>")[1:] {
		out = append(out, part[:strings.Index(part, "</code>")])
	}
	return out
}

func TestAdminAudit(t *testing.T) {
	f := newSecretsFixture(t)
	bob := f.userID(t, "bob@corp.com")

	if resp, _ := f.do(t, f.bob, http.MethodGet, "/admin/audit", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin GET /admin/audit = %d, want 403", resp.StatusCode)
	}

	// Admin actions (persisted) and a reveal (stdout only).
	f.post(t, f.admin, "/admin/roles", url.Values{"name": {"ops"}, "permission": {"read"}, "tags": {"ops"}})
	f.post(t, f.admin, "/admin/users/"+bob+"/roles", url.Values{"role_id": {f.roleID(t, "ops")}})
	f.post(t, f.admin, "/admin/secrets/"+f.synced, url.Values{"tags": {"front, ops"}})
	f.post(t, f.admin, "/admin/users/"+bob+"/disable", nil)
	f.post(t, f.admin, "/admin/users/"+bob+"/enable", nil)
	ver := f.editVersion(t, f.carol, f.api)
	f.post(t, f.carol, "/secrets/"+f.api, url.Values{"version": {ver}, "key": {"TOKEN", "NEW"}, "value": {"changed-value", "n1"}})
	f.post(t, f.admin, "/secrets/"+f.api+"/reveal", url.Values{"key": {"TOKEN"}})

	resp, body := f.do(t, f.admin, http.MethodGet, "/admin/audit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit page = %d", resp.StatusCode)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("audit page is cacheable")
	}
	want := []string{"secret.update", "user.enable", "user.disable", "secret.tags_update", "user.role_assign", "role.create"}
	if got := auditRows(body); !slices.Equal(got, want) {
		t.Errorf("rows = %v, want %v", got, want)
	}
	mustContain(t, body,
		`href="/admin/audit" aria-current="page">Audit</a>`,
		`<a href="/secrets/`+f.api+`">front/api</a>`,       // secret label + link
		`<a href="/secrets/`+f.synced+`">front/synced</a>`, // tags update label
		`<a href="/admin/users/`+bob+`">bob@corp.com</a>`,  // user target label
		`>ops</a>`, // role label
		`<span class="muted">added:</span> NEW`, `<span class="muted">changed:</span> TOKEN`,
		`<span class="muted">tags:</span> front, ops`,
		"carol@corp.com",
	)
	for _, leak := range []string{apiValue, "changed-value", "n1<", "secret.reveal</code>"} {
		if strings.Contains(body, leak) {
			t.Errorf("audit page contains %q", leak)
		}
	}

	// Filters.
	for _, tt := range []struct {
		query string
		want  []string
	}{
		{"action=role.create", []string{"role.create"}},
		{"user=CAROL", []string{"secret.update"}},
		{"secret=synced", []string{"secret.tags_update"}},
		{"secret=ops", nil}, // role named "ops" is not a secret
		{"user=admin&action=user.disable", []string{"user.disable"}},
		{"from=" + time.Now().UTC().Format(dateLayout) + "&to=" + time.Now().UTC().Format(dateLayout), want},
		{"to=" + time.Now().UTC().AddDate(0, 0, -1).Format(dateLayout), nil},
		{"from=" + time.Now().UTC().AddDate(0, 0, 1).Format(dateLayout), nil},
	} {
		_, body := f.do(t, f.admin, http.MethodGet, "/admin/audit?"+tt.query, nil)
		if got := auditRows(body); !slices.Equal(got, tt.want) {
			t.Errorf("%s: rows = %v, want %v", tt.query, got, tt.want)
		}
		if len(tt.want) == 0 {
			mustContain(t, body, "No events.")
		}
	}

	// Invalid filters.
	for _, q := range []string{"from=yesterday", "to=2026-13-01", "action=secret.reveal", "before=abc"} {
		resp, body := f.do(t, f.admin, http.MethodGet, "/admin/audit?"+q, nil)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "flash-error") {
			t.Errorf("%s = %d, want 400 with an error", q, resp.StatusCode)
		}
	}
}

func TestAdminAuditPagination(t *testing.T) {
	a := newFullApp(t)
	admin := a.loginAs(t, "admin@corp.com")
	for range auditPageSize + 5 {
		if err := a.store.InsertAuditEvent(t.Context(), db.InsertAuditEventParams{
			ActorEmail: "x@corp.com", Action: "role.create", TargetType: "role", TargetID: "1",
			TargetLabel: "r", Result: "success", Details: []byte("{}"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, body := a.do(t, admin, http.MethodGet, "/admin/audit?action=role.create", nil)
	if n := len(auditRows(body)); n != auditPageSize {
		t.Fatalf("first page rows = %d", n)
	}
	next := "/admin/audit?action=role.create&amp;before=6"
	mustContain(t, body, `href="`+next+`"`, "Older events")
	_, body = a.do(t, admin, http.MethodGet, strings.ReplaceAll(next, "&amp;", "&"), nil)
	if n := len(auditRows(body)); n != 5 {
		t.Errorf("second page rows = %d, want 5", n)
	}
	if strings.Contains(body, "Older events") {
		t.Error("last page links to older events")
	}
	mustContain(t, body, "Reset filters")
}

func TestAuditDetails(t *testing.T) {
	got := auditDetails([]byte(`{"tags":["a","b"],"removed":[],"role_id":3,"ref":"k8s:front/api","x":null,"m":{"k":"v"}}`))
	want := []auditDetail{{"m", `{"k":"v"}`}, {"ref", "k8s:front/api"}, {"role id", "3"}, {"tags", "a, b"}}
	if !slices.Equal(got, want) {
		t.Errorf("details = %v, want %v", got, want)
	}
	if auditDetails([]byte("not json")) != nil {
		t.Error("invalid JSON should give no details")
	}
}
