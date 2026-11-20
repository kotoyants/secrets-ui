package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kotoyants/secrets-ui/internal/audit"
	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// auditPageSize is the number of events per page of the Audit page.
const auditPageSize = 50

const dateLayout = "2006-01-02"

// auditFilter is the Audit page query: actor email and secret name substrings,
// an exact action, and an inclusive UTC date range.
type auditFilter struct {
	User, Secret, Action, From, To string
}

func (f auditFilter) query(before int64) string {
	q := url.Values{}
	for k, v := range map[string]string{"user": f.User, "secret": f.Secret, "action": f.Action, "from": f.From, "to": f.To} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if before > 0 {
		q.Set("before", idStr(before))
	}
	return q.Encode()
}

type auditDetail struct{ Key, Value string }

type auditRow struct {
	Event   db.AuditEvent
	Link    string // target page, if any
	Details []auditDetail
}

type auditPage struct {
	Filter   auditFilter
	Actions  []string
	Rows     []auditRow
	Error    string
	Filtered bool   // any filter or page offset applied
	NextURL  string // older events, if any
}

func (h *handlers) adminAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := auditFilter{
		User: strings.TrimSpace(q.Get("user")), Secret: strings.TrimSpace(q.Get("secret")),
		Action: q.Get("action"), From: q.Get("from"), To: q.Get("to"),
	}
	page := auditPage{Filter: f, Actions: audit.Persisted()}
	params, err := f.params(q.Get("before"))
	if err != nil {
		page.Error = err.Error()
		h.render(w, r, http.StatusBadRequest, "admin_audit", pageData{Nav: "audit", Data: page})
		return
	}
	page.Filtered = f != (auditFilter{}) || params.BeforeID > 0
	params.Lim = auditPageSize + 1
	events, err := h.store.ListAuditEvents(r.Context(), params)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if len(events) > auditPageSize {
		events = events[:auditPageSize]
		page.NextURL = "/admin/audit?" + f.query(events[len(events)-1].ID)
	}
	for _, e := range events {
		page.Rows = append(page.Rows, auditRow{Event: e, Link: auditLink(e), Details: auditDetails(e.Details)})
	}
	h.render(w, r, http.StatusOK, "admin_audit", pageData{Nav: "audit", Data: page})
}

// params validates the filter and converts it to query parameters.
func (f auditFilter) params(before string) (db.ListAuditEventsParams, error) {
	p := db.ListAuditEventsParams{Actor: f.User, Secret: f.Secret}
	if f.Action != "" {
		if !audit.IsPersisted(f.Action) {
			return p, fmt.Errorf("unknown action %q", f.Action)
		}
		p.Action = f.Action
	}
	if before != "" {
		id, err := strconv.ParseInt(before, 10, 64)
		if err != nil || id <= 0 {
			return p, fmt.Errorf("invalid page")
		}
		p.BeforeID = id
	}
	if f.From != "" {
		t, err := time.Parse(dateLayout, f.From)
		if err != nil {
			return p, fmt.Errorf("invalid start date")
		}
		p.Since = &t
	}
	if f.To != "" {
		t, err := time.Parse(dateLayout, f.To)
		if err != nil {
			return p, fmt.Errorf("invalid end date")
		}
		t = t.AddDate(0, 0, 1) // inclusive: events before the next day
		p.Until = &t
	}
	return p, nil
}

// auditLink is the admin page of an event's target (it may no longer exist).
func auditLink(e db.AuditEvent) string {
	if _, err := strconv.ParseInt(e.TargetID, 10, 64); err != nil {
		return ""
	}
	switch e.TargetType {
	case "secret":
		return "/secrets/" + e.TargetID
	case "role":
		return "/admin/roles/" + e.TargetID
	case "user":
		return "/admin/users/" + e.TargetID
	}
	return ""
}

// auditDetails decodes event details into sorted key/value pairs for display.
// Lists are joined with commas; empty values are omitted.
func auditDetails(raw []byte) []auditDetail {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var out []auditDetail
	for k, v := range m {
		if s := detailString(v); s != "" {
			out = append(out, auditDetail{Key: strings.ReplaceAll(k, "_", " "), Value: s})
		}
	}
	slices.SortFunc(out, func(a, b auditDetail) int { return strings.Compare(a.Key, b.Key) })
	return out
}

func detailString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			if s := detailString(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		b, _ := json.Marshal(x)
		return string(b)
	}
	return fmt.Sprint(v)
}
