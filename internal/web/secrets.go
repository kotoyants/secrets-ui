package web

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/kotoyants/secrets-ui/internal/audit"
	"github.com/kotoyants/secrets-ui/internal/auth"
	"github.com/kotoyants/secrets-ui/internal/authz"
	"github.com/kotoyants/secrets-ui/internal/provider"
	"github.com/kotoyants/secrets-ui/internal/store"
	"github.com/kotoyants/secrets-ui/internal/store/db"
)

// newKeyRows is the number of empty "add key" rows on the edit form.
const newKeyRows = 3

func (h *handlers) secretRoutes(r chi.Router) {
	r.Use(auth.RequireUser)
	r.Get("/", h.secretList)
	r.Get("/secrets/{id}", h.secretView)
	r.Post("/secrets/{id}/reveal", h.secretReveal)
	r.Get("/secrets/{id}/edit", h.secretEditForm)
	r.Post("/secrets/{id}", h.secretSave)
}

// accessible is an imported secret the current user may read.
type accessible struct {
	Row      db.GetSecretRow
	Ref      provider.SecretRef
	Provider provider.Provider
	Group    string
	Name     string
	CanWrite bool
}

// label is the secret's display name for audit events.
func (s *accessible) label() string { return describeLabel(s.Provider, s.Ref) }

// loadSecret loads secret {id} and checks read access. Secrets the user cannot
// read are reported as not found, so their existence is not revealed.
func (h *handlers) loadSecret(r *http.Request) (*accessible, error) {
	id, err := pathID(r, "id")
	if err != nil {
		return nil, err
	}
	row, err := h.store.GetSecret(r.Context(), id)
	if err != nil {
		return nil, err
	}
	subj := authz.FromPrincipal(auth.FromContext(r.Context()))
	if !subj.CanRead(row.Tags) {
		return nil, store.ErrNotFound
	}
	loc, err := decodeLocator(row.Locator)
	if err != nil {
		return nil, err
	}
	p, err := h.providers.Get(row.Provider)
	if err != nil {
		return nil, err
	}
	ref := provider.SecretRef{Provider: row.Provider, Locator: loc}
	group, name := p.Describe(ref)
	return &accessible{Row: row, Ref: ref, Provider: p, Group: group, Name: name, CanWrite: subj.CanWrite(row.Tags)}, nil
}

// ---- list ------------------------------------------------------------------

type listRow struct {
	ID       int64
	Group    string
	Name     string
	Tags     []string
	CanWrite bool
}

type listPage struct {
	Secrets  []listRow
	Tree     []listGroup // Secrets grouped by namespace, for the tree view
	View     string      // "tree" (default) or "table"
	Total    int         // readable secrets before filtering
	Groups   []string
	AllTags  []string
	Tag      string
	Group    string
	Query    string
	HasRoles bool
}

func (h *handlers) secretList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.FromContext(ctx)
	subj := authz.FromPrincipal(p)
	rows, err := h.store.ListSecrets(ctx)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	page := listPage{Tag: q.Get("tag"), Group: q.Get("ns"), Query: strings.TrimSpace(q.Get("q")), View: "tree"}
	if q.Get("view") == "table" {
		page.View = "table"
	}
	for _, ro := range p.Roles {
		if len(ro.Tags) > 0 || (ro.Builtin && ro.Name == store.RoleAdmin) {
			page.HasRoles = true
		}
	}

	groups, allTags := map[string]bool{}, map[string]bool{}
	for _, s := range authz.Filter(subj, authz.Read, rows, func(s db.ListSecretsRow) []string { return s.Tags }) {
		loc, err := decodeLocator(s.Locator)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		ref := provider.SecretRef{Provider: s.Provider, Locator: loc}
		row := listRow{ID: s.ID, Name: ref.String(), Tags: s.Tags, CanWrite: subj.CanWrite(s.Tags)}
		if prov, err := h.providers.Get(s.Provider); err == nil {
			row.Group, row.Name = prov.Describe(ref)
		}
		page.Total++
		groups[row.Group] = true
		for _, t := range s.Tags {
			allTags[t] = true
		}
		if page.Tag != "" && !slices.Contains(s.Tags, page.Tag) ||
			page.Group != "" && row.Group != page.Group ||
			page.Query != "" && !strings.Contains(strings.ToLower(row.Name), strings.ToLower(page.Query)) {
			continue
		}
		page.Secrets = append(page.Secrets, row)
	}
	slices.SortFunc(page.Secrets, func(a, b listRow) int {
		return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Name, b.Name))
	})
	for _, row := range page.Secrets { // sorted by group, so each group is contiguous
		if n := len(page.Tree); n == 0 || page.Tree[n-1].Name != row.Group {
			page.Tree = append(page.Tree, listGroup{Name: row.Group})
		}
		g := &page.Tree[len(page.Tree)-1]
		g.Secrets = append(g.Secrets, row)
	}
	page.Groups = slices.Sorted(maps.Keys(groups))
	page.AllTags = slices.Sorted(maps.Keys(allTags))
	h.render(w, r, http.StatusOK, "secrets", pageData{Nav: "home", Data: page})
}

// listGroup is one namespace (provider group) of the tree view.
type listGroup struct {
	Name    string
	Secrets []listRow
}

// ViewURL is the list URL with the current filters in view v ("tree" or "table").
func (p listPage) ViewURL(v string) string {
	q := url.Values{}
	for k, val := range map[string]string{"q": p.Query, "ns": p.Group, "tag": p.Tag} {
		if val != "" {
			q.Set(k, val)
		}
	}
	if v != "tree" {
		q.Set("view", v)
	}
	if len(q) == 0 {
		return "/"
	}
	return "/?" + q.Encode()
}

// ---- view & reveal ---------------------------------------------------------

type keyView struct {
	Index    int
	Key      string
	Revealed bool
	Value    string
	Binary   bool // value is not valid UTF-8 and is shown base64-encoded
}

type secretPage struct {
	ID        int64
	Group     string
	Name      string
	Tags      []string
	CanWrite  bool
	ManagedBy string
	Missing   bool
	Keys      []keyView
	HasBinary bool // some value is binary, so the plaintext view is unavailable
	HasFields bool // some value is a JSON/JS config, so the Fields tab is available

	// Plaintext view (?view=plaintext): the whole secret as one document.
	Plaintext bool
	Format    textFormat
	Text      string

	// Fields view (?view=fields): each JSON/JS config value field by field.
	Fields bool
	Docs   []fieldDoc
}

// BaseURL is the page URL, for the Key/value | Plaintext | Fields tabs.
func (p secretPage) BaseURL() string { return "/secrets/" + idStr(p.ID) }

// displayValue returns v as text, or base64 if it is binary.
func displayValue(v []byte) (string, bool) {
	if utf8.Valid(v) {
		return string(v), false
	}
	return base64.StdEncoding.EncodeToString(v), true
}

// buildSecretPage reads the secret from its provider. Values are included only
// for keys where reveal returns true (reveal may be nil).
func (h *handlers) buildSecretPage(r *http.Request, s *accessible, reveal func(key string) bool) (secretPage, error) {
	page := secretPage{ID: s.Row.ID, Group: s.Group, Name: s.Name, Tags: s.Row.Tags, CanWrite: s.CanWrite}
	data, err := s.Provider.Get(r.Context(), s.Ref)
	switch {
	case errors.Is(err, provider.ErrNotFound):
		page.Missing = true
		return page, nil
	case err != nil:
		return page, err
	}
	page.ManagedBy = data.ManagedBy
	for i, k := range data.SortedKeys() {
		kv := keyView{Index: i, Key: k, Binary: !utf8.Valid(data.Values[k])}
		page.HasBinary = page.HasBinary || kv.Binary
		if !kv.Binary && !page.HasFields {
			_, page.HasFields = parseStructured(string(data.Values[k]))
		}
		if reveal != nil && reveal(k) {
			kv.Revealed = true
			kv.Value, _ = displayValue(data.Values[k])
		}
		page.Keys = append(page.Keys, kv)
	}
	return page, nil
}

// secretView renders a secret with masked values, with ?view=plaintext the
// whole secret as one revealed (and audited) document in ?format=json|env, or with
// ?view=fields its JSON/JS config values field by field (revealed and audited).
func (h *handlers) secretView(w http.ResponseWriter, r *http.Request) {
	s, err := h.loadSecret(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	view := r.URL.Query().Get("view")
	plaintext, fields := view == "plaintext", view == "fields"
	page, err := h.buildSecretPage(r, s, func(string) bool { return plaintext || fields })
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if fields && page.HasFields {
		values := make(map[string][]byte, len(page.Keys))
		for _, k := range page.Keys {
			if !k.Binary {
				values[k.Key] = []byte(k.Value)
			}
		}
		page.Fields, page.Docs = true, buildFieldDocs(values)
		h.logAudit(r, audit.ActionSecretReveal, "secret", idStr(s.Row.ID), s.label(), map[string]any{
			"ref": s.Ref.String(), "keys": docKeys(page.Docs), "view": "fields",
		})
	}
	if plaintext && !page.Missing && !page.HasBinary {
		page.Plaintext = true
		page.Format = parseTextFormat(r.URL.Query().Get("format"))
		values := make(map[string][]byte, len(page.Keys))
		names := make([]string, len(page.Keys))
		for i, k := range page.Keys {
			values[k.Key], names[i] = []byte(k.Value), k.Key
		}
		page.Text = formatText(page.Format, values)
		h.logAudit(r, audit.ActionSecretReveal, "secret", idStr(s.Row.ID), s.label(), map[string]any{
			"ref": s.Ref.String(), "keys": names, "view": "plaintext",
		})
	}
	// Per-key values are only ever sent through the reveal endpoint.
	for i := range page.Keys {
		page.Keys[i].Revealed, page.Keys[i].Value = false, ""
	}
	h.render(w, r, http.StatusOK, "secret", pageData{Nav: "home", Data: page})
}

// secretReveal reveals one key ("key") or every key ("all"). Parameters come from
// the form body or the query string. For htmx it returns out-of-band fragments:
// value cells for the view page, or prefilled textareas when "for=edit" (binary
// values are skipped there, since they can't be edited as text). Without
// JavaScript it renders the full view page. "for=copy" returns one key's value as
// plain text, for double-click copy on a masked field. Every reveal is audited.
func (h *handlers) secretReveal(w http.ResponseWriter, r *http.Request) {
	s, err := h.loadSecret(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	all := r.FormValue("all") != ""
	key := r.FormValue("key")
	page, err := h.buildSecretPage(r, s, func(k string) bool { return all || k == key })
	if err != nil {
		h.fail(w, r, err)
		return
	}
	htmx := r.Header.Get("HX-Request") == "true"
	edit := htmx && r.FormValue("for") == "edit"
	cp := r.FormValue("for") == "copy"
	if cp && all {
		h.fail(w, r, errorf("Copy takes a single key."))
		return
	}
	var revealed []keyView
	for _, k := range page.Keys {
		if k.Revealed && (!edit || !k.Binary) {
			revealed = append(revealed, k)
		}
	}
	if !all && len(revealed) == 0 {
		h.fail(w, r, store.ErrNotFound)
		return
	}
	attrs := map[string]any{"ref": s.Ref.String()}
	if all {
		names := make([]string, len(revealed))
		for i, k := range revealed {
			names[i] = k.Key
		}
		attrs["keys"] = names
	} else {
		attrs["key"] = key
	}
	if cp {
		attrs["copy"] = true
	}
	h.logAudit(r, audit.ActionSecretReveal, "secret", idStr(s.Row.ID), s.label(), attrs)

	switch {
	case cp:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, revealed[0].Value)
	case edit:
		h.renderFragment(w, r, "secret_edit", "edit-values", revealed)
	case htmx:
		h.renderFragment(w, r, "secret", "revealed-values", revealed)
	default:
		h.render(w, r, http.StatusOK, "secret", pageData{Nav: "home", Data: page})
	}
}

func (h *handlers) renderFragment(w http.ResponseWriter, r *http.Request, page, name string, data any) {
	var buf bytes.Buffer
	if err := pages[page].ExecuteTemplate(&buf, name, data); err != nil {
		h.log.ErrorContext(r.Context(), "render fragment", "page", page, "fragment", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// ---- edit ------------------------------------------------------------------

type editKey struct {
	Index  int
	Key    string
	Binary bool
}

type editPage struct {
	ID        int64
	Group     string
	Name      string
	ManagedBy string
	Version   string
	Keys      []editKey
	NewRows   []int
	HasBinary bool // some value is binary, so plaintext editing is unavailable
	HasFields bool // some value is a JSON/JS config, so the Fields tab is available

	// Plaintext editing (?view=plaintext): the whole secret as one document.
	Plaintext bool
	Format    textFormat
	Text      string

	// Fields editing (?view=fields): each JSON/JS config value field by field.
	Fields bool
	Docs   []fieldDoc
}

func (h *handlers) loadWritable(w http.ResponseWriter, r *http.Request) (*accessible, *provider.SecretData, bool) {
	s, err := h.loadSecret(r)
	if err != nil {
		h.fail(w, r, err)
		return nil, nil, false
	}
	if !s.CanWrite {
		h.render(w, r, http.StatusForbidden, "error", pageData{Error: "You can view this secret but not change it."})
		return nil, nil, false
	}
	data, err := s.Provider.Get(r.Context(), s.Ref)
	if err != nil {
		h.fail(w, r, err)
		return nil, nil, false
	}
	return s, data, true
}

func (h *handlers) secretEditForm(w http.ResponseWriter, r *http.Request) {
	s, data, ok := h.loadWritable(w, r)
	if !ok {
		return
	}
	page := newEditPage(s, data)
	if r.URL.Query().Get("view") == "fields" && page.HasFields {
		page.Fields, page.Docs = true, buildFieldDocs(textValues(data.Values))
		h.logAudit(r, audit.ActionSecretReveal, "secret", idStr(s.Row.ID), s.label(), map[string]any{
			"ref": s.Ref.String(), "keys": docKeys(page.Docs), "view": "fields", "for": "edit",
		})
	}
	if r.URL.Query().Get("view") == "plaintext" && !page.HasBinary {
		page.Plaintext = true
		page.Format = parseTextFormat(r.URL.Query().Get("format"))
		page.Text = formatText(page.Format, data.Values)
		h.logAudit(r, audit.ActionSecretReveal, "secret", idStr(s.Row.ID), s.label(), map[string]any{
			"ref": s.Ref.String(), "keys": data.SortedKeys(), "view": "plaintext", "for": "edit",
		})
	}
	h.render(w, r, http.StatusOK, "secret_edit", pageData{Nav: "home", Data: page})
}

// BaseURL is the page URL, for the Key/value | Plaintext | Fields tabs.
func (p editPage) BaseURL() string { return "/secrets/" + idStr(p.ID) + "/edit" }

func newEditPage(s *accessible, data *provider.SecretData) editPage {
	page := editPage{ID: s.Row.ID, Group: s.Group, Name: s.Name, ManagedBy: data.ManagedBy, Version: data.Version}
	for i, k := range data.SortedKeys() {
		bin := !utf8.Valid(data.Values[k])
		page.HasBinary = page.HasBinary || bin
		if !bin && !page.HasFields {
			_, page.HasFields = parseStructured(string(data.Values[k]))
		}
		page.Keys = append(page.Keys, editKey{Index: i, Key: k, Binary: bin})
	}
	for i := range newKeyRows {
		page.NewRows = append(page.NewRows, i)
	}
	return page
}

// secretSave applies the edit form. Existing keys keep their value when the field
// is left blank; keys in "delete" are removed; new rows with a key are added.
func (h *handlers) secretSave(w http.ResponseWriter, r *http.Request) {
	s, current, ok := h.loadWritable(w, r)
	if !ok {
		return
	}
	back := "/secrets/" + idStr(s.Row.ID)
	if err := r.ParseForm(); err != nil {
		h.done(w, r, back+"/edit", "", errorf("Invalid form."))
		return
	}
	switch r.PostForm.Get("view") {
	case "plaintext":
		h.savePlaintext(w, r, s, current)
		return
	case "fields":
		h.saveFields(w, r, s, current)
		return
	}
	version := r.PostForm.Get("version")
	if version != current.Version {
		h.done(w, r, back+"/edit", "", provider.ErrConflict)
		return
	}

	keys, values := r.PostForm["key"], r.PostForm["value"]
	if len(keys) != len(values) {
		h.done(w, r, back+"/edit", "", errorf("Invalid form."))
		return
	}
	next := maps.Clone(current.Values)
	var changed, added, removed []string
	for i, k := range keys {
		k = strings.TrimSpace(k)
		v := strings.ReplaceAll(values[i], "\r\n", "\n")
		if k == "" {
			continue // unused "new key" row
		}
		_, exists := current.Values[k]
		switch {
		case exists && v == "":
			// blank = keep current value
		case exists:
			if !bytes.Equal(next[k], []byte(v)) {
				changed = append(changed, k)
			}
			next[k] = []byte(v)
		default:
			if _, dup := next[k]; dup {
				h.done(w, r, back+"/edit", "", errorf("Key "+k+" is listed twice."))
				return
			}
			added = append(added, k)
			next[k] = []byte(v)
		}
	}
	for _, k := range r.PostForm["delete"] {
		if _, ok := next[k]; ok {
			delete(next, k)
			removed = append(removed, k)
		}
	}
	if len(changed)+len(added)+len(removed) == 0 {
		h.done(w, r, back, "No changes.", nil)
		return
	}

	err := s.Provider.Update(r.Context(), s.Ref, &provider.SecretData{Values: next, Version: version})
	if err != nil {
		h.done(w, r, back+"/edit", "", err)
		return
	}
	h.saved(w, r, s, current, changed, added, removed, false)
}

// saved audits a successful update and redirects to the secret (to the Fields tab if fields is set).
func (h *handlers) saved(w http.ResponseWriter, r *http.Request, s *accessible, current *provider.SecretData,
	changed, added, removed []string, fields bool) {
	h.logAudit(r, audit.ActionSecretUpdate, "secret", idStr(s.Row.ID), s.label(), map[string]any{
		"ref": s.Ref.String(), "changed": changed, "added": added, "removed": removed,
	})
	msg := "Secret saved."
	if current.ManagedBy != "" {
		msg += " Note: it is managed by " + current.ManagedBy + ", which may overwrite your change."
	}
	back := "/secrets/" + idStr(s.Row.ID)
	if fields {
		back += "?view=fields"
	}
	h.done(w, r, back, msg, nil)
}

// savePlaintext applies the plaintext edit form: the document replaces the whole
// secret (keys missing from it are deleted). With "convert" set it only re-renders
// the form with the document converted to that format. Parse and save errors
// re-render the form with the submitted text, so edits are not lost.
func (h *handlers) savePlaintext(w http.ResponseWriter, r *http.Request, s *accessible, current *provider.SecretData) {
	page := newEditPage(s, current)
	if page.HasBinary {
		h.done(w, r, "/secrets/"+idStr(s.Row.ID)+"/edit", "", errorf("This secret has binary values; edit it as key/value."))
		return
	}
	page.Plaintext = true
	page.Version = r.PostForm.Get("version") // keep the version the user started from
	page.Format = parseTextFormat(r.PostForm.Get("format"))
	page.Text = r.PostForm.Get("text")
	retry := func(err error) {
		_, msg, known := describeErr(err)
		if !known {
			h.log.ErrorContext(r.Context(), "plaintext save failed", "path", r.URL.Path, "err", err)
		}
		h.render(w, r, http.StatusOK, "secret_edit", pageData{Nav: "home", Data: page, Flash: &flash{Kind: "error", Msg: msg}})
	}

	next, err := parseText(page.Format, page.Text)
	if err != nil {
		retry(err)
		return
	}
	if to := r.PostForm.Get("convert"); to != "" {
		page.Format = parseTextFormat(to)
		page.Text = formatText(page.Format, next)
		h.render(w, r, http.StatusOK, "secret_edit", pageData{Nav: "home", Data: page})
		return
	}
	if page.Version != current.Version {
		retry(provider.ErrConflict)
		return
	}
	var changed, added, removed []string
	for _, k := range slices.Sorted(maps.Keys(next)) {
		old, exists := current.Values[k]
		switch {
		case !exists:
			added = append(added, k)
		case !bytes.Equal(old, next[k]):
			changed = append(changed, k)
		}
	}
	for _, k := range current.SortedKeys() {
		if _, ok := next[k]; !ok {
			removed = append(removed, k)
		}
	}
	if len(changed)+len(added)+len(removed) == 0 {
		h.done(w, r, "/secrets/"+idStr(s.Row.ID), "No changes.", nil)
		return
	}
	if err := s.Provider.Update(r.Context(), s.Ref, &provider.SecretData{Values: next, Version: page.Version}); err != nil {
		retry(err)
		return
	}
	h.saved(w, r, s, current, changed, added, removed, false)
}
