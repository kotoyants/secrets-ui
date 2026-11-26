package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/kotoyants/secrets-ui/internal/provider"
)

// A secret value that holds a JSON config, or a JS config of the form
//
//	window.CONFIG = {...};   (also var/let/const X = ...; the object must be valid JSON)
//
// can be viewed and edited field by field ("Fields" tab). Each scalar inside it is a
// leaf addressed by a path such as links.join or items[0].url. Only leaf values can
// change: saving rewrites just the changed leaf tokens in place, so key order,
// formatting, escapes and the JS wrapper are kept byte for byte.

// leafType is the JSON type of a leaf.
type leafType string

const (
	leafString leafType = "string"
	leafNumber leafType = "number"
	leafBool   leafType = "boolean"
	leafNull   leafType = "null"
)

// leaf is one scalar inside a structured value. Start/End are the byte range of
// its JSON token within the whole value.
type leaf struct {
	Path       string
	Type       leafType
	Value      string // decoded string, or the literal text of a number/bool/null
	Start, End int
}

// structured is a value parsed for the Fields tab.
type structured struct {
	Wrapper string // e.g. "window.CONFIG = …;" for JS, "" for plain JSON
	Leaves  []leaf
}

// jsAssign matches the start of a JS config: an optional declaration keyword and
// an (optionally dotted) identifier being assigned.
var jsAssign = regexp.MustCompile(`^\s*(?:(?:var|let|const)\s+)?[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\s*=\s*`)

// jsTail is what may follow the object in a JS config.
var jsTail = regexp.MustCompile(`^\s*;?\s*$`)

// parseStructured parses v for the Fields tab. It reports false unless v is a JSON
// object or array (optionally wrapped in a JS assignment) with at least one leaf.
func parseStructured(v string) (*structured, bool) {
	start, wrapper := 0, ""
	if t := strings.TrimLeft(v, " \t\r\n"); !strings.HasPrefix(t, "{") && !strings.HasPrefix(t, "[") {
		m := jsAssign.FindStringIndex(v)
		if m == nil {
			return nil, false
		}
		start = m[1]
		wrapper = strings.TrimSpace(v[:start]) + " …"
	}
	body := v[start:]
	leaves, end, err := scanLeaves(body)
	if err != nil || len(leaves) == 0 {
		return nil, false
	}
	rest := body[end:]
	if wrapper == "" {
		if strings.TrimSpace(rest) != "" {
			return nil, false
		}
	} else {
		if !jsTail.MatchString(rest) {
			return nil, false
		}
		if strings.Contains(rest, ";") {
			wrapper += ";"
		}
	}
	for i := range leaves {
		leaves[i].Start += start
		leaves[i].End += start
	}
	return &structured{Wrapper: wrapper, Leaves: leaves}, true
}

// scanLeaves reads one JSON object or array from the start of s and returns its
// leaves and the offset just after it.
func scanLeaves(s string) ([]leaf, int, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()

	type frame struct {
		array bool
		path  string
		next  int    // next array index
		key   string // pending object key
		isKey bool   // next string token in this object is a key
	}
	var (
		stack  []*frame
		leaves []leaf
		prev   int // offset after the previous token
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, 0, err
		}
		end := int(dec.InputOffset())
		// Between tokens there is only whitespace and ':' / ','.
		start := prev + strings.IndexFunc(s[prev:end], func(r rune) bool {
			return !strings.ContainsRune(" \t\r\n:,", r)
		})
		prev = end

		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return leaves, end, nil
			}
			continue
		}
		if top != nil && !top.array && top.isKey {
			top.key, top.isKey = tok.(string), false
			continue
		}
		path := ""
		switch {
		case top == nil:
		case top.array:
			path = top.path + "[" + strconv.Itoa(top.next) + "]"
			top.next++
		default:
			path = joinPath(top.path, top.key)
			top.isKey = true
		}
		switch t := tok.(type) {
		case json.Delim: // '{' or '['
			stack = append(stack, &frame{array: t == '[', path: path, isKey: t == '{'})
			continue
		case string:
			leaves = append(leaves, leaf{Path: path, Type: leafString, Value: t, Start: start, End: end})
		case json.Number:
			leaves = append(leaves, leaf{Path: path, Type: leafNumber, Value: t.String(), Start: start, End: end})
		case bool:
			leaves = append(leaves, leaf{Path: path, Type: leafBool, Value: strconv.FormatBool(t), Start: start, End: end})
		case nil:
			leaves = append(leaves, leaf{Path: path, Type: leafNull, Value: "null", Start: start, End: end})
		}
		if top == nil {
			return nil, 0, errors.New("not an object or array")
		}
	}
}

var identRe = regexp.MustCompile(`^[A-Za-z_$][\w$-]*$`)

// joinPath appends object key k to path: a.b, or a["odd key"] when k is not identifier-like.
func joinPath(path, k string) string {
	if !identRe.MatchString(k) {
		return path + "[" + jsonString(k) + "]"
	}
	if path == "" {
		return k
	}
	return path + "." + k
}

var jsonNumberRe = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`)

// encodeLeaf returns the JSON token for a new value of l. Numbers and booleans keep
// their type (an invalid value is an error); a null leaf takes a JSON scalar as typed,
// or any other text as a string.
func encodeLeaf(l leaf, v string) (string, error) {
	switch l.Type {
	case leafNumber:
		v = strings.TrimSpace(v)
		if !jsonNumberRe.MatchString(v) {
			return "", errorf(l.Path + " must be a number.")
		}
		return v, nil
	case leafBool:
		v = strings.TrimSpace(v)
		if v != "true" && v != "false" {
			return "", errorf(l.Path + " must be true or false.")
		}
		return v, nil
	case leafNull:
		t := strings.TrimSpace(v)
		if t == "null" || t == "true" || t == "false" || jsonNumberRe.MatchString(t) {
			return t, nil
		}
	}
	return jsonString(v), nil
}

// applyLeaves returns value with the leaves whose new value (by index in s.Leaves)
// differs from the current one rewritten, and the paths that changed.
func applyLeaves(value string, s *structured, values map[int]string) (string, []string, error) {
	type edit struct {
		start, end int
		tok        string
	}
	var edits []edit
	var changed []string
	for i, l := range s.Leaves {
		v, ok := values[i]
		if !ok || v == l.Value {
			continue
		}
		tok, err := encodeLeaf(l, v)
		if err != nil {
			return "", nil, err
		}
		edits = append(edits, edit{l.Start, l.End, tok})
		changed = append(changed, l.Path)
	}
	slices.SortFunc(edits, func(a, b edit) int { return b.start - a.start })
	for _, e := range edits {
		value = value[:e.start] + e.tok + value[e.end:]
	}
	if len(edits) > 0 {
		if _, ok := parseStructured(value); !ok { // defensive: never write a broken config
			return "", nil, fmt.Errorf("fields: rewritten value no longer parses")
		}
	}
	return value, changed, nil
}

// ---- Fields tab (view and edit pages) ----------------------------------------

// fieldDoc is one structured secret key on the Fields tab.
type fieldDoc struct {
	Key     string
	Wrapper string
	Rows    []fieldRow
}

// fieldRow is one leaf. ID is unique on the page (for element ids); Leaf is its
// index within the key's leaves, posted back with the edit form.
type fieldRow struct {
	ID    int
	Leaf  int
	Path  string
	Type  leafType
	Value string
}

// buildFieldDocs returns a doc for each value that is a JSON/JS config, sorted by key.
// values must be valid UTF-8 (binary values are left out by the caller).
func buildFieldDocs(values map[string][]byte) []fieldDoc {
	var docs []fieldDoc
	id := 0
	for _, k := range slices.Sorted(maps.Keys(values)) {
		st, ok := parseStructured(string(values[k]))
		if !ok {
			continue
		}
		doc := fieldDoc{Key: k, Wrapper: st.Wrapper}
		for i, l := range st.Leaves {
			doc.Rows = append(doc.Rows, fieldRow{ID: id, Leaf: i, Path: l.Path, Type: l.Type, Value: l.Value})
			id++
		}
		docs = append(docs, doc)
	}
	return docs
}

// docKeys returns the secret keys shown on the Fields tab, for audit events.
func docKeys(docs []fieldDoc) []string {
	keys := make([]string, len(docs))
	for i, d := range docs {
		keys[i] = d.Key
	}
	return keys
}

// saveFields applies the Fields edit form: parallel "fk" (secret key), "fi" (leaf
// index) and "fv" (new value) lists. Only changed leaves are rewritten; other keys
// are untouched. Errors re-render the form with the submitted values.
func (h *handlers) saveFields(w http.ResponseWriter, r *http.Request, s *accessible, current *provider.SecretData) {
	page := newEditPage(s, current)
	page.Fields = true
	page.Version = r.PostForm.Get("version") // keep the version the user started from
	page.Docs = buildFieldDocs(textValues(current.Values))
	retry := func(err error) {
		_, msg, known := describeErr(err)
		if !known {
			h.log.ErrorContext(r.Context(), "fields save failed", "path", r.URL.Path, "err", err)
		}
		h.render(w, r, http.StatusOK, "secret_edit", pageData{Nav: "home", Data: page, Flash: &flash{Kind: "error", Msg: msg}})
	}

	keys, idx, vals := r.PostForm["fk"], r.PostForm["fi"], r.PostForm["fv"]
	if len(keys) != len(idx) || len(keys) != len(vals) {
		h.done(w, r, "/secrets/"+idStr(s.Row.ID)+"/edit?view=fields", "", errorf("Invalid form."))
		return
	}
	submitted := map[string]map[int]string{}
	for i, k := range keys {
		n, err := strconv.Atoi(idx[i])
		if err != nil {
			h.done(w, r, "/secrets/"+idStr(s.Row.ID)+"/edit?view=fields", "", errorf("Invalid form."))
			return
		}
		if submitted[k] == nil {
			submitted[k] = map[int]string{}
		}
		submitted[k][n] = strings.ReplaceAll(vals[i], "\r\n", "\n")
	}
	for d := range page.Docs { // show what the user typed if the form comes back
		for i, row := range page.Docs[d].Rows {
			if v, ok := submitted[page.Docs[d].Key][row.Leaf]; ok {
				page.Docs[d].Rows[i].Value = v
			}
		}
	}
	if page.Version != current.Version {
		retry(provider.ErrConflict)
		return
	}

	next := maps.Clone(current.Values)
	var changed []string
	for _, k := range slices.Sorted(maps.Keys(submitted)) {
		old, exists := current.Values[k]
		st, ok := parseStructured(string(old))
		if !exists || !ok {
			retry(errorf("Key " + k + " is no longer a JSON/JS config; reload the page."))
			return
		}
		v, paths, err := applyLeaves(string(old), st, submitted[k])
		if err != nil {
			retry(err)
			return
		}
		if len(paths) > 0 {
			next[k] = []byte(v)
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 {
		h.done(w, r, "/secrets/"+idStr(s.Row.ID)+"?view=fields", "No changes.", nil)
		return
	}
	if err := s.Provider.Update(r.Context(), s.Ref, &provider.SecretData{Values: next, Version: page.Version}); err != nil {
		retry(err)
		return
	}
	h.saved(w, r, s, current, changed, nil, nil, true)
}

// textValues returns the values that are valid UTF-8.
func textValues(values map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(values))
	for k, v := range values {
		if utf8.Valid(v) {
			out[k] = v
		}
	}
	return out
}
