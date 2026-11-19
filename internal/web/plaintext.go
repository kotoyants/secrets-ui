package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// A secret can be viewed and edited as one plaintext document, in one of two formats:
//
//	json: a flat object {"KEY": "value"}, pretty-printed with sorted keys.
//	env:  one KEY=value per line. A value that would not survive as-is (newlines,
//	      control characters, surrounding spaces, a leading quote) is written as a
//	      JSON string literal: KEY="line1\nline2". Blank lines and #-comments are ignored.
//
// Both are only for text values; secrets with binary values can't use plaintext.
type textFormat string

const (
	formatJSON textFormat = "json"
	formatEnv  textFormat = "env"
)

// parseTextFormat returns the format named s, defaulting to JSON.
func parseTextFormat(s string) textFormat {
	if textFormat(s) == formatEnv {
		return formatEnv
	}
	return formatJSON
}

// jsonString encodes s as a JSON string literal without HTML escaping.
func jsonString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(buf.String(), "\n")
}

// formatText renders values (all valid UTF-8) as a document in format f.
func formatText(f textFormat, values map[string][]byte) string {
	keys := slices.Sorted(maps.Keys(values))
	var b strings.Builder
	if f == formatEnv {
		for _, k := range keys {
			v := string(values[k])
			if envNeedsQuote(v) {
				v = jsonString(v)
			}
			b.WriteString(k + "=" + v + "\n")
		}
		return b.String()
	}
	if len(keys) == 0 {
		return "{}\n"
	}
	b.WriteString("{\n")
	for i, k := range keys {
		b.WriteString("  " + jsonString(k) + ": " + jsonString(string(values[k])))
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// envNeedsQuote reports whether v must be written as a quoted literal in env format.
func envNeedsQuote(v string) bool {
	if v != strings.TrimSpace(v) || strings.HasPrefix(v, `"`) {
		return true
	}
	return strings.ContainsFunc(v, unicode.IsControl)
}

// parseText parses a document in format f. Errors are meant for the user and
// never quote values.
func parseText(f textFormat, text string) (map[string][]byte, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if f == formatEnv {
		return parseEnv(text)
	}
	return parseJSON(text)
}

func parseEnv(text string) (map[string][]byte, error) {
	out := map[string][]byte{}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n := i + 1
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return nil, errorf(fmt.Sprintf("Line %d: expected KEY=value.", n))
		}
		if strings.HasPrefix(v, `"`) {
			var s string
			if err := json.Unmarshal([]byte(v), &s); err != nil {
				return nil, errorf(fmt.Sprintf("Line %d: invalid quoted value for %s (use JSON string escapes).", n, k))
			}
			v = s
		}
		if _, dup := out[k]; dup {
			return nil, errorf("Key " + k + " is listed twice.")
		}
		out[k] = []byte(v)
	}
	return out, nil
}

func parseJSON(text string) (map[string][]byte, error) {
	invalid := func(err error) error {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return errorf(fmt.Sprintf("Invalid JSON at offset %d.", se.Offset))
		}
		return errorf("Invalid JSON: expected an object of \"KEY\": \"value\" pairs.")
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, invalid(err)
	}
	out := map[string][]byte{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, invalid(err)
		}
		k, _ := tok.(string)
		if k == "" {
			return nil, errorf("Invalid JSON: key names must not be empty.")
		}
		if tok, err = dec.Token(); err != nil {
			return nil, invalid(err)
		}
		var v string
		switch t := tok.(type) {
		case string:
			v = t
		case json.Number:
			v = t.String()
		case bool:
			v = fmt.Sprint(t)
		default: // null, object or array
			return nil, errorf("The value of " + k + " must be a string.")
		}
		if _, dup := out[k]; dup {
			return nil, errorf("Key " + k + " is listed twice.")
		}
		out[k] = []byte(v)
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, invalid(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errorf("Invalid JSON: unexpected content after the object.")
	}
	return out, nil
}
