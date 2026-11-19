package web

import (
	"errors"
	"maps"
	"strings"
	"testing"
)

func TestFormatText(t *testing.T) {
	values := map[string][]byte{
		"B":     []byte("plain value"),
		"A":     []byte("line1\nline2"),
		"HTML":  []byte("<a&b>"),
		"SPACE": []byte(" padded "),
		"QUOTE": []byte(`"quoted"`),
		"EMPTY": {},
		"TAB":   []byte("a\tb"),
		"EQ":    []byte("x=y#z"),
	}
	tests := []struct {
		f    textFormat
		want string
	}{
		{formatJSON, `{
  "A": "line1\nline2",
  "B": "plain value",
  "EMPTY": "",
  "EQ": "x=y#z",
  "HTML": "<a&b>",
  "QUOTE": "\"quoted\"",
  "SPACE": " padded ",
  "TAB": "a\tb"
}
`},
		{formatEnv, `A="line1\nline2"
B=plain value
EMPTY=
EQ=x=y#z
HTML=<a&b>
QUOTE="\"quoted\""
SPACE=" padded "
TAB="a\tb"
`},
	}
	for _, tt := range tests {
		t.Run(string(tt.f), func(t *testing.T) {
			got := formatText(tt.f, values)
			if got != tt.want {
				t.Fatalf("formatText:\n%s\nwant:\n%s", got, tt.want)
			}
			back, err := parseText(tt.f, got)
			if err != nil {
				t.Fatal(err)
			}
			if !maps.EqualFunc(back, values, func(a, b []byte) bool { return string(a) == string(b) }) {
				t.Fatalf("round trip = %q", back)
			}
		})
	}
	if got := formatText(formatJSON, nil); got != "{}\n" {
		t.Errorf("empty json = %q", got)
	}
	if got := formatText(formatEnv, nil); got != "" {
		t.Errorf("empty env = %q", got)
	}
}

func TestParseText(t *testing.T) {
	tests := []struct {
		name    string
		f       textFormat
		in      string
		want    map[string]string
		wantErr string
	}{
		{"json scalars", formatJSON, "{\"A\": \"x\", \"N\": 42, \"F\": 1.50, \"B\": true}",
			map[string]string{"A": "x", "N": "42", "F": "1.50", "B": "true"}, ""},
		{"json crlf", formatJSON, "{\r\n\"A\": \"x\"\r\n}\r\n", map[string]string{"A": "x"}, ""},
		{"json empty", formatJSON, " {} ", map[string]string{}, ""},
		{"json null", formatJSON, `{"A": null}`, nil, "The value of A must be a string."},
		{"json nested", formatJSON, `{"A": {"b": "c"}}`, nil, "The value of A must be a string."},
		{"json array", formatJSON, `{"A": ["s3cr3t"]}`, nil, "The value of A must be a string."},
		{"json not object", formatJSON, `["A"]`, nil, "Invalid JSON: expected an object"},
		{"json duplicate", formatJSON, `{"A": "1", "A": "2"}`, nil, "Key A is listed twice."},
		{"json empty key", formatJSON, `{"": "1"}`, nil, "key names must not be empty"},
		{"json syntax", formatJSON, `{"A": "1",}`, nil, "Invalid JSON at offset"},
		{"json trailing", formatJSON, `{"A": "1"} {}`, nil, "unexpected content after the object"},
		{"json unterminated", formatJSON, `{"A": "1"`, nil, "Invalid JSON"},
		{"json blank", formatJSON, "", nil, "Invalid JSON"},
		{"env basic", formatEnv, "# comment\n\n A = b c \nB=\nC=x=y\nD=\"q\\n\"\r\nE='raw'",
			map[string]string{"A": "b c", "B": "", "C": "x=y", "D": "q\n", "E": "'raw'"}, ""},
		{"env empty", formatEnv, "\n\n", map[string]string{}, ""},
		{"env no equals", formatEnv, "A=1\nNOPE", nil, "Line 2: expected KEY=value."},
		{"env no key", formatEnv, "=x", nil, "Line 1: expected KEY=value."},
		{"env bad quote", formatEnv, `A="s3cr3t`, nil, "Line 1: invalid quoted value for A"},
		{"env duplicate", formatEnv, "A=1\nA=2", nil, "Key A is listed twice."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseText(tt.f, tt.in)
			if tt.wantErr != "" {
				var ue userError
				if !errors.As(err, &ue) || !strings.Contains(ue.msg, tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				if strings.Contains(ue.msg, "s3cr3t") {
					t.Fatalf("error quotes the value: %q", ue.msg)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			for k, v := range tt.want {
				if string(got[k]) != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestParseTextFormat(t *testing.T) {
	for in, want := range map[string]textFormat{"json": formatJSON, "env": formatEnv, "": formatJSON, "yaml": formatJSON} {
		if got := parseTextFormat(in); got != want {
			t.Errorf("parseTextFormat(%q) = %q, want %q", in, got, want)
		}
	}
}
