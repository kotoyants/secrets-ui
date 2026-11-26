package web

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cfgJS   = "window.CONFIG = {\"VITE_API_AUTH_SUFFIX\":\"/auth\",\"VITE_API_URL\":\"\",\"N\":1.5,\"ON\":true,\"X\":null};\n"
	cfgJSON = `{"links":{"join":"https://app.dev.example"},"list":[{"u":"a"},"bé"],"odd key":1}`
)

func TestParseStructured(t *testing.T) {
	type want struct {
		wrapper string
		paths   []string
		values  []string
	}
	tests := []struct {
		name string
		in   string
		ok   bool
		want want
	}{
		{"js config", cfgJS, true, want{"window.CONFIG = …;",
			[]string{"VITE_API_AUTH_SUFFIX", "VITE_API_URL", "N", "ON", "X"},
			[]string{"/auth", "", "1.5", "true", "null"}}},
		{"nested json", cfgJSON, true, want{"",
			[]string{"links.join", "list[0].u", "list[1]", `["odd key"]`},
			[]string{"https://app.dev.example", "a", "bé", "1"}}},
		{"top-level array", " [1, \"a\"] \n", true, want{"", []string{"[0]", "[1]"}, []string{"1", "a"}}},
		{"var no semicolon", "var cfg = {\"a\": \"b\"}", true, want{"var cfg = …", []string{"a"}, []string{"b"}}},
		{"const dotted", "const a.b = {\"a\": \"b\"};", true, want{"const a.b = …;", []string{"a"}, []string{"b"}}},
		{"plain string", "hello", false, want{}},
		{"json scalar", `"hello"`, false, want{}},
		{"number", "42", false, want{}},
		{"empty object", "{}", false, want{}},
		{"loose js", "window.C = {a: 'b'};", false, want{}},
		{"trailing code", "window.C = {\"a\":\"b\"}; alert(1)", false, want{}},
		{"trailing json", `{"a":"b"} {}`, false, want{}},
		{"truncated", `{"a":"b"`, false, want{}},
		{"not assignment", `foo({"a":"b"})`, false, want{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, ok := parseStructured(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			var paths, values []string
			for _, l := range st.Leaves {
				paths = append(paths, l.Path)
				values = append(values, l.Value)
			}
			if st.Wrapper != tt.want.wrapper || !slices.Equal(paths, tt.want.paths) || !slices.Equal(values, tt.want.values) {
				t.Fatalf("got wrapper %q paths %q values %q, want %+v", st.Wrapper, paths, values, tt.want)
			}
		})
	}
}

func TestApplyLeaves(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		values  map[int]string
		want    string
		changed []string
		wantErr string
	}{
		{"js: string and empty", cfgJS, map[int]string{0: "/auth2", 1: "https://x/<a&b>"},
			"window.CONFIG = {\"VITE_API_AUTH_SUFFIX\":\"/auth2\",\"VITE_API_URL\":\"https://x/<a&b>\",\"N\":1.5,\"ON\":true,\"X\":null};\n",
			[]string{"VITE_API_AUTH_SUFFIX", "VITE_API_URL"}, ""},
		{"unchanged values keep their escapes", cfgJSON, map[int]string{0: "https://app.dev.example", 2: "bé"},
			cfgJSON, nil, ""},
		{"nested and escapes", cfgJSON, map[int]string{1: "line1\n\"q\""},
			`{"links":{"join":"https://app.dev.example"},"list":[{"u":"line1\n\"q\""},"bé"],"odd key":1}`,
			[]string{"list[0].u"}, ""},
		{"number and bool keep type", cfgJS, map[int]string{2: " -2e3 ", 3: "false"},
			"window.CONFIG = {\"VITE_API_AUTH_SUFFIX\":\"/auth\",\"VITE_API_URL\":\"\",\"N\":-2e3,\"ON\":false,\"X\":null};\n",
			[]string{"N", "ON"}, ""},
		{"null takes scalar", cfgJS, map[int]string{4: "7"}, strings.Replace(cfgJS, "null", "7", 1), []string{"X"}, ""},
		{"null takes string", cfgJS, map[int]string{4: "abc"}, strings.Replace(cfgJS, "null", `"abc"`, 1), []string{"X"}, ""},
		{"bad number", cfgJS, map[int]string{2: "1,5"}, "", nil, "N must be a number."},
		{"bad bool", cfgJS, map[int]string{3: "yes"}, "", nil, "ON must be true or false."},
		{"pretty formatting kept", "{\n  \"a\": \"x\",\n  \"b\": 2\n}\n", map[int]string{0: "y"},
			"{\n  \"a\": \"y\",\n  \"b\": 2\n}\n", []string{"a"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, ok := parseStructured(tt.in)
			if !ok {
				t.Fatal("not structured")
			}
			got, changed, err := applyLeaves(tt.in, st, tt.values)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want || !slices.Equal(changed, tt.changed) {
				t.Fatalf("got %q changed %q\nwant %q changed %q", got, changed, tt.want, tt.changed)
			}
		})
	}
}

// fieldsFixture adds front/cfg (tags {front, prod}) with a JS and a JSON config and a plain key.
func fieldsFixture(t *testing.T) (*secretsFixture, string) {
	t.Helper()
	f := newSecretsFixture(t)
	if _, err := f.kube.CoreV1().Secrets("front").Create(t.Context(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "front", Name: "cfg", ResourceVersion: "1"},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"config.js": []byte(cfgJS), "config.json": []byte(cfgJSON), "PLAIN": []byte("p")},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	id, err := f.store.ImportSecret(t.Context(), "k8s", map[string]string{"namespace": "front", "name": "cfg"},
		[]string{"front", "prod"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, idStr(id)
}

func TestSecretFieldsView(t *testing.T) {
	f, cfg := fieldsFixture(t)
	path := "/secrets/" + cfg

	// The tab appears only for secrets with a config value; the key/value view reveals nothing.
	_, body := f.do(t, f.bob, http.MethodGet, path, nil)
	mustContain(t, body, `href="`+path+`?view=fields"`)
	if strings.Contains(body, "app.dev.example") || strings.Contains(body, "VITE_API") {
		t.Fatal("value revealed on key/value view")
	}
	_, body = f.do(t, f.bob, http.MethodGet, "/secrets/"+f.api, nil)
	if strings.Contains(body, "?view=fields") {
		t.Error("Fields tab on a secret without config values")
	}

	resp, body := f.do(t, f.bob, http.MethodGet, path+"?view=fields", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("fields = %d, cache %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	mustContain(t, body, `aria-current="page"`+"\n     title=\"Edit JSON / JS config values field by field\">Fields",
		"<code>config.js</code>", "<code>window.CONFIG = …;</code>", "<code>config.json</code>",
		"<code>VITE_API_AUTH_SUFFIX</code>", ">\n/auth</textarea>", "<code>links.join</code>",
		"<code>[&#34;odd key&#34;]</code>", "number</small>")
	if strings.Contains(body, "<code>PLAIN</code>") || strings.Contains(body, "/edit?view=fields") {
		t.Error("plain key shown, or edit link for a read-only user")
	}
	mustContain(t, f.audit.String(), `"view":"fields"`, `"keys":["config.js","config.json"]`)
	if strings.Contains(f.audit.String(), "app.dev.example") {
		t.Fatal("value in audit log")
	}

	_, body = f.do(t, f.carol, http.MethodGet, path+"?view=fields", nil)
	mustContain(t, body, `href="`+path+`/edit?view=fields"`)

	if resp, _ := f.do(t, f.alice, http.MethodGet, path+"?view=fields", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("alice fields = %d, want 404", resp.StatusCode)
	}
}

func TestSecretFieldsEdit(t *testing.T) {
	f, cfg := fieldsFixture(t)
	path := "/secrets/" + cfg

	if resp, _ := f.do(t, f.bob, http.MethodGet, path+"/edit?view=fields", nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob fields edit = %d, want 403", resp.StatusCode)
	}
	if resp, _ := f.post(t, f.bob, path, url.Values{"view": {"fields"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob fields save = %d, want 403", resp.StatusCode)
	}

	_, body := f.do(t, f.carol, http.MethodGet, path+"/edit?view=fields", nil)
	mustContain(t, body, `name="view" value="fields"`, `name="fk" value="config.js"`, ">\n/auth</textarea>")
	mustContain(t, f.audit.String(), `"view":"fields"`, `"for":"edit"`)
	ver := versionRe.FindStringSubmatch(body)[1]

	form := func(version string, kv ...string) url.Values {
		v := url.Values{"version": {version}, "view": {"fields"}}
		for i := 0; i < len(kv); i += 3 {
			v.Add("fk", kv[i])
			v.Add("fi", kv[i+1])
			v.Add("fv", kv[i+2])
		}
		return v
	}

	// Invalid number: the form comes back with what was typed; nothing saved.
	_, body = f.post(t, f.carol, path, form(ver, "config.js", "0", "/typed", "config.js", "2", "abc"))
	mustContain(t, body, "flash-error", "N must be a number.", ">\n/typed</textarea>")
	if got := f.kubeData(t, "cfg"); got["config.js"] != cfgJS {
		t.Fatal("failed save changed the secret")
	}

	// Unchanged values.
	_, body = f.post(t, f.carol, path, form(ver, "config.js", "0", "/auth", "config.json", "0", "https://app.dev.example"))
	mustContain(t, body, "No changes.")

	// Save: only changed leaves are rewritten; other keys untouched.
	resp, body := f.post(t, f.carol, path, form(ver,
		"config.js", "0", "/auth", "config.js", "1", "https://api", "config.json", "0", "https://join"))
	if resp.URL.RequestURI() != path+"?view=fields" {
		t.Fatalf("after save: %s", resp.URL)
	}
	mustContain(t, body, "Secret saved.")
	got := f.kubeData(t, "cfg")
	if want := strings.Replace(cfgJS, `"VITE_API_URL":""`, `"VITE_API_URL":"https://api"`, 1); got["config.js"] != want {
		t.Errorf("config.js = %q, want %q", got["config.js"], want)
	}
	if want := strings.Replace(cfgJSON, "https://app.dev.example", "https://join", 1); got["config.json"] != want {
		t.Errorf("config.json = %q, want %q", got["config.json"], want)
	}
	if got["PLAIN"] != "p" || len(got) != 3 {
		t.Errorf("other keys changed: %v", got)
	}
	mustContain(t, f.audit.String(), `"changed":["config.js","config.json"]`)

	// Stale version: conflict, typed values kept.
	_, body = f.post(t, f.carol, path, form("stale", "config.js", "0", "/mine"))
	mustContain(t, body, "changed by someone else", ">\n/mine</textarea>")

	// A key that isn't a config can't be edited here.
	ver = f.editVersion(t, f.carol, cfg)
	_, body = f.post(t, f.carol, path, form(ver, "PLAIN", "0", "x"))
	mustContain(t, body, "flash-error", "no longer a JSON/JS config")

	for _, v := range []string{"app.dev.example", "https://api", "https://join", "/mine", "/typed"} {
		if strings.Contains(f.audit.String(), v) {
			t.Fatalf("value %q in audit log", v)
		}
	}
}

func TestSecretListTree(t *testing.T) {
	f := newSecretsFixture(t)
	_, body := f.do(t, f.carol, http.MethodGet, "/", nil)
	mustContain(t, body, `<details open>`, "<strong>front</strong> <small class=\"muted\">(2)</small>",
		`href="/?view=table" role="button" class="small secondary outline"`)
	if !listed(body, f.api) || !listed(body, f.synced) {
		t.Error("tree misses secrets")
	}

	// Table view keeps the filters in the switch links and the filter form.
	_, body = f.do(t, f.carol, http.MethodGet, "/?view=table&tag=prod", nil)
	mustContain(t, body, "<th>Namespace</th>", `name="view" value="table"`, `href="/?tag=prod" role="button"`)
	if strings.Contains(body, "<details") || !listed(body, f.api) || listed(body, f.synced) {
		t.Error("table view with tag filter")
	}

	_, body = f.do(t, f.carol, http.MethodGet, "/?ns=other", nil)
	mustContain(t, body, "No secrets match the filter.")
	if regexp.MustCompile(`<details`).MatchString(body) {
		t.Error("empty tree has groups")
	}
}
