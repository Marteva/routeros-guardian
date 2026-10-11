package web

import (
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

func readStatic(t *testing.T, name string) string {
	t.Helper()
	b, err := staticFS.ReadFile("static/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// loadCatalog parses the JSON object assigned to window.GUARDIAN_I18N.
func loadCatalog(t *testing.T) map[string]map[string]any {
	t.Helper()
	src := readStatic(t, "i18n.js")
	i := strings.Index(src, "window.GUARDIAN_I18N =")
	if i < 0 {
		t.Fatal("i18n.js: window.GUARDIAN_I18N not found")
	}
	start := i + strings.Index(src[i:], "{")
	end := strings.LastIndex(src, "}")
	var cat map[string]map[string]any
	if err := json.Unmarshal([]byte(src[start:end+1]), &cat); err != nil {
		t.Fatalf("i18n.js object is not valid JSON: %v", err)
	}
	return cat
}

var placeholderRe = regexp.MustCompile(`\{(\w+)\}`)

func placeholders(v any) []string {
	b, _ := json.Marshal(v)
	set := map[string]bool{}
	for _, m := range placeholderRe.FindAllStringSubmatch(string(b), -1) {
		set[m[1]] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestI18nCatalogComplete(t *testing.T) {
	cat := loadCatalog(t)
	en := cat["en"]
	if len(en) < 100 {
		t.Fatalf("en has only %d keys", len(en))
	}
	for _, lang := range settings.Languages {
		c, ok := cat[lang]
		if !ok {
			t.Errorf("language %s missing", lang)
			continue
		}
		for k, v := range en {
			lv, ok := c[k]
			if !ok {
				t.Errorf("%s: missing key %s", lang, k)
				continue
			}
			if p, q := placeholders(lv), placeholders(v); !slices.Equal(p, q) {
				t.Errorf("%s: %s placeholders %v, en has %v", lang, k, p, q)
			}
			switch x := lv.(type) {
			case string:
				if strings.TrimSpace(x) == "" {
					t.Errorf("%s: %s is empty", lang, k)
				}
			case map[string]any:
				if _, ok := x["other"]; !ok {
					t.Errorf("%s: plural %s has no \"other\"", lang, k)
				}
				for cat := range x {
					if !slices.Contains([]string{"zero", "one", "two", "few", "many", "other"}, cat) {
						t.Errorf("%s: plural %s has unknown category %q", lang, k, cat)
					}
				}
			default:
				t.Errorf("%s: %s has type %T", lang, k, lv)
			}
		}
		for k := range c {
			if _, ok := en[k]; !ok {
				t.Errorf("%s: key %s not in en", lang, k)
			}
		}
	}
	// Labels the UI builds from server enums.
	var want []string
	for _, k := range model.Kinds {
		want = append(want, "kind."+k)
	}
	for _, d := range settings.Detectors {
		want = append(want, "alert."+d, "det."+d+".help")
	}
	for _, s := range settings.Sensitivities {
		want = append(want, "set.sens."+s, "set.sens."+s+".help")
	}
	for _, s := range []model.Severity{model.SevInfo, model.SevWarning, model.SevCritical} {
		want = append(want, "sev."+s.String())
	}
	for _, k := range want {
		if _, ok := en[k]; !ok {
			t.Errorf("en: missing %s", k)
		}
	}
	// Czech wording of the original UI is kept.
	for k, v := range map[string]string{
		"merge.mode": "Sloučit", "group.unmerge": "Rozdělit", "common.delete": "Smazat",
		"set.tokenSaved": "uloženo", "set.test": "Poslat testovací zprávu",
		"set.resetLearned": "Smazat naučená data a začít se učit znovu",
		"set.resetAll":     "Smazat vše včetně zařízení", "alerts.emptyOpen": "Žádná otevřená upozornění. 👍",
	} {
		if cat["cs"][k] != v {
			t.Errorf("cs %s = %q, want %q", k, cat["cs"][k], v)
		}
	}
}

func TestI18nKeysUsedByUIExist(t *testing.T) {
	en := loadCatalog(t)["en"]
	app := readStatic(t, "app.js")
	html := readStatic(t, "index.html")
	var keys []string
	for _, m := range regexp.MustCompile(`\btn?\("([a-zA-Z0-9_.]+)"`).FindAllStringSubmatch(app, -1) {
		keys = append(keys, m[1])
	}
	for _, m := range regexp.MustCompile(`data-i18n="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		keys = append(keys, m[1])
	}
	for _, m := range regexp.MustCompile(`data-i18n-attr="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		for _, pair := range strings.Split(m[1], ";") {
			if _, k, ok := strings.Cut(pair, ":"); ok {
				keys = append(keys, k)
			}
		}
	}
	if len(keys) < 50 {
		t.Fatalf("found only %d keys – regexps out of date?", len(keys))
	}
	for _, k := range keys {
		if strings.HasSuffix(k, ".") {
			continue // dynamic prefix, checked in TestI18nCatalogComplete
		}
		if _, ok := en[k]; !ok {
			t.Errorf("UI uses unknown key %q", k)
		}
	}
}

func TestUIListsMatchModel(t *testing.T) {
	app := readStatic(t, "app.js")
	list := func(name string) []string {
		m := regexp.MustCompile(`const ` + name + ` = \[([^\]]*)\]`).FindStringSubmatch(app)
		if m == nil {
			t.Fatalf("app.js: %s not found", name)
		}
		var out []string
		for _, x := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			out = append(out, x[1])
		}
		return out
	}
	if got := list("KINDS"); !slices.Equal(got, model.Kinds) {
		t.Errorf("app.js KINDS %v, model.Kinds %v", got, model.Kinds)
	}
	if got := list("DETECTORS"); !slices.Equal(got, settings.Detectors) {
		t.Errorf("app.js DETECTORS %v, settings.Detectors %v", got, settings.Detectors)
	}
	if got := list("LANGS"); !slices.Equal(got, settings.Languages) {
		t.Errorf("app.js LANGS %v, settings.Languages %v", got, settings.Languages)
	}
	if got := list("SENSITIVITIES"); !slices.Equal(got, settings.Sensitivities) {
		t.Errorf("app.js SENSITIVITIES %v, settings.Sensitivities %v", got, settings.Sensitivities)
	}
}

// The UI catalog, the native language names and the flags cover exactly the
// server's languages (a removed language such as "ru" leaves nothing behind).
func TestUILanguagesMatchSettings(t *testing.T) {
	want := slices.Sorted(slices.Values(settings.Languages))
	if got := slices.Sorted(maps.Keys(loadCatalog(t))); !slices.Equal(got, want) {
		t.Errorf("i18n.js languages %v, settings.Languages %v", got, want)
	}
	app := readStatic(t, "app.js")
	block := func(name string) string {
		i := strings.Index(app, "const "+name+" = {")
		if i < 0 {
			t.Fatalf("app.js: %s not found", name)
		}
		end := strings.Index(app[i:], "\n  };")
		if end < 0 {
			t.Fatalf("app.js: end of %s not found", name)
		}
		return app[i : i+end]
	}
	keys := func(name string, re *regexp.Regexp) []string {
		var out []string
		for _, m := range re.FindAllStringSubmatch(block(name), -1) {
			out = append(out, m[1])
		}
		slices.Sort(out)
		return out
	}
	names := keys("LANG_NAMES", regexp.MustCompile(`\b([a-z]{2}): "`))
	if !slices.Equal(names, want) {
		t.Errorf("app.js LANG_NAMES %v, settings.Languages %v", names, want)
	}
	flags := keys("FLAGS", regexp.MustCompile(`(?m)^    ([a-z]{2}): \["`))
	if !slices.Equal(flags, want) {
		t.Errorf("app.js FLAGS %v, settings.Languages %v", flags, want)
	}
	// every flag is a viewBox plus shapes with literal colours (no external images)
	for _, m := range regexp.MustCompile(`(?m)^    ([a-z]{2}): \["([^"]+)"`).FindAllStringSubmatch(block("FLAGS"), -1) {
		if len(strings.Fields(m[2])) != 4 {
			t.Errorf("flag %s: bad viewBox %q", m[1], m[2])
		}
	}
	if regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]`).MatchString(app) {
		t.Error("app.js contains emoji flags (not rendered on Windows)")
	}
}

// The header language picker is an accessible flag button + listbox.
func TestLanguagePickerMarkup(t *testing.T) {
	html := readStatic(t, "index.html")
	for _, want := range []string{
		`id="lang-btn"`, `aria-haspopup="listbox"`, `aria-expanded="false"`, `aria-controls="lang-menu"`,
		`id="lang-menu" role="listbox" hidden`, `data-i18n-attr="aria-label:hdr.language"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html: missing %s", want)
		}
	}
	if strings.Contains(html, "lang-select") {
		t.Error("index.html still has the old language <select>")
	}
	app := readStatic(t, "app.js")
	for _, want := range []string{`role: "option"`, `"aria-selected"`, `"aria-expanded"`, `"Escape"`, `"ArrowDown"`, `"ArrowUp"`, `"Home"`, `"End"`, `"Enter"`, "pointerdown", "focusout"} {
		if !strings.Contains(app, want) {
			t.Errorf("app.js language picker: %s not handled", want)
		}
	}
}

func TestUIHasNoExternalResources(t *testing.T) {
	html := readStatic(t, "index.html")
	for _, bad := range []string{"http://", "https://", "<script>", "style=\"", " on"} {
		if bad == " on" {
			// inline event handlers (onclick=…) are blocked by the CSP
			if regexp.MustCompile(`\son[a-z]+=`).MatchString(html) {
				t.Error("index.html has an inline event handler")
			}
			continue
		}
		if strings.Contains(html, bad) {
			t.Errorf("index.html contains %q", bad)
		}
	}
	if !strings.Contains(html, `<script src="theme.js"></script>`) {
		t.Error("theme.js must load synchronously in <head> (no flash of the wrong theme)")
	}
}
