package i18n

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var alertCatalogs = map[string]map[string]string{
	"en": alertsEN, "cs": alertsCS, "de": alertsDE, "pl": alertsPL,
	"ru": alertsRU, "es": alertsES, "pt": alertsPT,
}

var verbRE = regexp.MustCompile(`%[-+# 0]*[0-9]*(\.[0-9]+)?[a-zA-Z%]`)

// Every alert key exists in every language, with the same fmt verbs in the
// same order (T passes arguments positionally).
func TestAlertCatalogsComplete(t *testing.T) {
	for _, lang := range []string{"en", "cs", "de", "pl", "ru", "es", "pt"} {
		if alertCatalogs[lang] == nil {
			t.Fatalf("no alert catalog for %s", lang)
		}
	}
	for lang, cat := range alertCatalogs {
		if len(cat) != len(alertsEN) {
			t.Errorf("%s: %d keys, en has %d", lang, len(cat), len(alertsEN))
		}
		for key, en := range alertsEN {
			v, ok := cat[key]
			if !ok {
				t.Errorf("%s: missing key %q", lang, key)
				continue
			}
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: empty %q", lang, key)
			}
			if got, want := verbRE.FindAllString(v, -1), verbRE.FindAllString(en, -1); !slices.Equal(got, want) {
				t.Errorf("%s %q: verbs %v, en has %v", lang, key, got, want)
			}
		}
	}
}

func TestAlertCatalogRegistered(t *testing.T) {
	if got := T("cs", "kind.camera"); got != "Kamera" {
		t.Fatalf("cs kind.camera = %q", got)
	}
	if got := T("en", "alert.newdev.title", "X"); got != "New device on the network: X" {
		t.Fatalf("en title = %q", got)
	}
	if got := T("xx", "kind.camera"); got != "Camera" {
		t.Fatalf("fallback = %q", got)
	}
	if T("en", "fmt.decimal") != "." || T("de", "fmt.decimal") != "," {
		t.Fatal("decimal separators")
	}
}
