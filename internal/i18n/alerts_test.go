package i18n

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Marteva/routeros-guardian/internal/settings"
)

var alertCatalogs = map[string]map[string]string{
	"en": alertsEN, "cs": alertsCS, "de": alertsDE, "es": alertsES, "id": alertsID,
	"it": alertsIT, "pl": alertsPL, "pt": alertsPT, "tr": alertsTR, "uk": alertsUK,
}

var verbRE = regexp.MustCompile(`%[-+# 0]*[0-9]*(\.[0-9]+)?[a-zA-Z%]`)

// Every alert key exists in every language, with the same fmt verbs in the
// same order (T passes arguments positionally).
func TestAlertCatalogsComplete(t *testing.T) {
	// exactly the supported languages: no missing and no left-over catalogs
	langs := slices.Sorted(maps.Keys(alertCatalogs))
	if want := slices.Sorted(slices.Values(settings.Languages)); !slices.Equal(langs, want) {
		t.Fatalf("alert catalogs %v, settings.Languages %v", langs, want)
	}
	registered := slices.Sorted(maps.Keys(catalog))
	if want := slices.Sorted(slices.Values(settings.Languages)); !slices.Equal(registered, want) {
		t.Fatalf("registered languages %v, settings.Languages %v", registered, want)
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
	for _, lang := range []string{"xx", "ru"} { // ru was removed: English like any unknown language
		if got := T(lang, "kind.camera"); got != "Camera" {
			t.Fatalf("%s fallback = %q", lang, got)
		}
	}
	// decimal point only in English
	for _, lang := range settings.Languages {
		want := ","
		if lang == "en" {
			want = "."
		}
		if got := T(lang, "fmt.decimal"); got != want {
			t.Errorf("%s fmt.decimal = %q, want %q", lang, got, want)
		}
	}
	// languages without plural inflection after numerals use one word for all forms
	for _, lang := range []string{"id", "tr"} {
		for k := range alertsEN {
			if base, ok := strings.CutSuffix(k, ".one"); ok && strings.HasPrefix(k, "word.") {
				if one, few, many := T(lang, k), T(lang, base+".few"), T(lang, base+".many"); one != few || one != many {
					t.Errorf("%s %s: %q/%q/%q", lang, base, one, few, many)
				}
			}
		}
	}
	// Ukrainian distinguishes one/few/many like Czech and Polish
	if one, few, many := T("uk", "word.device.one"), T("uk", "word.device.few"), T("uk", "word.device.many"); one == few || few == many {
		t.Errorf("uk word.device: %q/%q/%q", one, few, many)
	}
}
