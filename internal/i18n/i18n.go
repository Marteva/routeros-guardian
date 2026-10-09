// Package i18n translates server-side texts (alert titles/details, notifications).
// The web UI has its own catalog in internal/web/static.
package i18n

import "fmt"

// Fallback language used when a key is missing in the requested language.
const Fallback = "en"

// catalog[lang][key] = format string (fmt verbs, args passed by T).
var catalog = map[string]map[string]string{
	"en": {
		"notify.device":     "Device: %s (%s, %s)",
		"notify.test.title": "Guardian for RouterOS: test notification",
		"notify.test.body":  "If you can read this, notifications work.",
		"notify.unknown":    "unknown device",
	},
	"cs": {
		"notify.device":     "Zařízení: %s (%s, %s)",
		"notify.test.title": "Guardian for RouterOS: testovací zpráva",
		"notify.test.body":  "Pokud tohle čteš, upozornění fungují.",
		"notify.unknown":    "neznámé zařízení",
	},
}

// T returns the translation of key in lang formatted with args, falling back
// to English and finally to the key itself.
func T(lang, key string, args ...any) string {
	f, ok := catalog[lang][key]
	if !ok {
		if f, ok = catalog[Fallback][key]; !ok {
			f = key
		}
	}
	if len(args) == 0 {
		return f
	}
	return fmt.Sprintf(f, args...)
}

// Register adds or replaces translations (used by packages owning their texts).
// Call only from init functions.
func Register(lang string, entries map[string]string) {
	m := catalog[lang]
	if m == nil {
		m = map[string]string{}
		catalog[lang] = m
	}
	for k, v := range entries {
		m[k] = v
	}
}
