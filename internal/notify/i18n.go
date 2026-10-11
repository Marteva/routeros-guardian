package notify

import (
	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// messageKeys are all i18n keys used by this package.
var messageKeys = []string{
	"notify.device", "notify.device.one", "notify.device.name",
	"notify.unknown", "notify.test.title", "notify.test.body",
}

// translations holds this package's texts. "notify.device.one" and
// "notify.device.name" are owned here; the other keys are defined by
// internal/i18n (en, cs) and only filled in here for languages where the
// shared catalog has no translation yet (see init).
var translations = map[string]map[string]string{
	"en": {
		"notify.device.one":  "Device: %s (%s)",
		"notify.device.name": "Device: %s",
	},
	"cs": {
		"notify.device.one":  "Zařízení: %s (%s)",
		"notify.device.name": "Zařízení: %s",
	},
	"de": {
		"notify.device":      "Gerät: %s (%s, %s)",
		"notify.device.one":  "Gerät: %s (%s)",
		"notify.device.name": "Gerät: %s",
		"notify.unknown":     "unbekanntes Gerät",
		"notify.test.title":  "Guardian for RouterOS: Testbenachrichtigung",
		"notify.test.body":   "Wenn du das lesen kannst, funktionieren die Benachrichtigungen.",
	},
	"es": {
		"notify.device":      "Dispositivo: %s (%s, %s)",
		"notify.device.one":  "Dispositivo: %s (%s)",
		"notify.device.name": "Dispositivo: %s",
		"notify.unknown":     "dispositivo desconocido",
		"notify.test.title":  "Guardian for RouterOS: notificación de prueba",
		"notify.test.body":   "Si puedes leer esto, las notificaciones funcionan.",
	},
	"id": {
		"notify.device":      "Perangkat: %s (%s, %s)",
		"notify.device.one":  "Perangkat: %s (%s)",
		"notify.device.name": "Perangkat: %s",
		"notify.unknown":     "perangkat tidak dikenal",
		"notify.test.title":  "Guardian for RouterOS: notifikasi uji coba",
		"notify.test.body":   "Jika Anda dapat membaca pesan ini, notifikasi sudah berfungsi.",
	},
	"it": {
		"notify.device":      "Dispositivo: %s (%s, %s)",
		"notify.device.one":  "Dispositivo: %s (%s)",
		"notify.device.name": "Dispositivo: %s",
		"notify.unknown":     "dispositivo sconosciuto",
		"notify.test.title":  "Guardian for RouterOS: notifica di prova",
		"notify.test.body":   "Se riesci a leggere questo messaggio, le notifiche funzionano.",
	},
	"pl": {
		"notify.device":      "Urządzenie: %s (%s, %s)",
		"notify.device.one":  "Urządzenie: %s (%s)",
		"notify.device.name": "Urządzenie: %s",
		"notify.unknown":     "nieznane urządzenie",
		"notify.test.title":  "Guardian for RouterOS: powiadomienie testowe",
		"notify.test.body":   "Jeśli to czytasz, powiadomienia działają.",
	},
	"pt": {
		"notify.device":      "Dispositivo: %s (%s, %s)",
		"notify.device.one":  "Dispositivo: %s (%s)",
		"notify.device.name": "Dispositivo: %s",
		"notify.unknown":     "dispositivo desconhecido",
		"notify.test.title":  "Guardian for RouterOS: notificação de teste",
		"notify.test.body":   "Se você está lendo isto, as notificações estão funcionando.",
	},
	"tr": {
		"notify.device":      "Cihaz: %s (%s, %s)",
		"notify.device.one":  "Cihaz: %s (%s)",
		"notify.device.name": "Cihaz: %s",
		"notify.unknown":     "bilinmeyen cihaz",
		"notify.test.title":  "Guardian for RouterOS: test bildirimi",
		"notify.test.body":   "Bunu okuyabiliyorsanız bildirimler çalışıyor.",
	},
	"uk": {
		"notify.device":      "Пристрій: %s (%s, %s)",
		"notify.device.one":  "Пристрій: %s (%s)",
		"notify.device.name": "Пристрій: %s",
		"notify.unknown":     "невідомий пристрій",
		"notify.test.title":  "Guardian for RouterOS: тестове сповіщення",
		"notify.test.body":   "Якщо ви це читаєте, сповіщення працюють.",
	},
}

// init registers the texts that the shared catalog does not translate yet, so
// translations maintained in internal/i18n always win over these defaults.
func init() {
	// English first: "untranslated" below means "falls back to English".
	langs := []string{i18n.Fallback}
	for _, l := range settings.Languages {
		if l != i18n.Fallback {
			langs = append(langs, l)
		}
	}
	for _, lang := range langs {
		add := map[string]string{}
		for k, v := range translations[lang] {
			cur := i18n.T(lang, k)
			if cur == k || (lang != i18n.Fallback && cur == i18n.T(i18n.Fallback, k)) {
				add[k] = v
			}
		}
		if len(add) > 0 {
			i18n.Register(lang, add)
		}
	}
}
