package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/model"
)

// loc renders alert texts in one language. Every user-visible string comes
// from the i18n catalog (internal/i18n/alerts_*.go); the code only adds
// numbers, names and punctuation that are the same in all languages.
type loc string

func (l loc) t(key string, args ...any) string { return i18n.T(string(l), key, args...) }

// pluralForm returns the plural category of n in lang: "one", "few" or
// "many". "few" is distinct only for Czech, Polish and Ukrainian (Ukrainian
// "one" also covers 21, 31…); the other languages register identical
// few/many forms (Indonesian and Turkish do not inflect nouns after numbers
// at all, so all three of their forms are the same).
func pluralForm(lang string, n int) string {
	if n < 0 {
		n = -n
	}
	m10, m100 := n%10, n%100
	switch lang {
	case "cs":
		switch {
		case n == 1:
			return "one"
		case n >= 2 && n <= 4:
			return "few"
		}
		return "many"
	case "pl":
		switch {
		case n == 1:
			return "one"
		case m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14):
			return "few"
		}
		return "many"
	case "uk":
		switch {
		case m10 == 1 && m100 != 11:
			return "one"
		case m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14):
			return "few"
		}
		return "many"
	}
	if n == 1 {
		return "one"
	}
	return "many"
}

// word returns the form of a counted noun (catalog key word.<noun>.<form>) for n.
func (l loc) word(noun string, n int) string {
	return l.t("word." + noun + "." + pluralForm(string(l), n))
}

// kind returns the localized label of a device kind ("Kamera", "Camera").
// Unknown or empty kinds get the generic "device" label.
func (l loc) kind(kind string) string {
	if !model.ValidKind(kind) {
		kind = "unknown"
	}
	return l.t("kind." + kind)
}

// deviceName builds a short human name. An explicit friendly name (user note,
// then DHCP lease comment – see model.Device.DisplayName) is used as is;
// otherwise the label of the effective kind is decorated with
// hostname/vendor, e.g. "Kamera (Hikvision)".
func (l loc) deviceName(d model.Device) string {
	if strings.TrimSpace(d.Note) != "" || strings.TrimSpace(d.Comment) != "" {
		d.Note, d.Comment = strings.TrimSpace(d.Note), strings.TrimSpace(d.Comment)
		return d.DisplayName()
	}
	label := l.kind(d.EffectiveKind())
	var extra []string
	if d.Hostname != "" {
		extra = append(extra, d.Hostname)
	}
	if d.Vendor != "" && !strings.EqualFold(d.Vendor, d.Hostname) {
		extra = append(extra, d.Vendor)
	}
	if len(extra) == 0 {
		if d.MAC == "" {
			return label
		}
		extra = append(extra, d.MAC)
	}
	return label + " (" + strings.Join(extra, ", ") + ")"
}

var byteUnits = []string{"unit.B", "unit.kB", "unit.MB", "unit.GB", "unit.TB"}

// bytes formats a byte count: "3.1 GB" (en), "3,1 GB" (cs), "45 MB", "812 kB".
func (l loc) bytes(b float64) string {
	i := 0
	for b >= 1024 && i < len(byteUnits)-1 {
		b /= 1024
		i++
	}
	return l.num(b) + " " + l.t(byteUnits[i])
}

// perHour formats a byte rate: "3,1 GB/h".
func (l loc) perHour(b float64) string { return l.t("unit.per_hour", l.bytes(b)) }

// num: one decimal below 10, integer otherwise; decimal separator per language.
func (l loc) num(x float64) string {
	var s string
	if x < 10 && x != float64(int64(x)) {
		s = fmt.Sprintf("%.1f", x)
	} else {
		s = fmt.Sprintf("%.0f", x)
	}
	if sep := l.t("fmt.decimal"); sep != "." {
		s = strings.Replace(s, ".", sep, 1)
	}
	return s
}

// ratio: "68×", "3,5×".
func (l loc) ratio(r float64) string { return l.num(r) + "×" }

// datetime formats t in local time with the language's layout.
func (l loc) datetime(t time.Time) string { return t.Local().Format(l.t("fmt.datetime")) }

// baseline describes a baseline median ("45 MB/h at this time of day
// (median of 12 days)"); unit is the already formatted median.
func (l loc) baseline(b baseline, unit string) string {
	if b.Method == "same_hour" {
		return l.t("alert.baseline.same_hour", unit, b.Samples, l.word("day", b.Samples))
	}
	return l.t("alert.baseline.all_hours", unit, b.Samples, l.word("hour", b.Samples))
}

// hourRange: "09:00–10:00" (local time, same in all languages).
func hourRange(h time.Time) string {
	lt := h.Local()
	return lt.Format("15:04") + "–" + lt.Add(time.Hour).Format("15:04")
}
