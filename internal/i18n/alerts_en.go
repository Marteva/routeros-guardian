package i18n

// Alert texts of internal/detect (English). Every key here must exist in all
// languages (see alerts_test.go). Counted nouns use the suffixes
// .one/.few/.many (few is only distinct in cs, pl and ru).
var alertsEN = map[string]string{
	// number and date formatting
	"fmt.decimal":  ".",
	"fmt.datetime": "2006-01-02 15:04",
	"unit.B":       "B",
	"unit.kB":      "kB",
	"unit.MB":      "MB",
	"unit.GB":      "GB",
	"unit.TB":      "TB",

	"unit.per_hour":       "%s/h",
	"unit.per_whole_hour": "%s for the whole hour",
	"unit.addr_per_hour":  "%s addresses/h",

	// device kinds (model.Kinds)
	"kind.phone":    "Phone",
	"kind.tablet":   "Tablet",
	"kind.computer": "Computer",
	"kind.tv":       "TV",
	"kind.camera":   "Camera",
	"kind.iot":      "Smart device",
	"kind.speaker":  "Speaker",
	"kind.console":  "Game console",
	"kind.printer":  "Printer",
	"kind.nas":      "NAS",
	"kind.network":  "Network device",
	"kind.unknown":  "Device",

	// counted nouns
	"word.device.one":    "device",
	"word.device.few":    "devices",
	"word.device.many":   "devices",
	"word.hour.one":      "hour",
	"word.hour.few":      "hours",
	"word.hour.many":     "hours",
	"word.day.one":       "day",
	"word.day.few":       "days",
	"word.day.many":      "days",
	"word.new_conn.one":  "new connection",
	"word.new_conn.few":  "new connections",
	"word.new_conn.many": "new connections",
	"word.country.one":   "country",
	"word.country.few":   "countries",
	"word.country.many":  "countries",
	"word.network.one":   "network",
	"word.network.few":   "networks",
	"word.network.many":  "networks",

	// baseline description: unit, samples, counted noun
	"alert.baseline.same_hour": "%s at this time of day (median of %d %s)",
	"alert.baseline.all_hours": "%s (median of %d %s with traffic)",

	// new device
	"alert.newdev.title":          "New device on the network: %s",
	"alert.newdev.first":          "%s appeared on the network for the first time.",
	"alert.newdev.hostname":       "hostname %s",
	"alert.newdev.comment":        "comment %s",
	"alert.newdev.vendor":         "vendor %s",
	"alert.newdev.kind":           "type (guess) %s",
	"alert.newdev.randomized":     "The device uses a random MAC address (typical for phones and laptops).",
	"alert.newdev.advice_warning": "The device could not be identified and has a fixed MAC address. If you do not recognise it, consider blocking it.",
	"alert.newdev.advice_info":    "If you do not recognise the device, you can quarantine it.",

	// initial inventory summary
	"alert.inventory.title":    "Initial inventory complete: %d %s",
	"alert.inventory.found":    "During the first %d %s Guardian found %d %s on the network (%s).",
	"alert.inventory.review":   "Please review the device list and label or block unknown devices.",
	"alert.inventory.learning": "Learning of normal behaviour continues until %s; until then no behaviour anomalies are reported.",
	"alert.inventory.learned":  "Learning of normal behaviour is complete; behaviour anomalies are now reported.",

	// destinations (new country / new ASN)
	"alert.dest.examples":       ", e.g. %s",
	"alert.dest.line":           "%s: sent %s, received %s, %d %s%s.",
	"alert.country.title.one":   "%s is communicating with a new country: %s",
	"alert.country.title.many":  "%s is communicating with new countries: %s",
	"alert.country.first":       "First contact with country %s",
	"alert.country.known":       "So far it has communicated with %d %s (%s).",
	"alert.country.advice_crit": "%s: such devices do not normally send data to new countries (sent ≥ %s). If you have not changed anything, consider quarantining the device.",
	"alert.country.advice_warn": "This may be an update or a new service; if you did not expect it, check the device.",
	"alert.asn.title.one":       "%s is communicating with a new network: %s",
	"alert.asn.title.many":      "%s is communicating with %d new networks",
	"alert.asn.first":           "First contact with network %s",
	"alert.asn.known":           "%s: such devices usually have a small, stable set of destinations (%d %s so far).",

	// upload spike
	"alert.spike.title":       "%s is uploading %s",
	"alert.spike.detail":      "In the hour %s the device uploaded %s to the internet, usually %s, i.e. %s more.",
	"alert.spike.max":         "Maximum over the last %d %s: %s.",
	"alert.spike.advice_crit": "%s: such devices do not usually upload this much – recordings may be being sent to a stranger, or the device may be compromised. If you did not expect this, consider quarantine.",
	"alert.spike.advice_warn": "This may be a backup or sharing of large files; if you did not expect it, check the device.",
	"alert.spike.fast.title":  "%s is uploading an unusual amount of data right now (%s)",
	"alert.spike.fast.detail": "In the last %d min the device uploaded %s to the internet, while it usually sends %s, i.e. already %s more.",

	// destination fan-out
	"alert.fanout.title":       "%s contacted %d different addresses in one hour",
	"alert.fanout.detail":      "In the hour %s the device contacted %d different IP addresses on the internet (%d new connections), usually %s, i.e. %s more.",
	"alert.fanout.max":         "Previous maximum: %s.",
	"alert.fanout.explain":     "Such behaviour is typical of internet scanning or of being part of a botnet.",
	"alert.fanout.advice_crit": "Consider quarantining the device and updating its firmware.",
}

func init() { Register("en", alertsEN) }
