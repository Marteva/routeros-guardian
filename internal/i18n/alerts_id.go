package i18n

// Alert texts of internal/detect (Indonesian). Nouns after numbers are not
// inflected ("1 perangkat", "3 perangkat"), so the .one/.few/.many forms of
// every counted noun are identical.
var alertsID = map[string]string{
	// number and date formatting
	"fmt.decimal":  ",",
	"fmt.datetime": "02/01/2006 15:04",
	"unit.B":       "B",
	"unit.kB":      "kB",
	"unit.MB":      "MB",
	"unit.GB":      "GB",
	"unit.TB":      "TB",

	"unit.per_hour":       "%s/jam",
	"unit.per_whole_hour": "%s dalam satu jam penuh",
	"unit.addr_per_hour":  "%s alamat/jam",

	// device kinds (model.Kinds)
	"kind.phone":    "Ponsel",
	"kind.tablet":   "Tablet",
	"kind.computer": "Komputer",
	"kind.tv":       "TV",
	"kind.camera":   "Kamera",
	"kind.iot":      "Perangkat pintar",
	"kind.speaker":  "Speaker",
	"kind.console":  "Konsol game",
	"kind.printer":  "Printer",
	"kind.nas":      "NAS",
	"kind.network":  "Perangkat jaringan",
	"kind.unknown":  "Perangkat",

	// counted nouns
	"word.device.one":    "perangkat",
	"word.device.few":    "perangkat",
	"word.device.many":   "perangkat",
	"word.hour.one":      "jam",
	"word.hour.few":      "jam",
	"word.hour.many":     "jam",
	"word.day.one":       "hari",
	"word.day.few":       "hari",
	"word.day.many":      "hari",
	"word.new_conn.one":  "koneksi baru",
	"word.new_conn.few":  "koneksi baru",
	"word.new_conn.many": "koneksi baru",
	"word.country.one":   "negara",
	"word.country.few":   "negara",
	"word.country.many":  "negara",
	"word.network.one":   "jaringan",
	"word.network.few":   "jaringan",
	"word.network.many":  "jaringan",

	// baseline description: unit, samples, counted noun
	"alert.baseline.same_hour": "%s pada jam yang sama (median dari %d %s)",
	"alert.baseline.all_hours": "%s (median dari %d %s dengan lalu lintas data)",

	// new device
	"alert.newdev.title":          "Perangkat baru di jaringan: %s",
	"alert.newdev.first":          "%s muncul di jaringan untuk pertama kalinya.",
	"alert.newdev.hostname":       "nama host %s",
	"alert.newdev.comment":        "komentar %s",
	"alert.newdev.vendor":         "produsen %s",
	"alert.newdev.kind":           "jenis (perkiraan) %s",
	"alert.newdev.randomized":     "Perangkat ini menggunakan alamat MAC acak (umum pada ponsel dan laptop).",
	"alert.newdev.advice_warning": "Perangkat ini tidak dapat dikenali dan memiliki alamat MAC tetap. Jika Anda tidak mengenalinya, pertimbangkan untuk memblokirnya.",
	"alert.newdev.advice_info":    "Jika Anda tidak mengenali perangkat ini, Anda dapat memasukkannya ke karantina.",

	// initial inventory summary
	"alert.inventory.title":    "Inventarisasi awal selesai: %d %s",
	"alert.inventory.found":    "Selama %d %s pertama, Guardian menemukan %d %s di jaringan (%s).",
	"alert.inventory.review":   "Silakan periksa daftar perangkat, lalu beri nama atau blokir perangkat yang tidak dikenal.",
	"alert.inventory.learning": "Pembelajaran perilaku normal berlangsung hingga %s; sampai saat itu, anomali perilaku tidak dilaporkan.",
	"alert.inventory.learned":  "Pembelajaran perilaku normal telah selesai; anomali perilaku kini dilaporkan.",

	// destinations (new country / new ASN)
	"alert.dest.examples":       ", misalnya %s",
	"alert.dest.line":           "%s: terkirim %s, diterima %s, %d %s%s.",
	"alert.country.title.one":   "%s berkomunikasi dengan negara baru: %s",
	"alert.country.title.many":  "%s berkomunikasi dengan beberapa negara baru: %s",
	"alert.country.first":       "Kontak pertama dengan negara %s",
	"alert.country.known":       "Sejauh ini perangkat telah berkomunikasi dengan %d %s (%s).",
	"alert.country.advice_crit": "%s: perangkat seperti ini biasanya tidak mengirim data ke negara baru (terkirim ≥ %s). Jika Anda tidak mengubah apa pun, pertimbangkan untuk memasukkan perangkat ini ke karantina.",
	"alert.country.advice_warn": "Ini mungkin pembaruan atau layanan baru; jika Anda tidak mengharapkannya, periksa perangkat tersebut.",
	"alert.asn.title.one":       "%s berkomunikasi dengan jaringan baru: %s",
	"alert.asn.title.many":      "%s berkomunikasi dengan %d jaringan baru",
	"alert.asn.first":           "Kontak pertama dengan jaringan %s",
	"alert.asn.known":           "%s: perangkat seperti ini biasanya hanya berkomunikasi dengan sedikit tujuan yang tetap (sejauh ini %d %s).",

	// upload spike
	"alert.spike.title":       "%s mengunggah %s",
	"alert.spike.detail":      "Pada pukul %s, perangkat mengunggah %s ke internet, padahal biasanya %s, yaitu %s lebih banyak.",
	"alert.spike.max":         "Maksimum selama %d %s terakhir: %s.",
	"alert.spike.advice_crit": "%s: perangkat seperti ini biasanya tidak mengunggah data sebanyak ini – mungkin rekaman sedang dikirim ke pihak yang tidak dikenal, atau perangkat telah diretas. Jika Anda tidak mengharapkannya, pertimbangkan karantina.",
	"alert.spike.advice_warn": "Ini mungkin pencadangan (backup) atau berbagi file berukuran besar; jika Anda tidak mengharapkannya, periksa perangkat tersebut.",
	"alert.spike.fast.title":  "%s saat ini mengunggah data dalam jumlah yang tidak biasa (%s)",
	"alert.spike.fast.detail": "Dalam %d menit terakhir, perangkat mengunggah %s ke internet, padahal biasanya mengirim %s, yaitu sudah %s lebih banyak.",

	// destination fan-out
	"alert.fanout.title":       "%s menghubungi %d alamat berbeda dalam satu jam",
	"alert.fanout.detail":      "Pada pukul %s, perangkat menghubungi %d alamat IP berbeda di internet (%d koneksi baru), padahal biasanya %s, yaitu %s lebih banyak.",
	"alert.fanout.max":         "Maksimum sebelumnya: %s.",
	"alert.fanout.explain":     "Perilaku seperti ini khas untuk pemindaian internet atau perangkat yang menjadi bagian dari botnet.",
	"alert.fanout.advice_crit": "Pertimbangkan untuk memasukkan perangkat ini ke karantina dan memperbarui firmware-nya.",
}

func init() { Register("id", alertsID) }
