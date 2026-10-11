package i18n

// Alert texts of internal/detect (Turkish). Nouns after numbers stay singular
// in Turkish ("3 cihaz"), so the .one/.few/.many forms are identical.
// Inserted values (device names, countries, networks) can be any text, so the
// sentences never attach suffixes to them.
var alertsTR = map[string]string{
	// number and date formatting
	"fmt.decimal":  ",",
	"fmt.datetime": "02.01.2006 15:04",
	"unit.B":       "B",
	"unit.kB":      "kB",
	"unit.MB":      "MB",
	"unit.GB":      "GB",
	"unit.TB":      "TB",

	"unit.per_hour":       "%s/sa",
	"unit.per_whole_hour": "bir saatte toplam %s",
	"unit.addr_per_hour":  "%s adres/sa",

	// device kinds (model.Kinds)
	"kind.phone":    "Telefon",
	"kind.tablet":   "Tablet",
	"kind.computer": "Bilgisayar",
	"kind.tv":       "TV",
	"kind.camera":   "Kamera",
	"kind.iot":      "Akıllı cihaz",
	"kind.speaker":  "Hoparlör",
	"kind.console":  "Oyun konsolu",
	"kind.printer":  "Yazıcı",
	"kind.nas":      "NAS",
	"kind.network":  "Ağ cihazı",
	"kind.unknown":  "Cihaz",

	// counted nouns
	"word.device.one":    "cihaz",
	"word.device.few":    "cihaz",
	"word.device.many":   "cihaz",
	"word.hour.one":      "saat",
	"word.hour.few":      "saat",
	"word.hour.many":     "saat",
	"word.day.one":       "gün",
	"word.day.few":       "gün",
	"word.day.many":      "gün",
	"word.new_conn.one":  "yeni bağlantı",
	"word.new_conn.few":  "yeni bağlantı",
	"word.new_conn.many": "yeni bağlantı",
	"word.country.one":   "ülke",
	"word.country.few":   "ülke",
	"word.country.many":  "ülke",
	"word.network.one":   "ağ",
	"word.network.few":   "ağ",
	"word.network.many":  "ağ",

	// baseline description: unit, samples, counted noun
	"alert.baseline.same_hour": "günün bu saatinde %s (%d %s üzerinden medyan)",
	"alert.baseline.all_hours": "%s (trafik olan %d %s üzerinden medyan)",

	// new device
	"alert.newdev.title":          "Ağda yeni cihaz: %s",
	"alert.newdev.first":          "%s ağda ilk kez göründü.",
	"alert.newdev.hostname":       "ana bilgisayar adı %s",
	"alert.newdev.comment":        "açıklama %s",
	"alert.newdev.vendor":         "üretici %s",
	"alert.newdev.kind":           "tür (tahmini) %s",
	"alert.newdev.randomized":     "Cihaz rastgele bir MAC adresi kullanıyor (telefonlar ve dizüstü bilgisayarlar için tipiktir).",
	"alert.newdev.advice_warning": "Cihaz tanımlanamadı ve sabit bir MAC adresi kullanıyor. Cihazı tanımıyorsanız engellemeyi düşünün.",
	"alert.newdev.advice_info":    "Cihazı tanımıyorsanız karantinaya alabilirsiniz.",

	// initial inventory summary
	"alert.inventory.title":    "İlk envanter tamamlandı: %d %s",
	"alert.inventory.found":    "İlk %d %s içinde Guardian ağda %d %s buldu (%s).",
	"alert.inventory.review":   "Lütfen cihaz listesini gözden geçirin; tanımadığınız cihazları adlandırın veya engelleyin.",
	"alert.inventory.learning": "Normal davranışın öğrenilmesi %s tarihine kadar sürüyor; o zamana kadar davranış anomalileri bildirilmez.",
	"alert.inventory.learned":  "Normal davranışın öğrenilmesi tamamlandı; davranış anomalileri artık bildiriliyor.",

	// destinations (new country / new ASN)
	"alert.dest.examples":       ", ör. %s",
	"alert.dest.line":           "%s: gönderilen %s, alınan %s, %d %s%s.",
	"alert.country.title.one":   "%s yeni bir ülkeyle iletişim kuruyor: %s",
	"alert.country.title.many":  "%s yeni ülkelerle iletişim kuruyor: %s",
	"alert.country.first":       "İlk kez iletişim kurulan ülke %s",
	"alert.country.known":       "Cihaz şimdiye kadar %d %s ile iletişim kurdu (%s).",
	"alert.country.advice_crit": "%s: bu tür cihazlar normalde yeni ülkelere veri göndermez (gönderilen ≥ %s). Hiçbir şeyi değiştirmediyseniz cihazı karantinaya almayı düşünün.",
	"alert.country.advice_warn": "Bu bir güncelleme veya yeni bir hizmet olabilir; beklemiyorduysanız cihazı kontrol edin.",
	"alert.asn.title.one":       "%s yeni bir ağla iletişim kuruyor: %s",
	"alert.asn.title.many":      "%s, %d yeni ağla iletişim kuruyor",
	"alert.asn.first":           "İlk kez iletişim kurulan ağ %s",
	"alert.asn.known":           "%s: bu tür cihazlar genellikle az sayıda ve sabit hedefle iletişim kurar (şimdiye kadar %d %s).",

	// upload spike
	"alert.spike.title":       "%s veri yüklüyor: %s",
	"alert.spike.detail":      "%s saatleri arasında cihaz internete %s yükledi; normalde %s, yani %s daha fazla.",
	"alert.spike.max":         "Son %d %s içindeki en yüksek değer: %s.",
	"alert.spike.advice_crit": "%s: bu tür cihazlar normalde bu kadar çok veri yüklemez – kayıtlar yabancı birine gönderiliyor olabilir veya cihaz ele geçirilmiş olabilir. Bunu beklemiyorduysanız karantinayı düşünün.",
	"alert.spike.advice_warn": "Bu bir yedekleme veya büyük dosyaların paylaşılması olabilir; beklemiyorduysanız cihazı kontrol edin.",
	"alert.spike.fast.title":  "%s şu anda olağandışı miktarda veri yüklüyor (%s)",
	"alert.spike.fast.detail": "Son %d dakikada cihaz internete %s yükledi; normalde %s gönderir, yani şimdiden %s daha fazla.",

	// destination fan-out
	"alert.fanout.title":       "%s bir saat içinde %d farklı adresle iletişim kurdu",
	"alert.fanout.detail":      "%s saatleri arasında cihaz internette %d farklı IP adresiyle iletişim kurdu (%d yeni bağlantı); normalde %s, yani %s daha fazla.",
	"alert.fanout.max":         "Önceki en yüksek değer: %s.",
	"alert.fanout.explain":     "Bu davranış genellikle internet taramasına veya cihazın bir botnet ağına dahil olduğuna işaret eder.",
	"alert.fanout.advice_crit": "Cihazı karantinaya almayı ve ürün yazılımını (firmware) güncellemeyi düşünün.",
}

func init() { Register("tr", alertsTR) }
