package i18n

// Alert texts of internal/detect (Ukrainian). Counted nouns use the suffixes
// .one/.few/.many (one: 1, 21, 31…; few: 2–4, 22–24…; many: 0, 5–20, 25…),
// each in the case its sentence needs: word.hour accusative after "за",
// word.country instrumental after "з", the others nominative/accusative.
// Sentences avoid past-tense verbs agreeing with the device name.
var alertsUK = map[string]string{
	// number and date formatting
	"fmt.decimal":  ",",
	"fmt.datetime": "02.01.2006 15:04",
	"unit.B":       "Б",
	"unit.kB":      "КБ",
	"unit.MB":      "МБ",
	"unit.GB":      "ГБ",
	"unit.TB":      "ТБ",

	"unit.per_hour":       "%s/год",
	"unit.per_whole_hour": "%s за всю годину",
	"unit.addr_per_hour":  "%s адрес/год",

	// device kinds (model.Kinds)
	"kind.phone":    "Телефон",
	"kind.tablet":   "Планшет",
	"kind.computer": "Комп’ютер",
	"kind.tv":       "Телевізор",
	"kind.camera":   "Камера",
	"kind.iot":      "Розумний пристрій",
	"kind.speaker":  "Колонка",
	"kind.console":  "Ігрова консоль",
	"kind.printer":  "Принтер",
	"kind.nas":      "NAS",
	"kind.network":  "Мережевий пристрій",
	"kind.unknown":  "Пристрій",

	// counted nouns
	"word.device.one":    "пристрій",
	"word.device.few":    "пристрої",
	"word.device.many":   "пристроїв",
	"word.hour.one":      "годину",
	"word.hour.few":      "години",
	"word.hour.many":     "годин",
	"word.day.one":       "день",
	"word.day.few":       "дні",
	"word.day.many":      "днів",
	"word.new_conn.one":  "нове з’єднання",
	"word.new_conn.few":  "нові з’єднання",
	"word.new_conn.many": "нових з’єднань",
	"word.country.one":   "країною",
	"word.country.few":   "країнами",
	"word.country.many":  "країнами",
	"word.network.one":   "мережа",
	"word.network.few":   "мережі",
	"word.network.many":  "мереж",

	// baseline description: unit, samples, counted noun
	"alert.baseline.same_hour": "%s у цей час доби (медіана за %d %s)",
	"alert.baseline.all_hours": "%s (медіана за %d %s із трафіком)",

	// new device
	"alert.newdev.title":          "Новий пристрій у мережі: %s",
	"alert.newdev.first":          "У мережі вперше з’явився пристрій %s.",
	"alert.newdev.hostname":       "ім’я хоста %s",
	"alert.newdev.comment":        "коментар %s",
	"alert.newdev.vendor":         "виробник %s",
	"alert.newdev.kind":           "ймовірний тип %s",
	"alert.newdev.randomized":     "Пристрій використовує випадкову MAC-адресу (це типово для телефонів і ноутбуків).",
	"alert.newdev.advice_warning": "Пристрій не вдалося розпізнати, і він має фіксовану MAC-адресу. Якщо ви не впізнаєте цей пристрій, розгляньте можливість його заблокувати.",
	"alert.newdev.advice_info":    "Якщо ви не впізнаєте цей пристрій, можете помістити його в карантин.",

	// initial inventory summary
	"alert.inventory.title":    "Початкову інвентаризацію завершено: %d %s",
	"alert.inventory.found":    "За перші %d %s Guardian знайшов у мережі %d %s (%s).",
	"alert.inventory.review":   "Перегляньте список пристроїв і позначте або заблокуйте невідомі.",
	"alert.inventory.learning": "Вивчення звичайної поведінки триває до %s; до того часу Guardian не повідомляє про аномалії поведінки.",
	"alert.inventory.learned":  "Вивчення звичайної поведінки завершено; тепер Guardian повідомляє про аномалії поведінки.",

	// destinations (new country / new ASN)
	"alert.dest.examples":       ", напр. %s",
	"alert.dest.line":           "%s: надіслано %s, отримано %s, %d %s%s.",
	"alert.country.title.one":   "%s зв’язується з новою країною: %s",
	"alert.country.title.many":  "%s зв’язується з новими країнами: %s",
	"alert.country.first":       "Перший зв’язок із країною %s",
	"alert.country.known":       "Досі пристрій зв’язувався з %d %s (%s).",
	"alert.country.advice_crit": "%s: такі пристрої зазвичай не надсилають дані до нових країн (надіслано ≥ %s). Якщо ви нічого не змінювали, розгляньте можливість помістити пристрій у карантин.",
	"alert.country.advice_warn": "Це може бути оновлення або новий сервіс; якщо ви цього не очікували, перевірте пристрій.",
	"alert.asn.title.one":       "%s зв’язується з новою мережею: %s",
	"alert.asn.title.many":      "%s зв’язується з новими мережами (%d)",
	"alert.asn.first":           "Перший зв’язок із мережею %s",
	"alert.asn.known":           "%s: такі пристрої зазвичай мають невелике й стале коло адресатів (досі %d %s).",

	// upload spike
	"alert.spike.title":       "%s надсилає %s",
	"alert.spike.detail":      "Протягом години %s пристрій надіслав в інтернет %s, зазвичай %s, тобто в %s більше.",
	"alert.spike.max":         "Максимум за останні %d %s: %s.",
	"alert.spike.advice_crit": "%s: такі пристрої зазвичай не надсилають стільки даних – можливо, записи надсилаються сторонній особі або пристрій зламано. Якщо ви цього не очікували, розгляньте можливість карантину.",
	"alert.spike.advice_warn": "Це може бути резервне копіювання або обмін великими файлами; якщо ви цього не очікували, перевірте пристрій.",
	"alert.spike.fast.title":  "%s зараз надсилає незвично багато даних (%s)",
	"alert.spike.fast.detail": "За останні %d хв пристрій надіслав в інтернет %s, хоча зазвичай надсилає %s, тобто вже в %s більше.",

	// destination fan-out
	"alert.fanout.title":       "%s звертається до великої кількості адрес: %d за годину",
	"alert.fanout.detail":      "Протягом години %s пристрій звертався до різних IP-адрес в інтернеті: %d (нових з’єднань: %d), зазвичай %s, тобто в %s більше.",
	"alert.fanout.max":         "Попередній максимум: %s.",
	"alert.fanout.explain":     "Така поведінка типова для сканування інтернету або участі в ботнеті.",
	"alert.fanout.advice_crit": "Розгляньте можливість помістити пристрій у карантин і оновити його прошивку.",
}

func init() { Register("uk", alertsUK) }
