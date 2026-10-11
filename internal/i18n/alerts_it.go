package i18n

// Alert texts of internal/detect (Italian).
var alertsIT = map[string]string{
	// number and date formatting
	"fmt.decimal":  ",",
	"fmt.datetime": "02/01/2006 15:04",
	"unit.B":       "B",
	"unit.kB":      "kB",
	"unit.MB":      "MB",
	"unit.GB":      "GB",
	"unit.TB":      "TB",

	"unit.per_hour":       "%s/h",
	"unit.per_whole_hour": "%s in un'ora intera",
	"unit.addr_per_hour":  "%s indirizzi/h",

	// device kinds (model.Kinds)
	"kind.phone":    "Telefono",
	"kind.tablet":   "Tablet",
	"kind.computer": "Computer",
	"kind.tv":       "TV",
	"kind.camera":   "Telecamera",
	"kind.iot":      "Dispositivo smart",
	"kind.speaker":  "Altoparlante",
	"kind.console":  "Console di gioco",
	"kind.printer":  "Stampante",
	"kind.nas":      "NAS",
	"kind.network":  "Dispositivo di rete",
	"kind.unknown":  "Dispositivo",

	// counted nouns
	"word.device.one":    "dispositivo",
	"word.device.few":    "dispositivi",
	"word.device.many":   "dispositivi",
	"word.hour.one":      "ora",
	"word.hour.few":      "ore",
	"word.hour.many":     "ore",
	"word.day.one":       "giorno",
	"word.day.few":       "giorni",
	"word.day.many":      "giorni",
	"word.new_conn.one":  "nuova connessione",
	"word.new_conn.few":  "nuove connessioni",
	"word.new_conn.many": "nuove connessioni",
	"word.country.one":   "paese",
	"word.country.few":   "paesi",
	"word.country.many":  "paesi",
	"word.network.one":   "rete",
	"word.network.few":   "reti",
	"word.network.many":  "reti",

	// baseline description: unit, samples, counted noun
	"alert.baseline.same_hour": "%s a quest'ora del giorno (mediana su %d %s)",
	"alert.baseline.all_hours": "%s (mediana su %d %s con traffico)",

	// new device
	"alert.newdev.title":          "Nuovo dispositivo in rete: %s",
	"alert.newdev.first":          "%s è in rete per la prima volta.",
	"alert.newdev.hostname":       "nome host %s",
	"alert.newdev.comment":        "commento %s",
	"alert.newdev.vendor":         "produttore %s",
	"alert.newdev.kind":           "tipo (stimato) %s",
	"alert.newdev.randomized":     "Il dispositivo usa un indirizzo MAC casuale (tipico di telefoni e portatili).",
	"alert.newdev.advice_warning": "Non è stato possibile identificare il dispositivo, che ha un indirizzo MAC fisso. Se non lo riconosci, valuta di bloccarlo.",
	"alert.newdev.advice_info":    "Se non riconosci il dispositivo, puoi metterlo in quarantena.",

	// initial inventory summary
	"alert.inventory.title":    "Inventario iniziale completato: %d %s",
	"alert.inventory.found":    "Nelle prime %d %s Guardian ha trovato %d %s in rete (%s).",
	"alert.inventory.review":   "Controlla l'elenco dei dispositivi: dai un nome a quelli sconosciuti oppure bloccali.",
	"alert.inventory.learning": "L'apprendimento del comportamento normale prosegue fino al %s; fino ad allora le anomalie di comportamento non vengono segnalate.",
	"alert.inventory.learned":  "L'apprendimento del comportamento normale è terminato; d'ora in poi le anomalie di comportamento vengono segnalate.",

	// destinations (new country / new ASN)
	"alert.dest.examples":       ", ad es. %s",
	"alert.dest.line":           "%s: inviati %s, ricevuti %s, %d %s%s.",
	"alert.country.title.one":   "%s comunica con un nuovo paese: %s",
	"alert.country.title.many":  "%s comunica con nuovi paesi: %s",
	"alert.country.first":       "Primo contatto con il paese %s",
	"alert.country.known":       "Finora ha comunicato con %d %s (%s).",
	"alert.country.advice_crit": "%s: i dispositivi di questo tipo di solito non inviano dati verso nuovi paesi (inviati ≥ %s). Se non hai cambiato nulla, valuta di mettere il dispositivo in quarantena.",
	"alert.country.advice_warn": "Potrebbe trattarsi di un aggiornamento o di un nuovo servizio; se non te lo aspettavi, controlla il dispositivo.",
	"alert.asn.title.one":       "%s comunica con una nuova rete: %s",
	"alert.asn.title.many":      "%s comunica con %d nuove reti",
	"alert.asn.first":           "Primo contatto con la rete %s",
	"alert.asn.known":           "%s: i dispositivi di questo tipo di solito hanno un insieme piccolo e stabile di destinazioni (finora %d %s).",

	// upload spike
	"alert.spike.title":       "%s sta inviando %s",
	"alert.spike.detail":      "Nell'ora %s il dispositivo ha inviato %s verso internet, di solito %s, cioè %s in più.",
	"alert.spike.max":         "Massimo negli ultimi %d %s: %s.",
	"alert.spike.advice_crit": "%s: i dispositivi di questo tipo di solito non inviano così tanti dati – potrebbe trattarsi di registrazioni inviate a estranei o di un dispositivo compromesso. Se non te lo aspettavi, valuta la quarantena.",
	"alert.spike.advice_warn": "Potrebbe trattarsi di un backup o della condivisione di file di grandi dimensioni; se non te lo aspettavi, controlla il dispositivo.",
	"alert.spike.fast.title":  "%s sta inviando una quantità insolita di dati in questo momento (%s)",
	"alert.spike.fast.detail": "Negli ultimi %d min il dispositivo ha inviato %s verso internet, mentre di solito ne invia %s, cioè già %s in più.",

	// destination fan-out
	"alert.fanout.title":       "%s ha contattato %d indirizzi diversi in un'ora",
	"alert.fanout.detail":      "Nell'ora %s il dispositivo ha contattato %d indirizzi IP diversi su internet (%d nuove connessioni), di solito %s, cioè %s in più.",
	"alert.fanout.max":         "Massimo precedente: %s.",
	"alert.fanout.explain":     "Questo comportamento è tipico di una scansione di internet o della partecipazione a una botnet.",
	"alert.fanout.advice_crit": "Valuta di mettere il dispositivo in quarantena e di aggiornarne il firmware.",
}

func init() { Register("it", alertsIT) }
