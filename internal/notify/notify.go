// Package notify delivers Guardian alerts to push channels (ntfy, Telegram)
// and implements model.AlertSink (store + dedup + async notification).
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// Notifier sends one alert to one channel.
type Notifier interface {
	Name() string
	Send(ctx context.Context, a model.Alert, d model.Device) error
}

// BuildNotifiers creates the notifiers configured in s: Telegram when both
// the bot token and chat ID are set, ntfy when the topic URL is set.
func BuildNotifiers(s settings.Settings) []Notifier {
	var ns []Notifier
	if s.TelegramToken != "" && s.TelegramChatID != "" {
		ns = append(ns, NewTelegram(s.TelegramToken, s.TelegramChatID))
	}
	if s.NtfyURL != "" {
		ns = append(ns, NewNtfy(s.NtfyURL, s.NtfyToken))
	}
	return ns
}

const httpTimeout = 10 * time.Second

// retryDelay is the pause before the single retry (variable for tests).
var retryDelay = 2 * time.Second

// langKey carries the message language from the Sink to the notifiers
// (the Notifier interface has no language parameter).
type langKey struct{}

func withLang(ctx context.Context, lang string) context.Context {
	return context.WithValue(ctx, langKey{}, lang)
}

// langFrom returns the message language stored in ctx (default English).
func langFrom(ctx context.Context) string {
	if l, ok := ctx.Value(langKey{}).(string); ok && l != "" {
		return l
	}
	return i18n.Fallback
}

// DeviceName is DeviceNameLang in English.
func DeviceName(d model.Device) string { return DeviceNameLang(d, i18n.Fallback) }

// DeviceNameLang returns the friendliest available name of a device:
// model.Device.DisplayName (Note > Comment > Hostname > Vendor > MAC) with
// whitespace-only fields ignored, or the localized "unknown device".
func DeviceNameLang(d model.Device, lang string) string {
	d.Note = strings.TrimSpace(d.Note)
	d.Comment = strings.TrimSpace(d.Comment)
	d.Hostname = strings.TrimSpace(d.Hostname)
	d.Vendor = strings.TrimSpace(d.Vendor)
	d.MAC = strings.TrimSpace(d.MAC)
	if s := d.DisplayName(); s != "" {
		return s
	}
	return i18n.T(lang, "notify.unknown")
}

// deviceLine is a one-line description of the device for message bodies,
// e.g. "Device: TV (192.168.88.10, AA:BB:CC:DD:EE:FF)".
func deviceLine(lang string, a model.Alert, d model.Device) string {
	if d.MAC == "" {
		d.MAC = a.DeviceMAC
	}
	if d.MAC == "" {
		return ""
	}
	name := DeviceNameLang(d, lang)
	var extra []string
	if d.IP.IsValid() {
		extra = append(extra, d.IP.String())
	}
	if name != strings.TrimSpace(d.MAC) {
		extra = append(extra, d.MAC)
	}
	switch len(extra) {
	case 2:
		return i18n.T(lang, "notify.device", name, extra[0], extra[1])
	case 1:
		return i18n.T(lang, "notify.device.one", name, extra[0])
	default:
		return i18n.T(lang, "notify.device.name", name)
	}
}

// ---------------------------------------------------------------------------
// ntfy
// ---------------------------------------------------------------------------

type ntfy struct {
	topicURL string
	token    string
	client   *http.Client
}

// NewNtfy returns a Notifier publishing to a ntfy topic URL
// (e.g. https://ntfy.sh/my-secret-topic). token is optional (Bearer).
func NewNtfy(topicURL, token string) Notifier {
	return &ntfy{topicURL: topicURL, token: token, client: &http.Client{Timeout: httpTimeout}}
}

func (n *ntfy) Name() string { return "ntfy" }

func ntfyPriority(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "5"
	case model.SevWarning:
		return "4"
	default:
		return "3"
	}
}

func ntfyTags(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "rotating_light"
	case model.SevWarning:
		return "warning"
	default:
		return "information_source"
	}
}

// headerText makes s safe for an HTTP header: strips control chars and uses
// RFC 2047 encoding for non-ASCII (ntfy decodes it).
func headerText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return mime.BEncoding.Encode("UTF-8", s)
		}
	}
	return s
}

// Send publishes the alert; the device line uses the language set on ctx by
// the Sink (English otherwise).
func (n *ntfy) Send(ctx context.Context, a model.Alert, d model.Device) error {
	body := a.Detail
	if line := deviceLine(langFrom(ctx), a, d); line != "" {
		if body != "" {
			body += "\n"
		}
		body += line
	}
	title := a.Title
	if title == "" {
		title = "Guardian: " + a.Kind
	}
	return doWithRetry(ctx, n.client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.topicURL, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Title", headerText(title))
		req.Header.Set("Priority", ntfyPriority(a.Severity))
		req.Header.Set("Tags", ntfyTags(a.Severity))
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		if n.token != "" {
			req.Header.Set("Authorization", "Bearer "+n.token)
		}
		return req, nil
	})
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

type telegram struct {
	baseURL string // https://api.telegram.org (overridable in tests)
	token   string
	chatID  string
	client  *http.Client
}

// NewTelegram returns a Notifier using the Telegram Bot API sendMessage method.
func NewTelegram(token, chatID string) Notifier {
	return &telegram{baseURL: "https://api.telegram.org", token: token, chatID: chatID,
		client: &http.Client{Timeout: httpTimeout}}
}

func (t *telegram) Name() string { return "telegram" }

const telegramMaxLen = 4096

func sevIcon(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "🚨"
	case model.SevWarning:
		return "⚠️"
	default:
		return "ℹ️"
	}
}

func telegramText(lang string, a model.Alert, d model.Device) string {
	var b strings.Builder
	b.WriteString(sevIcon(a.Severity))
	b.WriteString(" <b>")
	title := a.Title
	if title == "" {
		title = "Guardian: " + a.Kind
	}
	b.WriteString(html.EscapeString(title))
	b.WriteString("</b>")
	if a.Detail != "" {
		b.WriteString("\n")
		b.WriteString(html.EscapeString(truncate(a.Detail, 3000)))
	}
	if line := deviceLine(lang, a, d); line != "" {
		b.WriteString("\n<i>")
		b.WriteString(html.EscapeString(line))
		b.WriteString("</i>")
	}
	return b.String()
}

// truncate cuts s to at most max bytes on a rune boundary.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + "…"
}

// Send posts the alert; the device line uses the language set on ctx by the
// Sink (English otherwise).
func (t *telegram) Send(ctx context.Context, a model.Alert, d model.Device) error {
	payload, err := json.Marshal(map[string]any{
		"chat_id":                  t.chatID,
		"text":                     telegramText(langFrom(ctx), a, d),
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(t.baseURL, "/") + "/bot" + t.token + "/sendMessage"
	err = doWithRetry(ctx, t.client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
	if err != nil && t.token != "" {
		// never leak the bot token into logs (it is part of the URL)
		err = errors.New(strings.ReplaceAll(err.Error(), t.token, "***"))
	}
	return err
}

// ---------------------------------------------------------------------------
// HTTP helper
// ---------------------------------------------------------------------------

type statusError struct {
	code int
	body string
}

func (e *statusError) Error() string {
	return fmt.Sprintf("http %d: %s", e.code, e.body)
}

// retryable reports whether one more attempt makes sense.
func retryable(err error) bool {
	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= 500
	}
	return !errors.Is(err, context.Canceled)
}

// doWithRetry performs the request built by mk, retrying at most once on
// network errors, 429 and 5xx.
func doWithRetry(ctx context.Context, c *http.Client, mk func() (*http.Request, error)) error {
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			delay := retryDelay
			if se := (*statusError)(nil); errors.As(err, &se) && se.code == http.StatusTooManyRequests {
				delay = 2 * retryDelay
			}
			select {
			case <-ctx.Done():
				return errors.Join(err, ctx.Err())
			case <-time.After(delay):
			}
		}
		err = doOnce(c, mk)
		if err == nil || !retryable(err) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func doOnce(c *http.Client, mk func() (*http.Request, error)) error {
	req, err := mk()
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode/100 != 2 {
		return &statusError{code: resp.StatusCode, body: strings.TrimSpace(string(b))}
	}
	return nil
}
