// Command demo lets you try Guardian for RouterOS without a router.
//
// It seeds a Guardian database with a fictional household (18 devices, a
// week of traffic, a few alerts raised by the real detection engine) and then
// serves a fake RouterOS REST API for that household, so that cmd/guardian
// can run against it. It is also used for the README screenshots.
//
//	go run ./tools/demo -reset
//	# then, in a second terminal, the command it prints, e.g.
//	GUARDIAN_ROS_URL=http://127.0.0.1:18728 GUARDIAN_ROS_PASS=demo GUARDIAN_DB=demo.db \
//	    GUARDIAN_LAN=192.168.88.0/24 GUARDIAN_LISTEN=127.0.0.1:8080 go run ./cmd/guardian
//
// All device names, addresses and MAC suffixes are made up. Without -reset
// an existing demo database is reused as is; -reset re-seeds it relative to
// the current time and refuses to delete a database this tool did not create.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Marteva/routeros-guardian/internal/store"
)

type options struct {
	db, listen, ui, geo string
	reset               bool
}

func main() {
	var o options
	flag.StringVar(&o.db, "db", "demo.db", "Guardian database to seed (SQLite file)")
	flag.StringVar(&o.listen, "listen", "127.0.0.1:18728", "listen address of the fake RouterOS REST API")
	flag.BoolVar(&o.reset, "reset", false, "delete and re-seed the database (only one created by this tool)")
	flag.StringVar(&o.ui, "ui", "127.0.0.1:8080", "GUARDIAN_LISTEN used in the printed guardian command")
	flag.StringVar(&o.geo, "geoip", filepath.Join("dist", "geo"),
		"directory with DB-IP Lite country.mmdb and asn.mmdb; added to the printed command when present")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(o, log); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run(o options, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := filepath.Abs(o.db)
	if err != nil {
		return err
	}
	hh := newHousehold()
	state, err := prepareDB(ctx, db, o.reset, hh, time.Now())
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: newFakeRouter(hh, time.Now, log), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("fake router", "err", err)
			stop()
		}
	}()

	printInstructions(os.Stdout, instructions{
		api:     browseURL(ln.Addr().String()),
		ui:      browseURL(o.ui),
		uiArg:   o.ui,
		db:      db,
		geo:     geoFiles(o.geo),
		state:   state,
		hh:      hh,
		clashes: clashes(hh, localAddrs()),
	})
	<-ctx.Done()
	shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(shut)
}

// ---------------------------------------------------------------------------
// database

// dbState describes the database the demo serves.
type dbState struct {
	seeded   bool      // seeded by this run (stats valid)
	seededAt time.Time // when the data was seeded ("now" of the story)
	stats    seedStats
}

// prepareDB seeds path unless it already holds demo data. With reset an
// existing demo database is deleted and seeded again. A database that was
// not created by this tool (no marker, but devices) is never touched.
func prepareDB(ctx context.Context, path string, reset bool, hh *household, now time.Time) (dbState, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		demo, seededAt, devices, err := inspectDB(path)
		if err != nil {
			return dbState{}, fmt.Errorf("%s: %w", path, err)
		}
		switch {
		case !demo && devices > 0:
			return dbState{}, fmt.Errorf("%s is not a demo database (it holds %d devices); refusing to touch it, use another -db path", path, devices)
		case reset:
			if err := removeDB(path); err != nil {
				return dbState{}, fmt.Errorf("%w (stop Guardian before -reset)", err)
			}
		case demo:
			return dbState{seededAt: seededAt}, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return dbState{}, err
	}

	st, err := store.Open(path)
	if err != nil {
		return dbState{}, err
	}
	stats, err := seed(ctx, st, hh, now)
	if cerr := st.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = removeDB(path) // never leave a half-seeded database behind
		return dbState{}, err
	}
	return dbState{seeded: true, seededAt: newTimeline(now).now, stats: stats}, nil
}

// inspectDB reports whether path is a demo database and how many devices it has.
func inspectDB(path string) (demo bool, seededAt time.Time, devices int, err error) {
	st, err := store.Open(path)
	if err != nil {
		return false, time.Time{}, 0, err
	}
	defer st.Close()
	ctx := context.Background()
	kv, err := st.Settings(ctx)
	if err != nil {
		return false, time.Time{}, 0, err
	}
	devs, err := st.Devices(ctx)
	if err != nil {
		return false, time.Time{}, 0, err
	}
	v, demo := kv[markerKey]
	seededAt, _ = time.Parse(time.RFC3339, v)
	return demo, seededAt, len(devs), nil
}

// removeDB deletes the database and its WAL/SHM side files.
func removeDB(path string) error {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// instructions

type instructions struct {
	api, ui, uiArg, db string
	geo                []string // country and ASN mmdb, or nil
	state              dbState
	hh                 *household
	clashes            []string // demo devices that share an IP with this PC
}

// localAddrs returns this PC's own unicast addresses.
func localAddrs() []netip.Addr {
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifAddrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// clashes describes online demo devices whose IP this PC also has. Guardian
// leaves its own addresses out of monitoring, so such a device would get no
// live updates (a PC on a real MikroTik LAN often has a 192.168.88.x address).
func clashes(hh *household, local []netip.Addr) []string {
	var out []string
	for _, d := range hh.online() {
		if slices.Contains(local, d.ip) {
			name := d.note
			if name == "" {
				name = d.comment
			}
			out = append(out, fmt.Sprintf("%s (%s)", d.ip, name))
		}
	}
	return out
}

// browseURL turns a listen address into a URL a browser/client can use.
func browseURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// geoFiles returns the absolute paths of dir/country.mmdb and dir/asn.mmdb
// if both exist.
func geoFiles(dir string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	for _, name := range []string{"country.mmdb", "asn.mmdb"} {
		p, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil {
			return nil
		}
		if _, err := os.Stat(p); err != nil {
			return nil
		}
		out = append(out, p)
	}
	return out
}

// shellQuote quotes v for POSIX shells unless it only has safe characters.
func shellQuote(v string) string {
	safe := v != "" && strings.IndexFunc(v, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_-.,:/@%+=", r))
	}) < 0
	if safe {
		return v
	}
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

func printInstructions(w io.Writer, in instructions) {
	env := [][2]string{
		{"GUARDIAN_ROS_URL", in.api},
		{"GUARDIAN_ROS_PASS", "demo"},
		{"GUARDIAN_DB", in.db},
		{"GUARDIAN_LAN", "192.168.88.0/24"},
		{"GUARDIAN_LISTEN", in.uiArg},
	}
	if len(in.geo) == 2 {
		env = append(env, [2]string{"GUARDIAN_GEOIP_COUNTRY", in.geo[0]}, [2]string{"GUARDIAN_GEOIP_ASN", in.geo[1]})
	}
	var ps, sh []string
	for _, kv := range env {
		ps = append(ps, fmt.Sprintf("$env:%s='%s'", kv[0], strings.ReplaceAll(kv[1], "'", "''")))
		sh = append(sh, kv[0]+"="+shellQuote(filepath.ToSlash(kv[1])))
	}

	fmt.Fprintln(w, "Guardian for RouterOS - demo with a fictional household (no real network data)")
	fmt.Fprintln(w)
	if in.state.seeded {
		s := in.state.stats
		fmt.Fprintf(w, "  Database       %s\n                 seeded now: %d devices (%d MAC addresses), %d alerts, %d hourly traffic rows\n",
			in.db, s.Rows, s.Devices, s.Alerts, s.HourRows)
	} else {
		fmt.Fprintf(w, "  Database       %s\n                 reused, seeded %s (-reset re-seeds it relative to now)\n",
			in.db, in.state.seededAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintf(w, "  Fake RouterOS  %s/rest  (%d devices online, any user/password)\n", in.api, len(in.hh.online()))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Start Guardian in a second terminal, in the repository root:")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  PowerShell:")
	fmt.Fprintf(w, "    %s; go run ./cmd/guardian\n", strings.Join(ps, "; "))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  bash / zsh:")
	fmt.Fprintf(w, "    %s go run ./cmd/guardian\n", strings.Join(sh, " "))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Then open %s. Press Ctrl+C here to stop the fake router.\n", in.ui)
	if len(in.geo) != 2 {
		fmt.Fprintln(w, "Tip: with DB-IP Lite files in dist/geo (scripts/update-geoip.*) new traffic gets countries and ASNs too.")
	}
	if len(in.clashes) > 0 {
		fmt.Fprintf(w, "Note: this PC also has the address of demo device %s. Guardian ignores its own\n"+
			"addresses, so that device gets no live updates in the demo.\n", strings.Join(in.clashes, ", "))
	}
}
