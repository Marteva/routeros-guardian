// Command mkimage assembles a single-layer container image tarball in the
// `docker save` format (manifest.json + repositories + <id>/layer.tar) without
// needing Docker. RouterOS `/container/add file=...` imports such tarballs.
//
// Layers are stored uncompressed (RouterOS historically does not accept
// gzip-compressed layers in imported tarballs).
//
// Example:
//
//	go run ./tools/mkimage -out dist/routeros-guardian-arm64.tar -tag routeros-guardian:latest \
//	    -exec /guardian=dist/linux-arm64/guardian \
//	    -exec /probe=dist/linux-arm64/probe \
//	    -file /etc/ssl/certs/ca-certificates.crt=tools/mkimage/cacert.pem
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// fileSpec is one file to put into the layer.
type fileSpec struct {
	Dst  string // absolute path inside the image, e.g. /guardian
	Src  string // local path
	Mode int64
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// options fully describe the image to build.
type options struct {
	Out        string
	Tag        string
	Arch       string
	Variant    string
	OS         string
	Files      []fileSpec
	Dirs       []string // extra empty directories
	Env        []string
	Entrypoint []string
	Cmd        []string
	WorkingDir string
	User       string
	Expose     []string
	Volumes    []string
	Labels     map[string]string
	Created    time.Time
	// Healthcheck: exec form argv (empty = none) and its timing.
	Health         []string
	HealthInterval time.Duration
	HealthTimeout  time.Duration
	HealthStart    time.Duration
	HealthRetries  int
}

func main() {
	var (
		execs, files, dirs, envs, exposes, volumes, labels, cmds multiFlag
		o                                                        options
		entry, created, health                                   string
	)
	flag.StringVar(&o.Out, "out", "guardian-arm64.tar", "output tarball")
	flag.StringVar(&o.Tag, "tag", "guardian:latest", "repo:tag stored in manifest.json")
	flag.StringVar(&o.Arch, "arch", "arm64", "image architecture (arm64, arm, amd64)")
	flag.StringVar(&o.Variant, "variant", "", "architecture variant (e.g. v8 for arm64, v7 for arm); empty = auto")
	flag.StringVar(&o.OS, "os", "linux", "image OS")
	flag.Var(&execs, "exec", "executable to add, /dst=localsrc (mode 0755); repeatable")
	flag.Var(&files, "file", "regular file to add, /dst=localsrc (mode 0644); repeatable")
	flag.Var(&dirs, "dir", "extra empty directory, e.g. /data; repeatable")
	flag.Var(&envs, "env", "KEY=VALUE default environment; repeatable")
	flag.StringVar(&entry, "entrypoint", "/guardian", "entrypoint, comma separated argv")
	flag.Var(&cmds, "cmd", "CMD argument; repeatable")
	flag.StringVar(&o.WorkingDir, "workdir", "/", "working directory")
	flag.StringVar(&o.User, "user", "", "user (empty = root; e.g. 65532:65532)")
	flag.Var(&exposes, "expose", "exposed port, e.g. 8080/tcp; repeatable")
	flag.Var(&volumes, "volume", "volume path, e.g. /data; repeatable")
	flag.Var(&labels, "label", "KEY=VALUE image label; repeatable")
	flag.StringVar(&created, "created", "", "RFC3339 creation time (default: SOURCE_DATE_EPOCH or now)")
	flag.StringVar(&health, "healthcheck", "", "HEALTHCHECK command, comma separated argv (exec form), e.g. /guardian,-healthcheck")
	flag.DurationVar(&o.HealthInterval, "health-interval", 30*time.Second, "healthcheck interval")
	flag.DurationVar(&o.HealthTimeout, "health-timeout", 5*time.Second, "healthcheck timeout")
	flag.DurationVar(&o.HealthStart, "health-start", 60*time.Second, "healthcheck start period")
	flag.IntVar(&o.HealthRetries, "health-retries", 3, "healthcheck retries")
	flag.Parse()

	var err error
	if health != "" {
		o.Health = strings.Split(health, ",")
	}
	if o.Created, err = parseCreated(created); err != nil {
		fatal(err)
	}
	for _, s := range execs {
		fs, err := parseFileSpec(s, 0o755)
		if err != nil {
			fatal(err)
		}
		o.Files = append(o.Files, fs)
	}
	for _, s := range files {
		fs, err := parseFileSpec(s, 0o644)
		if err != nil {
			fatal(err)
		}
		o.Files = append(o.Files, fs)
	}
	o.Dirs = dirs
	o.Env = envs
	if entry != "" {
		o.Entrypoint = strings.Split(entry, ",")
	}
	o.Cmd = cmds
	o.Expose = exposes
	o.Volumes = volumes
	o.Labels = map[string]string{}
	for _, l := range labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			fatal(fmt.Errorf("bad -label %q, want KEY=VALUE", l))
		}
		o.Labels[k] = v
	}
	if len(o.Files) == 0 {
		fatal(errors.New("nothing to add: use -exec / -file"))
	}

	f, err := os.Create(o.Out)
	if err != nil {
		fatal(err)
	}
	if err := build(f, o); err != nil {
		f.Close()
		os.Remove(o.Out)
		fatal(err)
	}
	if err := f.Close(); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%s, %s/%s)\n", o.Out, o.Tag, o.OS, o.Arch)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mkimage:", err)
	os.Exit(1)
}

func parseCreated(s string) (time.Time, error) {
	if s != "" {
		return time.Parse(time.RFC3339, s)
	}
	if e := os.Getenv("SOURCE_DATE_EPOCH"); e != "" {
		var sec int64
		if _, err := fmt.Sscan(e, &sec); err != nil {
			return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH: %w", err)
		}
		return time.Unix(sec, 0).UTC(), nil
	}
	return time.Now().UTC().Truncate(time.Second), nil
}

// parseFileSpec parses "/dst=src". The split is on the first '=' so Windows
// paths such as C:\x\y work as src.
func parseFileSpec(s string, mode int64) (fileSpec, error) {
	dst, src, ok := strings.Cut(s, "=")
	if !ok || dst == "" || src == "" {
		return fileSpec{}, fmt.Errorf("bad file spec %q, want /dst=localsrc", s)
	}
	dst = path.Clean("/" + strings.TrimPrefix(strings.ReplaceAll(dst, "\\", "/"), "/"))
	if dst == "/" {
		return fileSpec{}, fmt.Errorf("bad destination in %q", s)
	}
	return fileSpec{Dst: dst, Src: src, Mode: mode}, nil
}

// --- image JSON structures (docker image spec v1.2 / OCI-compatible subset) ---

type imageConfig struct {
	User         string              `json:"User,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	Env          []string            `json:"Env,omitempty"`
	Entrypoint   []string            `json:"Entrypoint,omitempty"`
	Cmd          []string            `json:"Cmd,omitempty"`
	Volumes      map[string]struct{} `json:"Volumes,omitempty"`
	WorkingDir   string              `json:"WorkingDir,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	Healthcheck  *healthConfig       `json:"Healthcheck,omitempty"`
}

// healthConfig mirrors Docker's HEALTHCHECK; durations are nanoseconds.
type healthConfig struct {
	Test        []string `json:"Test"`
	Interval    int64    `json:"Interval,omitempty"`
	Timeout     int64    `json:"Timeout,omitempty"`
	StartPeriod int64    `json:"StartPeriod,omitempty"`
	Retries     int      `json:"Retries,omitempty"`
}

type rootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type history struct {
	Created   string `json:"created"`
	CreatedBy string `json:"created_by"`
	Comment   string `json:"comment,omitempty"`
}

type image struct {
	Architecture string      `json:"architecture"`
	Variant      string      `json:"variant,omitempty"`
	OS           string      `json:"os"`
	Created      string      `json:"created"`
	Config       imageConfig `json:"config"`
	RootFS       rootFS      `json:"rootfs"`
	History      []history   `json:"history"`
}

type manifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// legacyLayerJSON is the per-layer "json" file of the v1 docker save format.
type legacyLayerJSON struct {
	ID           string      `json:"id"`
	Created      string      `json:"created"`
	Architecture string      `json:"architecture"`
	OS           string      `json:"os"`
	Config       imageConfig `json:"config"`
}

// build writes the complete docker-save tarball to w.
func build(w io.Writer, o options) error {
	layer, err := buildLayer(o)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(layer)
	diffID := "sha256:" + hex.EncodeToString(sum[:])
	layerID := hex.EncodeToString(sum[:]) // directory name inside the tarball

	variant := o.Variant
	if variant == "" {
		switch o.Arch {
		case "arm64":
			variant = "v8"
		case "arm":
			variant = "v7"
		}
	}
	cfg := imageConfig{
		User:       o.User,
		Env:        o.Env,
		Entrypoint: o.Entrypoint,
		Cmd:        o.Cmd,
		WorkingDir: o.WorkingDir,
	}
	if len(o.Expose) > 0 {
		cfg.ExposedPorts = map[string]struct{}{}
		for _, p := range o.Expose {
			if !strings.Contains(p, "/") {
				p += "/tcp"
			}
			cfg.ExposedPorts[p] = struct{}{}
		}
	}
	if len(o.Volumes) > 0 {
		cfg.Volumes = map[string]struct{}{}
		for _, v := range o.Volumes {
			cfg.Volumes[v] = struct{}{}
		}
	}
	if len(o.Labels) > 0 {
		cfg.Labels = o.Labels
	}
	if len(o.Health) > 0 {
		cfg.Healthcheck = &healthConfig{
			Test:        append([]string{"CMD"}, o.Health...),
			Interval:    int64(o.HealthInterval),
			Timeout:     int64(o.HealthTimeout),
			StartPeriod: int64(o.HealthStart),
			Retries:     o.HealthRetries,
		}
	}
	created := o.Created.UTC().Format(time.RFC3339)
	img := image{
		Architecture: o.Arch,
		Variant:      variant,
		OS:           o.OS,
		Created:      created,
		Config:       cfg,
		RootFS:       rootFS{Type: "layers", DiffIDs: []string{diffID}},
		History:      []history{{Created: created, CreatedBy: "routeros-guardian tools/mkimage", Comment: "single layer"}},
	}
	imgJSON, err := json.Marshal(img)
	if err != nil {
		return err
	}
	cfgSum := sha256.Sum256(imgJSON)
	cfgName := hex.EncodeToString(cfgSum[:]) + ".json"

	repo, tag := splitTag(o.Tag)
	manifest, err := json.Marshal([]manifestEntry{{
		Config:   cfgName,
		RepoTags: []string{repo + ":" + tag},
		Layers:   []string{layerID + "/layer.tar"},
	}})
	if err != nil {
		return err
	}
	repositories, err := json.Marshal(map[string]map[string]string{repo: {tag: layerID}})
	if err != nil {
		return err
	}
	legacy, err := json.Marshal(legacyLayerJSON{
		ID: layerID, Created: created, Architecture: o.Arch, OS: o.OS, Config: cfg,
	})
	if err != nil {
		return err
	}

	tw := tar.NewWriter(w)
	mt := o.Created
	if err := tarDir(tw, layerID+"/", mt); err != nil {
		return err
	}
	for _, e := range []struct {
		name string
		data []byte
	}{
		{layerID + "/VERSION", []byte("1.0")},
		{layerID + "/json", legacy},
		{layerID + "/layer.tar", layer},
		{cfgName, imgJSON},
		{"manifest.json", manifest},
		{"repositories", repositories},
	} {
		if err := tarFile(tw, e.name, 0o644, e.data, mt); err != nil {
			return err
		}
	}
	return tw.Close()
}

func splitTag(t string) (repo, tag string) {
	// a ':' after the last '/' separates the tag (registry host:port has '/' after it)
	i := strings.LastIndex(t, ":")
	if i > strings.LastIndex(t, "/") {
		return t[:i], t[i+1:]
	}
	return t, "latest"
}

// buildLayer creates the uncompressed root filesystem tar.
func buildLayer(o options) ([]byte, error) {
	type entry struct {
		dir  bool
		mode int64
		data []byte
	}
	entries := map[string]entry{}
	addDir := func(p string, mode int64) {
		p = strings.Trim(path.Clean(p), "/")
		for p != "" && p != "." {
			if _, ok := entries[p]; !ok {
				entries[p] = entry{dir: true, mode: mode}
			}
			p = path.Dir(p)
			if p == "." {
				break
			}
		}
	}
	// minimal filesystem skeleton
	addDir("/etc", 0o755)
	addDir("/tmp", 0o1777)
	addDir("/data", 0o755)
	for _, d := range o.Dirs {
		addDir(d, 0o755)
	}
	// minimal passwd/group so tools and `User` lookups behave
	entries["etc/passwd"] = entry{mode: 0o644, data: []byte("root:x:0:0:root:/root:/sbin/nologin\nnonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin\n")}
	entries["etc/group"] = entry{mode: 0o644, data: []byte("root:x:0:\nnonroot:x:65532:\n")}

	for _, f := range o.Files {
		data, err := os.ReadFile(f.Src)
		if err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(f.Dst, "/")
		addDir(path.Dir(f.Dst), 0o755)
		entries[name] = entry{mode: f.Mode, data: data}
	}

	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names) // parents sort before children ("etc" < "etc/ssl")

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		e := entries[n]
		var err error
		if e.dir {
			err = tarDirMode(tw, n+"/", e.mode, o.Created)
		} else {
			err = tarFile(tw, n, e.mode, e.data, o.Created)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func tarDir(tw *tar.Writer, name string, mt time.Time) error {
	return tarDirMode(tw, name, 0o755, mt)
}

func tarDirMode(tw *tar.Writer, name string, mode int64, mt time.Time) error {
	return tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir, Name: name, Mode: mode, ModTime: mt,
	})
}

func tarFile(tw *tar.Writer, name string, mode int64, data []byte, mt time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(data)), ModTime: mt,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
