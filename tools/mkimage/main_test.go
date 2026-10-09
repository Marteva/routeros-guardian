package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readTar(t *testing.T, r io.Reader) (map[string][]byte, map[string]*tar.Header) {
	t.Helper()
	data := map[string][]byte{}
	hdrs := map[string]*tar.Header{}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		data[h.Name] = b
		hdrs[h.Name] = h
	}
	return data, hdrs
}

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "guardian")
	if err := os.WriteFile(bin, []byte("#!dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := options{
		Tag: "guardian:test", Arch: "arm64", OS: "linux",
		Files:      []fileSpec{{Dst: "/guardian", Src: bin, Mode: 0o755}, {Dst: "/etc/ssl/certs/ca-certificates.crt", Src: bin, Mode: 0o644}},
		Entrypoint: []string{"/guardian"}, WorkingDir: "/", Expose: []string{"8080"}, Volumes: []string{"/data"},
		Env:     []string{"TZ=UTC"},
		Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Health:  []string{"/guardian", "-healthcheck"}, HealthInterval: 30 * time.Second, HealthRetries: 3,
	}
	var buf bytes.Buffer
	if err := build(&buf, o); err != nil {
		t.Fatal(err)
	}
	outer, _ := readTar(t, &buf)

	var man []manifestEntry
	if err := json.Unmarshal(outer["manifest.json"], &man); err != nil || len(man) != 1 {
		t.Fatalf("manifest: %v %s", err, outer["manifest.json"])
	}
	m := man[0]
	if m.RepoTags[0] != "guardian:test" || len(m.Layers) != 1 {
		t.Fatalf("manifest content: %+v", m)
	}
	var img image
	if err := json.Unmarshal(outer[m.Config], &img); err != nil {
		t.Fatal(err)
	}
	if img.Architecture != "arm64" || img.OS != "linux" || img.Variant != "v8" {
		t.Fatalf("platform: %+v", img)
	}
	layer := outer[m.Layers[0]]
	sum := sha256.Sum256(layer)
	if img.RootFS.DiffIDs[0] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("diff_id mismatch")
	}
	cs := sha256.Sum256(outer[m.Config])
	if m.Config != hex.EncodeToString(cs[:])+".json" {
		t.Fatal("config name is not its digest")
	}
	if _, ok := img.Config.ExposedPorts["8080/tcp"]; !ok {
		t.Fatal("expose")
	}
	hc := img.Config.Healthcheck
	if hc == nil || len(hc.Test) != 3 || hc.Test[0] != "CMD" || hc.Test[2] != "-healthcheck" ||
		hc.Interval != int64(30*time.Second) || hc.Retries != 3 {
		t.Fatalf("healthcheck: %+v", hc)
	}
	files, hdrs := readTar(t, bytes.NewReader(layer))
	if string(files["guardian"]) != "#!dummy" || hdrs["guardian"].Mode != 0o755 {
		t.Fatalf("guardian entry: %+v", hdrs["guardian"])
	}
	for _, d := range []string{"data/", "tmp/", "etc/", "etc/ssl/", "etc/ssl/certs/"} {
		if h, ok := hdrs[d]; !ok || h.Typeflag != tar.TypeDir {
			t.Fatalf("missing dir %s", d)
		}
	}
}

func TestParseFileSpecWindows(t *testing.T) {
	fs, err := parseFileSpec(`/probe=C:\x\dist\probe`, 0o755)
	if err != nil || fs.Dst != "/probe" || fs.Src != `C:\x\dist\probe` {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestSplitTag(t *testing.T) {
	for in, want := range map[string][2]string{
		"guardian":                {"guardian", "latest"},
		"guardian:v1":             {"guardian", "v1"},
		"localhost:5000/guardian": {"localhost:5000/guardian", "latest"},
	} {
		r, tg := splitTag(in)
		if r != want[0] || tg != want[1] {
			t.Errorf("%s -> %s %s", in, r, tg)
		}
	}
}
