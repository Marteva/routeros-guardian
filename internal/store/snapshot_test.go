package store

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

func TestSnapshotAndRestore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	live := filepath.Join(dir, "live", "guardian.db")
	backup := filepath.Join(dir, "nas", "guardian.db")

	// No snapshot yet → nothing restored.
	if ok, err := RestoreIfMissing(live, backup); err != nil || ok {
		t.Fatalf("restore without snapshot: ok=%v err=%v", ok, err)
	}

	if err := os.MkdirAll(filepath.Dir(live), 0o755); err != nil {
		t.Fatal(err)
	}
	s, err := Open(live)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: "AA:BB:CC:00:00:01", IP: netip.MustParseAddr("192.168.88.5"), FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Snapshot(ctx, backup); err != nil {
		t.Fatal(err)
	}
	// Second snapshot overwrites the first.
	if err := s.Snapshot(ctx, backup); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if _, err := os.Stat(backup + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file left behind: %v", err)
	}
	s.Close()

	// Live DB exists → no restore.
	if ok, err := RestoreIfMissing(live, backup); err != nil || ok {
		t.Fatalf("restore over existing db: ok=%v err=%v", ok, err)
	}

	// Simulate reboot (tmpfs emptied) → restore from snapshot.
	fresh := filepath.Join(dir, "fresh", "guardian.db")
	ok, err := RestoreIfMissing(fresh, backup)
	if err != nil || !ok {
		t.Fatalf("restore: ok=%v err=%v", ok, err)
	}
	s2, err := Open(fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, found, err := s2.Device(ctx, "AA:BB:CC:00:00:01"); err != nil || !found {
		t.Fatalf("device not restored: found=%v err=%v", found, err)
	}
}
