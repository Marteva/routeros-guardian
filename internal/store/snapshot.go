package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Snapshot writes a consistent copy of the database to dst (e.g. a NAS share).
// It writes dst+".tmp" first and renames it, so a reader never sees a partial file.
// The live database is meant to stay on local storage (tmpfs): SQLite locking
// over SMB/NFS is not reliable, a periodic snapshot is.
func (s *SQLite) Snapshot(ctx context.Context, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	_ = os.Remove(tmp) // VACUUM INTO refuses to overwrite
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		return fmt.Errorf("store: snapshot: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		// Some SMB servers refuse rename over an existing file.
		_ = os.Remove(dst)
		if err2 := os.Rename(tmp, dst); err2 != nil {
			return fmt.Errorf("store: snapshot rename: %w", err2)
		}
	}
	return nil
}

// RestoreIfMissing copies the snapshot at src to dbPath when dbPath does not
// exist yet (e.g. tmpfs emptied by a router reboot). It reports whether a
// restore happened. A missing snapshot is not an error.
func RestoreIfMissing(dbPath, src string) (bool, error) {
	if src == "" {
		return false, nil
	}
	if _, err := os.Stat(dbPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	in, err := os.Open(src)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return false, err
	}
	tmp := dbPath + ".restore"
	out, err := os.Create(tmp)
	if err != nil {
		return false, err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return false, err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return false, err
	}
	// Leftover WAL/SHM files from an older database would corrupt the restore.
	for _, suf := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + suf)
	}
	return true, os.Rename(tmp, dbPath)
}
