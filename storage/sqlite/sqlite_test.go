package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/micromdm/nanomdm/test/e2e"
)

// The same end-to-end suite the mysql and pgsql backends run, on a fresh
// SQLite file each time (no server needed, so it always runs).
func TestSQLite(t *testing.T) {
	s, err := New(WithDSN(filepath.Join(t.TempDir(), "rm.db")), WithDeleteCommands())
	if err != nil {
		t.Fatal(err)
	}
	t.Run("e2e-WithDeleteCommands()", func(t *testing.T) { e2e.TestE2E(t, context.Background(), s) })

	s, err = New(WithDSN(filepath.Join(t.TempDir(), "keep.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("e2e", func(t *testing.T) { e2e.TestE2E(t, context.Background(), s) })
}
