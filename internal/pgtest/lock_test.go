package pgtest

import (
	"context"
	"database/sql"
	"os"
	"testing"
)

func TestLockWithoutDatabase(t *testing.T) {
	for _, dsn := range []string{"", "://invalid"} {
		t.Run(dsn, func(t *testing.T) {
			release := Lock(dsn)
			release()
			release()
		})
	}
}

func TestLockPinsSessionAndReleases(t *testing.T) {
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN is required")
	}
	release := Lock(dsn)
	t.Cleanup(release)
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	conn, err := pool.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	var acquired bool
	if err := conn.QueryRowContext(t.Context(), `SELECT pg_try_advisory_lock(7337741002)`).Scan(&acquired); err != nil {
		t.Fatal(err)
	}
	if acquired {
		conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741002)`)
		t.Fatal("suite lock was not held on its session")
	}
	release()
	release()
	secondRelease := Lock(dsn)
	secondRelease()
}
