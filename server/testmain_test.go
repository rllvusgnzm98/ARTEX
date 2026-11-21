package server

import (
	"os"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/internal/pgtest"
)

func TestMain(m *testing.M) {
	dsn, _, _ := db.DSN()
	release := pgtest.Lock(dsn)
	code := m.Run()
	release()
	os.Exit(code)
}
