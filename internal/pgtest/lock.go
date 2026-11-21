package pgtest

import (
	"context"
	"database/sql"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Lock serializes integration suites on a pinned PostgreSQL session. When the
// database is unavailable, individual tests retain responsibility for skipping.
func Lock(dsn string) func() {
	noop := func() {}
	if dsn == "" {
		return noop
	}
	pool, err := sql.Open("pgx", dsn)
	if err != nil {
		return noop
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := pool.Conn(ctx)
	cancel()
	if err != nil {
		pool.Close()
		return noop
	}
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock(7337741002)`); err != nil {
		conn.Close()
		pool.Close()
		panic(err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			defer pool.Close()
			defer conn.Close()
			if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock(7337741002)`); err != nil {
				panic(err)
			}
		})
	}
}
