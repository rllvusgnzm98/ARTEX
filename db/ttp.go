package db

import (
	"database/sql"
	"strings"
	"time"
)

// TTP (结构化复盘与 TTP 沉淀): a reviewable "场景→判据→转向" decision-skeleton entry,
// isomorphic to agent/chainskel/*.md. Entries only enter the decision corpus after a
// human approves them (status=approved); Source separates internal retros from
// external writeups so low-quality external content cannot auto-pollute the corpus.
type TTPEntry struct {
	ID         int64      `json:"id"`
	Source     string     `json:"source"` // retro | writeup
	Category   string     `json:"category"`
	Scene      string     `json:"scene"`
	Criteria   string     `json:"criteria"`
	Pivot      string     `json:"pivot"`
	Status     string     `json:"status"`     // pending | approved | rejected
	Confidence float64    `json:"confidence"` // writeup 置信度 0-1;retro 恒 0
	TaskID     *int64     `json:"task_id,omitempty"`
	OriginRef  string     `json:"origin_ref,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	Reviewer   string     `json:"reviewer,omitempty"`
}

// TTPLine renders an entry in the single-line chainskel format
// ("场景:…|判据:…|转向:…"), matching agent/chainskel/*.md.
func TTPLine(e TTPEntry) string {
	return "场景:" + e.Scene + "|判据:" + e.Criteria + "|转向:" + e.Pivot
}

// AddTTPEntry inserts a pending entry and returns its id.
func (d *DB) AddTTPEntry(e TTPEntry) (int64, error) {
	status := e.Status
	if status == "" {
		status = "pending"
	}
	var id int64
	err := d.QueryRow(`INSERT INTO ttp_entries
		(source, category, scene, criteria, pivot, status, confidence, task_id, origin_ref)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		e.Source, e.Category, strings.TrimSpace(e.Scene), strings.TrimSpace(e.Criteria),
		strings.TrimSpace(e.Pivot), status, e.Confidence, e.TaskID, e.OriginRef).Scan(&id)
	return id, err
}

const ttpCols = `id, source, category, scene, criteria, pivot, status, confidence,
	task_id, COALESCE(origin_ref,''), created_at, reviewed_at, COALESCE(reviewer,'')`

func scanTTP(rows *sql.Rows) ([]TTPEntry, error) {
	out := []TTPEntry{}
	for rows.Next() {
		var e TTPEntry
		if err := rows.Scan(&e.ID, &e.Source, &e.Category, &e.Scene, &e.Criteria, &e.Pivot,
			&e.Status, &e.Confidence, &e.TaskID, &e.OriginRef, &e.CreatedAt, &e.ReviewedAt,
			&e.Reviewer); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListTTPEntries returns entries, newest first; status="" returns all.
func (d *DB) ListTTPEntries(status string) ([]TTPEntry, error) {
	q := `SELECT ` + ttpCols + ` FROM ttp_entries`
	var args []any
	if s := strings.TrimSpace(status); s != "" {
		q += ` WHERE status=$1`
		args = append(args, s)
	}
	q += ` ORDER BY id DESC`
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTTP(rows)
}

// GetTTPEntry reads one entry (nil if absent).
func (d *DB) GetTTPEntry(id int64) (*TTPEntry, error) {
	rows, err := d.Query(`SELECT `+ttpCols+` FROM ttp_entries WHERE id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanTTP(rows)
	if err != nil || len(list) == 0 {
		return nil, err
	}
	return &list[0], nil
}

// SetTTPStatus moves an entry to approved/rejected (stamping reviewer+time) and
// returns the updated row.
func (d *DB) SetTTPStatus(id int64, status, reviewer string) (*TTPEntry, error) {
	if _, err := d.Exec(
		`UPDATE ttp_entries SET status=$2, reviewer=$3, reviewed_at=now() WHERE id=$1`,
		id, status, reviewer); err != nil {
		return nil, err
	}
	return d.GetTTPEntry(id)
}

// ApprovedTTPLines returns the chainskel-format lines for approved entries of a
// category — the runtime overlay merged into the embedded skeletons.
func (d *DB) ApprovedTTPLines(category string) ([]string, error) {
	rows, err := d.Query(`SELECT `+ttpCols+`
		FROM ttp_entries WHERE status='approved' AND category=$1 ORDER BY id`, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list, err := scanTTP(rows)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, TTPLine(e))
	}
	return out, nil
}
