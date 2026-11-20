// credential_inheritance.go 记录外网任务移交给内网子任务时引用了哪些凭据。
// 行里只有元数据和分数，不复制 secret；明文仍只在 CredentialStore 解密后出现。
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
)

// 继承相关性依据。越靠前越精确；handoff 按这个顺序取第一条命中的。
const (
	InheritFootholdHost = "foothold_host"
	InheritSameSegment  = "same_segment"
	InheritDomain       = "domain"
	InheritCompany      = "company"
	InheritManual       = "manual"
)

const (
	InheritActive  = "active"
	InheritRevoked = "revoked"
)

// ErrInheritanceRevoked 表示该 (子任务, 凭据) 已经被撤销，Inherit 不会把它改回 active。
var ErrInheritanceRevoked = errors.New("继承已撤销,不能复活")

// CredentialInheritance 是 credential_inheritances 的一行。不含 secret。
type CredentialInheritance struct {
	ID           int64   `json:"id,omitempty"`
	ChildTaskID  int64   `json:"child_task_id"`
	SourceTaskID int64   `json:"source_task_id"`
	CredentialID int64   `json:"credential_id"`
	ScopeBasis   string  `json:"scope_basis"`
	Score        float64 `json:"score"`
	State        string  `json:"state,omitempty"`
	Reason       string  `json:"reason,omitempty"`
}

// InheritedMeta 是给提示词和工具看的继承凭据摘要。故意没有 secret 字段。
type InheritedMeta struct {
	CredentialID int64  `json:"credential_id"`
	Username     string `json:"username"`
	CredType     string `json:"cred_type"`
	Domain       string `json:"domain"`
	HostAssetID  int64  `json:"host_asset_id"`
	SourceTaskID int64  `json:"source_task_id"`
	ScopeBasis   string `json:"scope_basis"`
}

// ValidInheritBasis 校验 scope_basis。
func ValidInheritBasis(b string) bool {
	switch b {
	case InheritFootholdHost, InheritSameSegment, InheritDomain, InheritCompany, InheritManual:
		return true
	}
	return false
}

// Inherit 写入或刷新一条继承关系。冲突时只在新分数不低于原分数时改写
// source/basis/score/reason，避免一次较低分的重放盖掉更高分。
// state=revoked 的行不匹配 UPDATE 的 WHERE，因此不会被改回 active。
func (s *CredentialStore) Inherit(ctx context.Context, in CredentialInheritance) error {
	if in.ChildTaskID <= 0 || in.SourceTaskID <= 0 || in.CredentialID <= 0 {
		return fmt.Errorf("child_task_id、source_task_id、credential_id 必填")
	}
	if !ValidInheritBasis(in.ScopeBasis) {
		return fmt.Errorf("非法 scope_basis %q", in.ScopeBasis)
	}
	tx, err := s.d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var id int64
	err = tx.QueryRowContext(ctx, `
INSERT INTO credential_inheritances
    (child_task_id, source_task_id, credential_id, scope_basis, score, state, reason)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (child_task_id, credential_id) DO UPDATE SET
    source_task_id = CASE
        WHEN EXCLUDED.score >= credential_inheritances.score THEN EXCLUDED.source_task_id
        ELSE credential_inheritances.source_task_id END,
    scope_basis = CASE
        WHEN EXCLUDED.score >= credential_inheritances.score THEN EXCLUDED.scope_basis
        ELSE credential_inheritances.scope_basis END,
    score = GREATEST(credential_inheritances.score, EXCLUDED.score),
    reason = CASE
        WHEN EXCLUDED.score >= credential_inheritances.score THEN EXCLUDED.reason
        ELSE credential_inheritances.reason END
WHERE credential_inheritances.state <> $8
RETURNING id`,
		in.ChildTaskID, in.SourceTaskID, in.CredentialID, in.ScopeBasis, in.Score,
		InheritActive, in.Reason, InheritRevoked).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var state string
		qerr := tx.QueryRowContext(ctx, `
SELECT state FROM credential_inheritances
WHERE child_task_id=$1 AND credential_id=$2`, in.ChildTaskID, in.CredentialID).Scan(&state)
		if qerr != nil {
			return qerr
		}
		if state == InheritRevoked {
			return ErrInheritanceRevoked
		}
		return fmt.Errorf("继承冲突未写入,当前 state=%s", state)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

const inheritCredentialCols = `c.id, c.task_id, COALESCE(c.host_asset_id,0), c.username, c.cred_type, c.secret,
	c.domain, c.source, c.verified, c.created_at`

// ListInherited 返回子任务自有凭据，加上仍有效的继承凭据。
// 继承条目带 inherited/source_task_id/scope_basis。解密失败的行计入 Skipped，不让整表失败。
func (s *CredentialStore) ListInherited(ctx context.Context, taskID int64) (CredentialList, error) {
	own, err := s.collectInherited(ctx, `
SELECT `+inheritCredentialCols+`, false, 0::bigint, ''
FROM credentials c
WHERE c.task_id=$1
ORDER BY c.id`, taskID)
	if err != nil {
		return emptyCredentialList(), err
	}
	inherited, err := s.collectInherited(ctx, `
SELECT `+inheritCredentialCols+`, true, i.source_task_id, i.scope_basis
FROM credential_inheritances i
JOIN credentials c ON c.id = i.credential_id
WHERE i.child_task_id=$1 AND i.state=$2
ORDER BY i.score DESC, c.id`, taskID, InheritActive)
	if err != nil {
		return emptyCredentialList(), err
	}
	own.Items = append(own.Items, inherited.Items...)
	own.Skipped = append(own.Skipped, inherited.Skipped...)
	return own, nil
}

// ListInheritedMeta 只返回仍有效的继承凭据元数据，不读取 secret 列。
func (s *CredentialStore) ListInheritedMeta(ctx context.Context, taskID int64) ([]InheritedMeta, error) {
	rows, err := s.d.QueryContext(ctx, `
SELECT c.id, COALESCE(c.username,''), COALESCE(c.cred_type,''), COALESCE(c.domain,''),
       COALESCE(c.host_asset_id,0), i.source_task_id, i.scope_basis
FROM credential_inheritances i
JOIN credentials c ON c.id = i.credential_id
WHERE i.child_task_id=$1 AND i.state=$2
ORDER BY i.score DESC, c.id`, taskID, InheritActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InheritedMeta{}
	for rows.Next() {
		var m InheritedMeta
		if err := rows.Scan(&m.CredentialID, &m.Username, &m.CredType, &m.Domain,
			&m.HostAssetID, &m.SourceTaskID, &m.ScopeBasis); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RevokeInherited 把一条仍有效的继承标为 revoked。没有可撤销的行则报错。
func (s *CredentialStore) RevokeInherited(ctx context.Context, taskID, credentialID int64) error {
	if taskID <= 0 || credentialID <= 0 {
		return fmt.Errorf("task_id 与 credential_id 必填")
	}
	res, err := s.d.ExecContext(ctx, `
UPDATE credential_inheritances
SET state=$3, revoked_at=now()
WHERE child_task_id=$1 AND credential_id=$2 AND state=$4`,
		taskID, credentialID, InheritRevoked, InheritActive)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("任务 %d 上没有可撤销的继承凭据 %d", taskID, credentialID)
	}
	return nil
}

func (s *CredentialStore) collectInherited(ctx context.Context, query string, args ...any) (CredentialList, error) {
	rows, err := s.d.QueryContext(ctx, query, args...)
	if err != nil {
		return emptyCredentialList(), err
	}
	defer rows.Close()
	list := emptyCredentialList()
	for rows.Next() {
		rec, enc, inherited, sourceID, basis, err := scanInheritRow(rows)
		if err != nil {
			return emptyCredentialList(), err
		}
		list = s.takeInherited(list, rec, enc, inherited, sourceID, basis)
	}
	return list, rows.Err()
}

func scanInheritRow(row interface{ Scan(...any) error }) (CredentialRecord, string, bool, int64, string, error) {
	var r CredentialRecord
	var enc, basis string
	var inherited bool
	var sourceTaskID int64
	err := row.Scan(
		&r.ID, &r.TaskID, &r.HostAssetID, &r.Username, &r.CredType, &enc,
		&r.Domain, &r.Source, &r.Verified, &r.CreatedAt,
		&inherited, &sourceTaskID, &basis,
	)
	return r, enc, inherited, sourceTaskID, basis, err
}

func (s *CredentialStore) takeInherited(list CredentialList, rec CredentialRecord, enc string, inherited bool, sourceID int64, basis string) CredentialList {
	plain, err := s.decrypt(enc)
	if err != nil {
		log.Printf("[credentials] skip credential %d: decrypt failed", rec.ID)
		list.Skipped = append(list.Skipped, rec.ID)
		return list
	}
	rec.Secret = plain
	if inherited {
		rec.Inherited = true
		rec.SourceTaskID = sourceID
		rec.ScopeBasis = basis
	}
	list.Items = append(list.Items, &rec)
	return list
}
