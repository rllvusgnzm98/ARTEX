// credentials.go 是凭据一等实体的落库层。secret 用 AES-GCM 加密存储：与
// sessions 同款派生方式（jwt.key → SHA-256 域分离）但不同域标签，两个子系统
// 密钥互相独立。密文格式为 gcm1:<base64(nonce|ciphertext)>。
// 轮换 jwt.key 会使已存密文无法解密；本波只记账，不做迁移。
package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// 凭据类型全集（schema CHECK 与 Go 校验同源）。
const (
	CredPassword = "password"
	CredHashNT   = "hash_nt"
	CredHashLM   = "hash_lm"
	CredHashSHA1 = "hash_sha1"
	CredTicket   = "ticket"
	CredSSHKey   = "ssh_key"
	CredToken    = "token"
)

// CredentialRecord 是 credentials 表的一行。Secret 在 Go 层是明文；Create 加密、
// Get/ListByTask 解密，密钥不出 CredentialStore。列表/日志必须走 PublicCredential
// 或 RedactCredentialPayload，不得把明文 secret 写出。
type CredentialRecord struct {
	ID          int64     `json:"id"`
	TaskID      int64     `json:"task_id"`
	HostAssetID int64     `json:"host_asset_id,omitempty"`
	Username    string    `json:"username"`
	CredType    string    `json:"cred_type"`
	Secret      string    `json:"secret"` // 明文；落库时加密
	Domain      string    `json:"domain,omitempty"`
	Source      string    `json:"source"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
}

// ValidCredType 校验凭据类型。
func ValidCredType(t string) bool {
	switch t {
	case CredPassword, CredHashNT, CredHashLM, CredHashSHA1, CredTicket, CredSSHKey, CredToken:
		return true
	}
	return false
}

// CredentialSecretKey 由 master key（jwt.key 内容）派生凭据加密密钥：与
// SessionSecretKey 同款 SHA-256 域分离，但域标签不同（"artex/credentials/v1"），
// 两个子系统的密文互不通用。
func CredentialSecretKey(master []byte) []byte {
	sum := sha256.Sum256(append([]byte("artex/credentials/v1\x00"), master...))
	return sum[:]
}

// CredentialStore 是 credentials 表的访问层。key 为 32 字节 AES 密钥（经
// CredentialSecretKey 派生）；key 缺失时加解密直接报错（诚实失败，不落明文）。
type CredentialStore struct {
	d   *DB
	key []byte
}

// NewCredentialStore 构造访问层。masterKey 传 jwt.key 内容；内部自行派生。
func NewCredentialStore(d *DB, masterKey []byte) *CredentialStore {
	var key []byte
	if len(masterKey) > 0 {
		key = CredentialSecretKey(masterKey)
	}
	return &CredentialStore{d: d, key: key}
}

func (s *CredentialStore) encrypt(plain string) (string, error) {
	if len(s.key) != 32 {
		return "", fmt.Errorf("凭据加密密钥未初始化,拒绝明文落库")
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return secretPrefix + base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

func (s *CredentialStore) decrypt(stored string) (string, error) {
	if len(stored) == 0 {
		return "", nil
	}
	if len(s.key) != 32 {
		return "", fmt.Errorf("凭据加密密钥未初始化,无法解密")
	}
	if !hasPrefix(stored, secretPrefix) {
		return "", fmt.Errorf("未知 secret 格式(缺 gcm1: 前缀),拒绝按明文读取")
	}
	raw, err := base64.StdEncoding.DecodeString(stored[len(secretPrefix):])
	if err != nil {
		return "", fmt.Errorf("secret base64 解码失败: %w", err)
	}
	gcm, err := newGCM(s.key)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("secret 密文过短")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("secret 解密失败(密钥不符或数据被篡改): %w", err)
	}
	return string(plain), nil
}

// Create 插入一条凭据并返回主键。Secret 加密存储。
func (s *CredentialStore) Create(ctx context.Context, rec *CredentialRecord) (int64, error) {
	if rec.TaskID <= 0 {
		return 0, fmt.Errorf("task_id 必填")
	}
	if !ValidCredType(rec.CredType) {
		return 0, fmt.Errorf("非法 cred_type %q(password/hash_nt/hash_lm/hash_sha1/ticket/ssh_key/token)", rec.CredType)
	}
	if rec.Secret == "" {
		return 0, fmt.Errorf("secret 必填")
	}
	enc, err := s.encrypt(rec.Secret)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.d.QueryRowContext(ctx, `
INSERT INTO credentials(task_id, host_asset_id, username, cred_type, secret, domain, source, verified)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id`,
		rec.TaskID, nilIfZero(rec.HostAssetID), rec.Username, rec.CredType, enc,
		rec.Domain, rec.Source, rec.Verified).Scan(&id)
	return id, err
}

const credentialCols = `id, task_id, COALESCE(host_asset_id,0), username, cred_type, secret,
	domain, source, verified, created_at`

func (s *CredentialStore) scan(row interface{ Scan(...any) error }) (*CredentialRecord, error) {
	var r CredentialRecord
	var enc string
	if err := row.Scan(&r.ID, &r.TaskID, &r.HostAssetID, &r.Username, &r.CredType, &enc,
		&r.Domain, &r.Source, &r.Verified, &r.CreatedAt); err != nil {
		return nil, err
	}
	plain, err := s.decrypt(enc)
	if err != nil {
		return nil, fmt.Errorf("credential %d: %w", r.ID, err)
	}
	r.Secret = plain
	return &r, nil
}

// Get 取一条（含解密 secret）；不存在返回 (nil, nil)。
func (s *CredentialStore) Get(ctx context.Context, id int64) (*CredentialRecord, error) {
	r, err := s.scan(s.d.QueryRowContext(ctx,
		`SELECT `+credentialCols+` FROM credentials WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

// ListByTask 取一个任务的全部凭据（按 id 升序，含解密 secret）。
func (s *CredentialStore) ListByTask(ctx context.Context, taskID int64) ([]*CredentialRecord, error) {
	rows, err := s.d.QueryContext(ctx,
		`SELECT `+credentialCols+` FROM credentials WHERE task_id=$1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CredentialRecord{}
	for rows.Next() {
		r, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListAll 取全部凭据（按 id 升序，含解密 secret）——控制台跨任务视图用。
// 调用方必须走 PublicCredential 脱敏，secret 不明文出接口。
func (s *CredentialStore) ListAll(ctx context.Context) ([]*CredentialRecord, error) {
	rows, err := s.d.QueryContext(ctx,
		`SELECT `+credentialCols+` FROM credentials ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CredentialRecord{}
	for rows.Next() {
		r, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetVerified 标记凭据是否已实测可登录（复用打分的 verified 加分依赖它）。
func (s *CredentialStore) SetVerified(ctx context.Context, id int64, verified bool) error {
	_, err := s.d.ExecContext(ctx, `UPDATE credentials SET verified=$2 WHERE id=$1`, id, verified)
	return err
}

// Delete 删除一条。
func (s *CredentialStore) Delete(ctx context.Context, id int64) error {
	_, err := s.d.ExecContext(ctx, `DELETE FROM credentials WHERE id=$1`, id)
	return err
}

// MaskSecret 脱敏展示：只露前后各 2 字符，其余掩码；过短（≤4 字符）全掩码。
func MaskSecret(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "****"
	}
	return string(r[:2]) + "****" + string(r[len(r)-2:])
}

// PublicCredential 是控制台列表 / list_credentials 用的脱敏视图，不含明文 secret。
func PublicCredential(c *CredentialRecord) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"id":            c.ID,
		"task_id":       c.TaskID,
		"username":      c.Username,
		"cred_type":     c.CredType,
		"secret_masked": MaskSecret(c.Secret),
		"domain":        c.Domain,
		"source":        c.Source,
		"verified":      c.Verified,
		"host_asset_id": c.HostAssetID,
		"created_at":    c.CreatedAt,
	}
}

// CredentialReuseFields 是工人复用路径下发给该任务工具结果的必要字段（可含明文
// secret）。只应出现在工具返回中，不得写入列表、log.Printf 或活动日志。
func CredentialReuseFields(c *CredentialRecord) map[string]any {
	if c == nil {
		return map[string]any{}
	}
	return map[string]any{
		"cred_id":   c.ID,
		"username":  c.Username,
		"cred_type": c.CredType,
		"secret":    c.Secret,
		"domain":    c.Domain,
	}
}

var credentialRedactKeys = map[string]bool{
	"secret":    true,
	"auth_pass": true,
	"AUTH":      true,
}

// RedactCredentialPayload 清洗凭据相关工具的入参/出参，供活动日志使用：
// 去掉 secret / AUTH 等字段的明文，其他工具原样返回。
func RedactCredentialPayload(tool, payload string) string {
	switch tool {
	case "add_credential", "list_credentials", "credential_reuse_plan":
	default:
		return payload
	}
	if payload == "" {
		return payload
	}
	var v any
	if err := json.Unmarshal([]byte(payload), &v); err != nil {
		return `{"redacted":true}`
	}
	redactJSONValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return `{"redacted":true}`
	}
	return string(out)
}

func redactJSONValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if credentialRedactKeys[k] {
				if s, ok := val.(string); ok {
					t[k] = MaskSecret(s)
				} else {
					t[k] = "****"
				}
				continue
			}
			redactJSONValue(val)
		}
	case []any:
		for _, item := range t {
			redactJSONValue(item)
		}
	}
}
