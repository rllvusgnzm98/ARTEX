package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// LegacyUnknownBuild 标记「升级前就已经跑过、build 已无从考证」的任务（见 schema.sql
// 的回填）。它与空串的区别是：空串表示任务还没真正跑过，之后第一次跑时应当如实盖章；
// 这个哨兵表示任务跑过但证据缺失，必须一直上报「构建未知」，绝不被当前 build 回填。
const LegacyUnknownBuild = "legacy-unknown"

// DevBuildVersion 是未注入版本时的默认标签（plain go build、dev.sh 的 go run、非 Git
// 目录下的 build.sh 都落到它）。它指不回任何一次提交，所以除非同时记到了 build_commit，
// 否则不算运行证据——否则「构建未知」会被一个毫无信息量的 "dev" 顶替。
const DevBuildVersion = "dev"

// provenanceRecorded 判定这一行是否真有可归因的构建证据。
func provenanceRecorded(version string, runtime map[string]any) bool {
	switch version {
	case "", LegacyUnknownBuild:
		return false
	case DevBuildVersion:
		commit, _ := runtime["build_commit"].(string)
		return strings.TrimSpace(commit) != ""
	}
	return true
}

// TaskProvenance 是一次任务运行的溯源证据：当时真正在跑的二进制版本，以及脱敏后的
// 有效配置快照。
type TaskProvenance struct {
	// BuildVersion 是执行该任务的二进制版本。空表示没有记录（旧任务）。
	BuildVersion string `json:"build_version"`
	// Runtime 是脱敏后的有效配置/运行时快照。
	Runtime map[string]any `json:"runtime,omitempty"`
	// Recorded 为 false 表示这一行没有溯源证据——必须据此上报「构建未知」，
	// 而不是用当前检出或当前进程的版本倒推。
	Recorded bool `json:"recorded"`
}

// StampRunProvenance 在任务「第一次真正执行」时写入运行溯源。
//
// 只在 build_version 仍为空时写入：第一次真正跑起来的那个 build 才是产生这轮数据的
// build，之后的重启/升级不得改写既有证据，否则跑分归因会指向错误的版本。因此这个
// 操作是幂等的，且对旧任务不做任何回填。
func (d *DB) StampRunProvenance(id int64, version string, runtime map[string]any) error {
	if d == nil || d.DB == nil || id <= 0 || version == "" {
		return nil
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		return err
	}
	_, err = d.Exec(`
UPDATE tasks
   SET build_version = $2, runtime_provenance = $3
 WHERE id = $1 AND build_version = ''`, id, version, string(raw))
	return err
}

// TaskProvenance 读取某任务的运行溯源。没有记录时返回 Recorded=false，调用方应展示
// 「构建未知」而不是替它猜一个版本。
func (d *DB) TaskProvenance(id int64) (TaskProvenance, error) {
	if d == nil || d.DB == nil {
		return TaskProvenance{}, nil
	}
	var (
		version string
		raw     []byte
	)
	err := d.QueryRow(`SELECT build_version, runtime_provenance FROM tasks WHERE id=$1`, id).Scan(&version, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return TaskProvenance{}, err
	}
	if err != nil {
		return TaskProvenance{}, err
	}
	out := TaskProvenance{BuildVersion: version}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out.Runtime)
	}
	out.Recorded = provenanceRecorded(version, out.Runtime)
	return out, nil
}
