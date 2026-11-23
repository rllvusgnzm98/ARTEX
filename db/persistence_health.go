package db

import (
	"sort"
	"sync"
	"time"
)

// PersistenceHealth 记录「执行成功但落库失败」这一类事件，让持久化故障可见。
// 日志只能事后翻查，判定上下文优化是否有效时需要能直接读到：某次探索有没有丢过
// activity、有没有写过悬空锚点。按 exploration 聚合，进程内存活即可——它描述的是
// 当前运行实例的落库健康，不是需要持久化的业务数据。
type PersistenceHealth struct {
	mu   sync.Mutex
	byID map[int64]*expHealth
}

type expHealth struct {
	droppedActivity int64
	writeFailures   int64
	danglingAnchors int64
	missingAssets   map[int64]struct{}
	lastReason      string
	lastAt          time.Time
}

// ExplorationPersistence 是某次探索的落库健康快照。
type ExplorationPersistence struct {
	DroppedActivity int64     `json:"dropped_activity"`
	WriteFailures   int64     `json:"write_failures"`
	DanglingAnchors int64     `json:"dangling_anchors"`
	MissingAssets   []int64   `json:"missing_assets,omitempty"`
	LastReason      string    `json:"last_reason,omitempty"`
	LastAt          time.Time `json:"last_at,omitempty"`
}

// Healthy 表示这次探索至今没有任何已知的落库失败。
func (p ExplorationPersistence) Healthy() bool {
	return p.DroppedActivity == 0 && p.WriteFailures == 0 && p.DanglingAnchors == 0
}

func NewPersistenceHealth() *PersistenceHealth {
	return &PersistenceHealth{byID: map[int64]*expHealth{}}
}

func (h *PersistenceHealth) slot(expID int64) *expHealth {
	e := h.byID[expID]
	if e == nil {
		e = &expHealth{missingAssets: map[int64]struct{}{}}
		h.byID[expID] = e
	}
	return e
}

// RecordDroppedActivity 记一条彻底写不进去、已经被丢弃的 activity。
func (h *PersistenceHealth) RecordDroppedActivity(expID int64, reason string) {
	if h == nil || expID <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.slot(expID)
	e.droppedActivity++
	e.lastReason, e.lastAt = reason, time.Now()
}

// RecordWriteFailure 记一次非 activity 的落库失败（节点、意图状态、溯源等）。
func (h *PersistenceHealth) RecordWriteFailure(expID int64, reason string) {
	if h == nil || expID <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.slot(expID)
	e.writeFailures++
	e.lastReason, e.lastAt = reason, time.Now()
}

// RecordDanglingAnchors 记一次锚点引用了不存在的 asset（23503 的根因）。
func (h *PersistenceHealth) RecordDanglingAnchors(expID int64, missing []int64, reason string) {
	if h == nil || expID <= 0 || len(missing) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.slot(expID)
	e.danglingAnchors += int64(len(missing))
	for _, id := range missing {
		if len(e.missingAssets) < 64 {
			e.missingAssets[id] = struct{}{}
		}
	}
	e.lastReason, e.lastAt = reason, time.Now()
}

// Snapshot 返回某次探索的健康快照。
func (h *PersistenceHealth) Snapshot(expID int64) ExplorationPersistence {
	if h == nil {
		return ExplorationPersistence{}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.byID[expID]
	if e == nil {
		return ExplorationPersistence{}
	}
	out := ExplorationPersistence{
		DroppedActivity: e.droppedActivity,
		WriteFailures:   e.writeFailures,
		DanglingAnchors: e.danglingAnchors,
		LastReason:      e.lastReason,
		LastAt:          e.lastAt,
	}
	for id := range e.missingAssets {
		out.MissingAssets = append(out.MissingAssets, id)
	}
	sort.Slice(out.MissingAssets, func(i, j int) bool { return out.MissingAssets[i] < out.MissingAssets[j] })
	return out
}

// Unhealthy 返回当前所有有落库失败记录的 exploration。
func (h *PersistenceHealth) Unhealthy() map[int64]ExplorationPersistence {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	ids := make([]int64, 0, len(h.byID))
	for id := range h.byID {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	out := map[int64]ExplorationPersistence{}
	for _, id := range ids {
		if s := h.Snapshot(id); !s.Healthy() {
			out[id] = s
		}
	}
	return out
}

// Forget 丢弃一次探索的健康记录（任务删除后调用，避免进程内无界增长）。
func (h *PersistenceHealth) Forget(expID int64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.byID, expID)
}
