package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Crown Jewels (目标导向分析) HTTP surface: operators flag high-value target
// assets (global, asset-level) and read, per task, the attack path lineage and
// frontier distance toward each target so planning can prioritize reaching them.

// markCrownJewel flags a global asset as a crown jewel and records its business
// value note. POST /api/assets/{id}/crown-jewel {note}.
func (s *Server) markCrownJewel(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid asset id")
		return
	}
	var body struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := as.SetCrownJewel(id, true, body.Note); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeCrownJewelAsset(w, as, id)
}

// unmarkCrownJewel clears the crown jewel flag (and note). DELETE /api/assets/{id}/crown-jewel.
func (s *Server) unmarkCrownJewel(w http.ResponseWriter, r *http.Request) {
	as := s.assetStore()
	if as == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "invalid asset id")
		return
	}
	if err := as.SetCrownJewel(id, false, ""); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeCrownJewelAsset(w, as, id)
}

func writeCrownJewelAsset(w http.ResponseWriter, as *db.AssetStore, id int64) {
	assets, err := as.GetByIDs([]int64{id})
	if err != nil || len(assets) == 0 {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "asset": assets[0]})
}

// CrownJewelTargetDTO is one crown jewel target with this task's standing toward it.
type CrownJewelTargetDTO struct {
	Asset   *db.Asset           `json:"asset"`
	Status  db.CrownJewelStatus `json:"status"`
	GoalIDs []string            `json:"goal_ids,omitempty"`
}

// crownJewelPaths returns, for this task, every crown jewel target plus the attack
// path lineage and frontier distance toward it. GET /api/tasks/{id}/crown-jewels/paths.
func (s *Server) crownJewelPaths(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	as := s.assetStore()
	if as == nil || t.Store == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	jewels, err := as.CrownJewels()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]CrownJewelTargetDTO, 0, len(jewels))
	for _, a := range jewels {
		st, err := t.Store.CrownJewelStatusFor(a.ID)
		if err != nil {
			continue
		}
		dto := CrownJewelTargetDTO{Asset: a, Status: st}
		if gids, _ := t.Store.AnchoredGoalIDs(a.ID); len(gids) > 0 {
			for _, g := range gids {
				dto.GoalIDs = append(dto.GoalIDs, strconv.FormatInt(g, 10))
			}
		}
		out = append(out, dto)
	}
	writeJSON(w, 200, map[string]any{"targets": out})
}

// anchorGoalAsset anchors a goal node to a (crown jewel) asset so the planner
// knows which objective targets it. POST /api/tasks/{id}/goals/{gid}/anchors {asset_id}.
func (s *Server) anchorGoalAsset(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除,无法锚定目标")
		return
	}
	defer s.engine.decInflight(t.ID)
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "invalid goal id")
		return
	}
	var body struct {
		AssetID int64 `json:"asset_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AssetID <= 0 {
		writeErr(w, 400, "asset_id required")
		return
	}
	node, err := t.Store.GetNode(gid)
	if err != nil || node == nil || node.Kind != db.KindGoal {
		writeErr(w, 404, "goal not found")
		return
	}
	if err := t.Store.Anchor(gid, body.AssetID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// unanchorGoalAsset removes a goal→asset anchor.
// DELETE /api/tasks/{id}/goals/{gid}/anchors/{assetID}.
func (s *Server) unanchorGoalAsset(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除,无法取消锚定")
		return
	}
	defer s.engine.decInflight(t.ID)
	gid, err := strconv.ParseInt(r.PathValue("gid"), 10, 64)
	if err != nil || gid <= 0 {
		writeErr(w, 400, "invalid goal id")
		return
	}
	assetID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("assetID")), 10, 64)
	if err != nil || assetID <= 0 {
		writeErr(w, 400, "invalid asset id")
		return
	}
	if err := t.Store.Unanchor(gid, assetID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
