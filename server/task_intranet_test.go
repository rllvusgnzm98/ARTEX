package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestHasLiveTaskSessionNilSafe(t *testing.T) {
	if hasLiveTaskSession(nil, errors.New("list failed"), 1) {
		t.Fatal("查找失败不得误切内网变体")
	}
	if hasLiveTaskSession(nil, nil, 1) {
		t.Fatal("无记录应为外网")
	}
	if hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: 2, Status: db.SessionAlive}}, nil, 1) {
		t.Fatal("其他任务的存活会话不得切本任务变体")
	}
	if hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: 1, Status: db.SessionAlive}}, nil, 0) {
		t.Fatal("非法 taskID 不得切变体")
	}
	if !hasLiveTaskSession([]*db.SessionRecord{{CreatedByTask: 3, Status: db.SessionAlive}}, nil, 3) {
		t.Fatal("本任务存活会话应切内网变体")
	}
}

func TestTaskIntranetNilStoreAndNoTunnelsStayExternal(t *testing.T) {
	var s Server
	if s.taskIntranet(1) {
		t.Fatal("sessStore 为 nil 且无隧道台账时必须保持外网")
	}
	if s.taskIntranet(0) {
		t.Fatal("非法 taskID 必须保持外网")
	}
}

func TestTaskIntranetLiveSessionOnly(t *testing.T) {
	pg := openIntranetTestDB(t)
	task, err := pg.CreateTask("intranet variant fixture", "live session check", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(task.ID) })
	other, err := pg.CreateTask("other task", "unrelated", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask other: %v", err)
	}
	t.Cleanup(func() { _ = pg.DeleteTask(other.ID) })

	store := db.NewSessionStore(pg, []byte("intranet-variant-master-key"))
	s := &Server{ctx: context.Background(), sessStore: store}

	if s.taskIntranet(task.ID) {
		t.Fatal("尚无会话时应为外网")
	}

	ctx := context.Background()
	deadID, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.0.2.10/s.php", Lang: "php",
		Status: db.SessionDead, CreatedByTask: task.ID,
		Secret: json.RawMessage(`{"url":"http://192.0.2.10/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create dead: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), deadID) })
	if s.taskIntranet(task.ID) {
		t.Fatal("仅有 dead 会话不得切内网变体")
	}

	aliveOther, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.0.2.11/s.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: other.ID,
		Secret: json.RawMessage(`{"url":"http://192.0.2.11/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create other alive: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), aliveOther) })
	if s.taskIntranet(task.ID) {
		t.Fatal("其他任务的存活会话不得切本任务变体")
	}

	aliveID, err := store.Create(ctx, &db.SessionRecord{
		Kind: "http_php", URL: "http://192.0.2.12/s.php", Lang: "php",
		Status: db.SessionAlive, CreatedByTask: task.ID,
		Secret: json.RawMessage(`{"url":"http://192.0.2.12/s.php"}`),
	})
	if err != nil {
		t.Fatalf("Create alive: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), aliveID) })
	if !s.taskIntranet(task.ID) {
		t.Fatal("本任务存活立足点会话应切内网变体")
	}
}
