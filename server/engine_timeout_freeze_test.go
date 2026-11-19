package server

import (
	"testing"
	"time"
)

// 时钟跳变检测纯函数:注入计划/实际睡眠时长(等价于假时钟),验证冻结判定与顺延量。
func TestDetectFreeze(t *testing.T) {
	cases := []struct {
		name    string
		planned time.Duration
		actual  time.Duration
		want    time.Duration
	}{
		{"正常轮询 2s 不顺延", 2 * time.Second, 2*time.Second + 50*time.Millisecond, 0},
		{"正常 nap 30s 不顺延", 30 * time.Second, 30*time.Second + 500*time.Millisecond, 0},
		{"首轮 planned=0 立即醒不顺延", 0, 10 * time.Millisecond, 0},
		{"跳 65s 顺延 65s", 2 * time.Second, 67 * time.Second, 65 * time.Second},
		{"冻结 7 小时顺延差值", 30 * time.Second, 7*time.Hour + 30*time.Second, 7 * time.Hour},
		{"恰好低于阈值不顺延", 30 * time.Second, 30*time.Second + freezeDetectThreshold - time.Second, 0},
		{"时钟回拨不顺延", 30 * time.Second, 5 * time.Second, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := detectFreeze(c.planned, c.actual); got != c.want {
				t.Fatalf("detectFreeze(%v, %v) = %v, want %v", c.planned, c.actual, got, c.want)
			}
		})
	}
}

// 连续小跳:每轮各自低于阈值,不累计、不顺延。
func TestDetectFreezeConsecutiveSmallJumps(t *testing.T) {
	total := time.Duration(0)
	for i := 0; i < 5; i++ {
		// 每轮超睡 30s(< 60s 阈值),连跳 5 轮共超 150s 也不应顺延。
		total += detectFreeze(2*time.Second, 32*time.Second)
	}
	if total != 0 {
		t.Fatalf("连续小跳累计顺延 %v, want 0", total)
	}
}

// 顺延累计正确:两次大跳分别检出,由调用方累加。
func TestDetectFreezeAccumulates(t *testing.T) {
	var shift time.Duration
	shift += detectFreeze(30*time.Second, 30*time.Second+65*time.Second)
	shift += detectFreeze(30*time.Second, 30*time.Second+time.Hour)
	want := 65*time.Second + time.Hour
	if shift != want {
		t.Fatalf("累计顺延 %v, want %v", shift, want)
	}
}

// 顺延只改进程内存 deadline:map 中的值被推后,Task.DeadlineAt(模拟 DB 盖章值)不变。
// 重启等价于清空 map 后再读,taskDeadline 回落到 DB 原值。
func TestExtendDeadlineMemoryOnly(t *testing.T) {
	const dbDeadline int64 = 1_700_000_000
	e := &Engine{}
	task := &Task{ID: "t-freeze", DeadlineAt: dbDeadline}
	e.deadline.Store(task.ID, dbDeadline)

	e.extendDeadline(task.ID, 65*time.Second)
	got := e.taskDeadline(task)
	if got != dbDeadline+65 {
		t.Fatalf("内存 deadline=%d, want %d", got, dbDeadline+65)
	}
	if task.DeadlineAt != dbDeadline {
		t.Fatalf("DB/结构体 DeadlineAt 被改成 %d, 顺延不得写库", task.DeadlineAt)
	}

	// 模拟重启:丢弃内存 map,回落到结构体上的 DB 值。
	e.deadline.Delete(task.ID)
	if got := e.taskDeadline(task); got != dbDeadline {
		t.Fatalf("重启回落后 deadline=%d, want DB %d", got, dbDeadline)
	}
}
