package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/stage"
)

// tokenLogPrefix 是日志与 Activity 里允许出现的 token 前缀长度。完整 token
// 不得写入 Summary/Detail 或 log.Printf；工具返回给 worker 的下载 URL 仍带全文。
const tokenLogPrefix = 8

// testStageActivity 仅供测试观察即将写入 Activity 的 Summary/Detail。
var testStageActivity func(summary, detail string)

func stageTokenPrefix(token string) string {
	if len(token) <= tokenLogPrefix {
		return token
	}
	return token[:tokenLogPrefix]
}

// stageEventTexts 生成 stage 记账的摘要与详情：只含 token 前缀，不含全文。
func stageEventTexts(ev stage.Event) (summary, detail string) {
	e := ev.Entry
	prefix := stageTokenPrefix(e.Token)
	summary = fmt.Sprintf("stage %s: %s (token=%s… size=%d bytes, expires %s)",
		ev.Kind, e.Name, prefix, e.Size, e.ExpiresAt.Format(time.RFC3339))
	if ev.Kind == stage.EventDownload {
		summary = fmt.Sprintf("stage download: %s 被 %s 拉取 %d/%d 字节(累计命中 %d 次)",
			e.Name, ev.Remote, ev.Bytes, e.Size, e.Hits)
	}
	detail = fmt.Sprintf("token=%s… name=%s size=%d one_shot=%v expires_at=%s remote=%s bytes=%d hits=%d",
		prefix, e.Name, e.Size, e.OneShot, e.ExpiresAt.Format(time.RFC3339), ev.Remote, ev.Bytes, e.Hits)
	return summary, detail
}

// taskWorkspaceRoot 返回当前任务工作区根：dataDir/tasks/<taskID>。
// 不用控制台全局工作区（s.m.dir 本身）。taskID 必须是单段名称，防止被当成路径。
func (s *Server) taskWorkspaceRoot(taskID string) (string, error) {
	if s == nil || s.m == nil || strings.TrimSpace(s.m.dir) == "" {
		return "", fmt.Errorf("任务工作区未就绪")
	}
	id := strings.TrimSpace(taskID)
	if id == "" || id == "." || id == ".." || filepath.Base(id) != id || strings.ContainsAny(id, `/\`) {
		return "", fmt.Errorf("缺少任务上下文，拒绝读取主机路径")
	}
	base := filepath.Clean(s.m.dir)
	tasksRoot := filepath.Clean(filepath.Join(base, "tasks"))
	root := filepath.Clean(filepath.Join(tasksRoot, id))
	if !pathInside(tasksRoot, root) {
		return "", fmt.Errorf("缺少任务上下文，拒绝读取主机路径")
	}
	return root, nil
}

// resolveTaskWorkspaceFile 把用户给出的 path 解析到当前任务工作区内的实路径。
// 跟随符号链接后必须仍落在工作区根内；不在根内、不存在或不是普通文件一律拒绝。
func (s *Server) resolveTaskWorkspaceFile(taskID, path string) (string, error) {
	root, err := s.taskWorkspaceRoot(taskID)
	if err != nil {
		return "", err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("不在当前任务工作区内或不存在")
	}
	cand := path
	if !filepath.IsAbs(path) {
		cand = filepath.Join(root, path)
	}
	cand = filepath.Clean(cand)

	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("不在当前任务工作区内或不存在")
	}
	rootReal = filepath.Clean(rootReal)

	if _, err := os.Lstat(cand); err != nil {
		return "", fmt.Errorf("不在当前任务工作区内或不存在")
	}
	real, err := filepath.EvalSymlinks(cand)
	if err != nil {
		return "", fmt.Errorf("不在当前任务工作区内或不存在")
	}
	real = filepath.Clean(real)
	if !pathInside(rootReal, real) {
		return "", fmt.Errorf("不在当前任务工作区内或不存在")
	}
	st, err := os.Stat(real)
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("不在当前任务工作区内或不存在")
	}
	return real, nil
}

// pathInside 报告 path 是否等于 root 或位于 root 之下（按已清理的绝对路径比较）。
func pathInside(root, path string) bool {
	if path == root {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(path, root+sep)
}
