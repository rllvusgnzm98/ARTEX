package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const setupTokenFilename = "setup.token"

// setupGate 保护首次设置密码入口。/api/auth/* 不经 requireAuth，未初始化时
// 谁先打到 /api/auth/init 谁就成了管理员，所以必须让调用方证明自己能看到
// 服务端的日志或文件系统：启动时生成一次性令牌，写进 keyDir/setup.token
// 并打印到日志，init 必须携带它；用过即销毁。
type setupGate struct {
	mu    sync.Mutex
	token string
	path  string
}

// initSetupToken 仅在密码尚未设置（或无法确认）时生成令牌。读失败也生成：
// authInit 自己会在读失败时拒绝，多一个令牌不会放宽任何东西。
func (s *Server) initSetupToken(keyDir string) {
	path := filepath.Join(keyDir, setupTokenFilename)
	s.setup.path = path
	if s.m == nil || s.m.pg == nil {
		return
	}
	if hash, _, err := s.m.pg.GetSetting(authPassKey); err == nil && hash != "" {
		_ = os.Remove(path)
		return
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("[auth] 生成初始化令牌失败，初始化入口保持关闭: %v", err)
		return
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		log.Printf("[auth] 写入初始化令牌 %s 失败（令牌仍见下方日志）: %v", path, err)
	}
	s.setup.mu.Lock()
	s.setup.token = tok
	s.setup.mu.Unlock()
	log.Printf("[auth] 管理员密码尚未设置。打开 /setup 时需填写初始化令牌: %s（同时写入 %s）", tok, path)
}

// checkSetupToken 常量时间比较；服务端没有令牌时一律拒绝（fail closed）。
func (s *Server) checkSetupToken(got string) bool {
	s.setup.mu.Lock()
	want := s.setup.token
	s.setup.mu.Unlock()
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// consumeSetupToken 在密码设置成功后销毁令牌。
func (s *Server) consumeSetupToken() {
	s.setup.mu.Lock()
	s.setup.token = ""
	path := s.setup.path
	s.setup.mu.Unlock()
	if path != "" {
		_ = os.Remove(path)
	}
}
