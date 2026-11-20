//go:build unix

package main

import (
	"os"
	"syscall"
)

// usr1 返回 SIGUSR1。defer-entry 测试靠它在 ListenPort 之后补绑 socks/local。
func usr1() os.Signal { return syscall.SIGUSR1 }
