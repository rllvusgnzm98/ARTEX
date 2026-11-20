//go:build windows

package main

import "os"

// usr1 在 Windows 上没有 SIGUSR1，返回 nil 让 main 跳过 Notify。
func usr1() os.Signal { return nil }
