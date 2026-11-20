//go:build windows

package evidence

// syncDir 在 Windows 上不做目录 fsync：以只读方式打开的目录句柄调用
// FlushFileBuffers 会返回 Access is denied，而 Windows 本身也不提供与 Unix
// 等价的“目录项落盘”保证。文件正文在 rename 之前已 f.Sync()，写到目标路径
// 的字节仍然持久化；这里返回 nil 只跳过目录项本身的刷盘。
func syncDir(string) error { return nil }
