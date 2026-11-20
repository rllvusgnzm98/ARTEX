//go:build !windows

package evidence

import "os"

// syncDir 把新建的目录项落盘（rename 后调用）。非 Windows 平台对目录句柄做
// fsync 是受支持的语义。
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
