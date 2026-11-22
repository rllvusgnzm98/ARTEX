// Package tools 管理外部工具二进制的钉版清单与完整性自检。
//
// 清单（packaging/tools-manifest.json）记录名称/用途/版本/平台/sha256/url/相对路径。
// sha256 是 data/tools/<name> 落地后的二进制，不是压缩包。空串表示「未钉」：
// 宁可留空也不编造哈希；未钉则只查存在性。
// optional 条目允许空哈希。非 optional 的非空哈希不匹配默认只警告，不阻断
// （可能自编译）；doctor -strict-tools 才会把非 optional 的缺失/不匹配记为 FAIL。
// 未知 JSON 字段会被忽略，旧二进制读到带 url/optional 的新清单也不会失败。
// 清单文件缺失时由调用方警告并跳过汇总。
// 默认清单不把凭据收割、提权工具或 suo5-payloads/penelope 当作必装项。
package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Autumn-27/artex/config"
)

// Entry 是清单里一个外部工具的记录。
type Entry struct {
	Name     string `json:"name"`               // 工具名，与 platform 联合唯一
	Purpose  string `json:"purpose"`            // 用途（一行话）
	Version  string `json:"version"`            // 钉的版本；空 = 未钉
	Platform string `json:"platform"`           // linux/amd64；空或 any = 不限
	SHA256   string `json:"sha256"`             // 落地二进制的 sha256；空串 = 未钉（不校验）
	URL      string `json:"url,omitempty"`      // 官方发布资产。哈希针对解包后的二进制，不是压缩包
	Path     string `json:"path"`               // 相对 data 目录的路径（文件或目录）
	Env      string `json:"env"`                // 可选：覆盖路径的环境变量（如 ARTEX_CHISEL_PATH）
	Category string `json:"category"`           // tunnel（可选隧道） | arsenal（军火库）
	Optional bool   `json:"optional,omitempty"` // true = 可选：允许空哈希，-strict-tools 也不因此 FAIL
}

// Manifest 是 tools-manifest.json 的整体结构。
type Manifest struct {
	Tools []Entry `json:"tools"`
}

// ManifestPath 解析清单文件路径：
//
//	env ARTEX_TOOLS_MANIFEST  >  BaseDir()/packaging/tools-manifest.json
//
// 返回的路径可能不存在（开发态/裁剪部署）——调用方用 os.IsNotExist 判断后跳过汇总。
// packaging/tools-manifest.optional.json 不在这条路径上，默认不下载、不参与校验。
func ManifestPath() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_TOOLS_MANIFEST")); v != "" {
		return v
	}
	return filepath.Join(config.BaseDir(), "packaging", "tools-manifest.json")
}

// Load 读取并解析清单文件。文件缺失时返回的 error 满足 os.IsNotExist。
// 未知字段忽略，因此旧二进制可以读新清单。
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Status 是单个工具的自检结论。
type Status int

const (
	StatusOK            Status = iota // 存在；若钉了哈希则一致
	StatusUnpinned                    // 存在，但清单未钉哈希（只报存在，不校验）
	StatusMissing                     // 缺失（精简环境常态，不视为故障）
	StatusMismatch                    // 存在但哈希与清单不符（只警告，可能自编译）
	StatusNotApplicable               // 平台不符，跳过（避免 arm64 对照 amd64 钉版假报 mismatch）
)

// CheckResult 是单个工具的自检结果。
type CheckResult struct {
	Entry  Entry
	Status Status
	Path   string // 实际解析出的绝对/相对路径（env 覆盖优先）
	Actual string // 实际 sha256（算了才有）
}

// Check 对清单里每个工具做存在性 + （钉了哈希的）sha256 校验。dataDir 是 data
// 目录；条目带 env 且环境变量已设置时优先用环境变量指定的路径。目录条目只做存在性检查。
func Check(m *Manifest, dataDir string) []CheckResult {
	if m == nil {
		return nil
	}
	out := make([]CheckResult, 0, len(m.Tools))
	for _, e := range m.Tools {
		out = append(out, CheckEntry(e, dataDir))
	}
	return out
}

// CheckEntry 校验单个清单条目（见 Check）。
// 清单 platform 与当前 GOOS/GOARCH 不符时直接 StatusNotApplicable，不算缺失，
// 也不把另一架构的文件哈希算成 mismatch。
func CheckEntry(e Entry, dataDir string) CheckResult {
	r := CheckResult{Entry: e, Status: StatusMissing}
	p := ""
	overridden := false
	if e.Env != "" {
		p = strings.TrimSpace(os.Getenv(e.Env))
		overridden = p != ""
	}
	if p == "" {
		p = filepath.Join(dataDir, filepath.FromSlash(e.Path))
	}
	if !overridden && filepath.ToSlash(e.Path) == "tools/"+e.Name {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			image := filepath.Join(ImageToolsDir, e.Name)
			if _, err := os.Stat(image); err == nil {
				p = image
			}
		}
	}
	r.Path = p
	if !platformApplies(e.Platform) {
		r.Status = StatusNotApplicable
		return r
	}
	st, err := os.Stat(p)
	if err != nil {
		return r
	}
	want := strings.ToLower(strings.TrimSpace(e.SHA256))
	if st.IsDir() || want == "" {
		r.Status = StatusUnpinned
		return r
	}
	sum, err := fileSHA256(p)
	if err != nil {
		return r
	}
	r.Actual = sum
	if sum == want {
		r.Status = StatusOK
	} else {
		r.Status = StatusMismatch
	}
	return r
}

// platformApplies reports whether entry platform matches this process.
// Empty, "any", or a list containing "any" matches everything.
// "linux/amd64;any" is explicitly unrestricted. Comma, semicolon, or space separates tokens.
func platformApplies(platform string) bool {
	p := strings.ToLower(strings.TrimSpace(platform))
	if p == "" || p == "any" {
		return true
	}
	runtimePlat := runtime.GOOS + "/" + runtime.GOARCH
	saw := false
	for _, part := range strings.FieldsFunc(p, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '|'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "any" {
			return true
		}
		saw = true
		if part == runtimePlat {
			return true
		}
	}
	return !saw
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
