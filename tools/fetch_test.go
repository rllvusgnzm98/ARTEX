package tools

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestFetchPlatforms(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for fetch script")
	}
	script, err := os.ReadFile(filepath.Join("..", "tools-manifest.sh"))
	if err != nil {
		t.Fatal(err)
	}
	_, source, ok := strings.Cut(string(script), "<<'PY'\n")
	if !ok {
		t.Fatal("Python entry point missing")
	}
	source = strings.TrimSuffix(source, "PY\n")
	probe := `
import tempfile, json, os, hashlib
assert platform_matches('linux/amd64,linux/arm64', 'linux/arm64')
assert platform_matches('any', 'darwin/arm64')
assert not platform_matches('linux/amd64', 'linux/arm64')
with tempfile.TemporaryDirectory() as root:
    payload = b'\x7fELFfixture'
    calls = []
    def fake_get(url):
        calls.append(url)
        return payload
    http_get = fake_get
    manifest = os.path.join(root, 'manifest.json')
    entries = [dict(name='right', platform='linux/arm64', url='https://fixture/right', sha256=hashlib.sha256(payload).hexdigest()), dict(name='wrong', platform='linux/amd64', url='https://fixture/never', sha256='0'*64)]
    with open(manifest, 'w') as f: json.dump({'tools':entries}, f)
    cmd_fetch(manifest, os.path.join(root,'bin'), 'linux/arm64')
    assert calls == ['https://fixture/right'], calls
    assert open(os.path.join(root,'bin/right'),'rb').read() == payload
    assert not os.path.exists(os.path.join(root,'bin/wrong'))
    entries[0]['sha256'] = '0'*64
    with open(manifest, 'w') as f: json.dump({'tools':[entries[0]]}, f)
    try:
        cmd_fetch(manifest, os.path.join(root,'bad'), 'linux/arm64')
        raise AssertionError('checksum mismatch accepted')
    except SystemExit as err:
        assert err.code == 1
    assert not os.path.exists(os.path.join(root,'bad/right'))
    with open(manifest, 'w') as f: json.dump({'tools':[]}, f)
    cmd_fetch(manifest, os.path.join(root,'empty'), 'linux/arm64')
    pins = {'tools':[dict(name='right', platform='linux/amd64'), dict(name='right', platform='linux/arm64', sha256='preserved')]}
    apply_pins(pins, {'right':dict(ok=True,version='v1',sha256='new',url='https://fixture')})
    assert pins['tools'][1]['sha256'] == 'preserved'
print('platform skip and matching fetch passed')
`
	cmd := exec.Command(python, "-c", "__name__='fetch_test'\n"+source+probe)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fetch: %v\n%s", err, out)
	}
	t.Log(string(out))
}

func TestImageToolPinsBothArchitectures(t *testing.T) {
	m, err := Load(filepath.Join("..", "packaging", "image-tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	main, err := Load(defaultManifestPath(t))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]bool{}
	for _, entry := range append(main.Tools, m.Tools...) {
		if entry.Optional {
			continue
		}
		if len(entry.SHA256) != 64 || !strings.HasPrefix(entry.URL, "https://github.com/") {
			t.Fatalf("invalid pin: %+v", entry)
		}
		key := entry.Name + " " + entry.Platform
		if counts[key] {
			t.Fatalf("duplicate pin: %s", key)
		}
		counts[key] = true
	}
	for _, name := range []string{"gogo", "naabu", "httpx", "katana", "fscan", "nuclei", "feroxbuster"} {
		for _, arch := range []string{"amd64", "arm64"} {
			if !counts[name+" linux/"+arch] {
				t.Fatalf("missing %s %s pin", name, arch)
			}
		}
	}
}
