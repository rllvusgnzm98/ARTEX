#!/usr/bin/env bash
# 钉版 packaging/tools-manifest.json。
#   tools-manifest.sh verify
#   tools-manifest.sh fetch [--dest data/tools]
#   tools-manifest.sh pin [--write] [--manifest packaging/tools-manifest.json]
# 只有 pin --write 会改 JSON。fetch 只把落地二进制写到 --dest，并与清单 sha256 比对。
# sha256 是解包后的 ELF（data/tools/<name>），不是压缩包。取不到官方资产或校验失败时不写哈希。
set -eu

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "需要 python3" >&2
  exit 1
fi

exec "$PY" - "$@" <<'PY'
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import zipfile

UA = "artex-tools-manifest"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN = {
    "mimikatz", "pypykatz", "lazagne", "peass", "impacket", "nxc",
    "suo5-payloads", "penelope",
}
TUNNELS = {"suo5", "chisel", "ligolo-agent", "ligolo-proxy"}
RECON = ("gogo", "naabu", "httpx", "katana", "fscan")
SPECS = {
    "naabu": {"repo": "projectdiscovery/naabu", "mode": "pd-zip"},
    "httpx": {"repo": "projectdiscovery/httpx", "mode": "pd-zip"},
    "katana": {"repo": "projectdiscovery/katana", "mode": "pd-zip"},
    "fscan": {"repo": "shadow1ng/fscan", "mode": "raw-or-zip"},
    "gogo": {"repo": "chainreactors/gogo", "mode": "exact", "exact": "gogo_linux_amd64"},
}


def die(msg, code=1):
    print("error: " + msg, file=sys.stderr)
    raise SystemExit(code)


def http_get(url, timeout=300):
    last = None
    for i in range(3):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Accept": "application/octet-stream, application/vnd.github+json;q=0.9, */*;q=0.8",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            time.sleep(2 * (i + 1))
    raise last


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def dump_json(path, obj):
    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tools-manifest.", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def excluded_name(name):
    low = name.lower()
    tokens = (
        "musl", "arm64", "armv", "aarch64", "windows", "darwin", "macos",
        "386", "i386", "checksum", "sha256", "sha512", ".txt", ".sig",
        "license", "nolocal",
    )
    if any(tok in low for tok in tokens):
        return True
    if re.search(r"(^|[^a-z])arm([^a-z0-9]|$)", low):
        return True
    if "web" in low and "http" not in low:
        return True
    return False


def linux_amd64_name(name):
    low = name.lower()
    if "linux" not in low:
        return False
    return "amd64" in low or "x86_64" in low or "x64" in low


def pick_asset(spec, assets):
    mode = spec["mode"]
    if mode == "exact":
        exact = spec["exact"]
        for asset in assets:
            if asset.get("name") == exact:
                return asset
        zips = [
            a for a in assets
            if a.get("name", "").lower() == exact + ".zip"
        ]
        if len(zips) == 1:
            return zips[0]
        raise RuntimeError("release 里没有 %s" % exact)

    def candidates(want_zip):
        out = []
        for asset in assets:
            name = asset.get("name") or ""
            low = name.lower()
            archive = low.endswith((".zip", ".tar.gz", ".tgz", ".tar"))
            if want_zip and not low.endswith(".zip"):
                continue
            if not want_zip and archive:
                continue
            if excluded_name(name) or not linux_amd64_name(name):
                continue
            out.append(asset)
        return out

    if mode == "pd-zip":
        found = candidates(True)
    else:
        found = candidates(False) or candidates(True)
    if len(found) != 1:
        names = [a.get("name") for a in found]
        raise RuntimeError("linux/amd64 资产不是唯一的: %s" % names)
    return found[0]


def pick_checksum(assets):
    found = [a for a in assets if "checksum" in (a.get("name") or "").lower()]
    if len(found) != 1:
        names = [a.get("name") for a in found]
        raise RuntimeError("checksum 文件不是唯一的: %s" % names)
    return found[0]


def checksum_for(text, filename):
    base = os.path.basename(filename)
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([0-9a-fA-F]{64})\s+\*?(\S+)$", line)
        if match:
            got = os.path.basename(match.group(2).lstrip("*"))
            if got == base or match.group(2) == filename:
                return match.group(1).lower()
        match = re.match(r"^SHA256\s*\((.+)\)\s*=\s*([0-9a-fA-F]{64})$", line, re.I)
        if match and os.path.basename(match.group(1).strip()) == base:
            return match.group(2).lower()
    return None


def extract_elf(blob, tool):
    if blob.startswith(b"\x7fELF"):
        return blob

    def from_members(members):
        preferred = []
        others = []
        for name, data in members:
            if not data.startswith(b"\x7fELF"):
                continue
            if os.path.basename(name) == tool:
                preferred.append(data)
            else:
                others.append((name, data))
        if len(preferred) == 1:
            return preferred[0]
        if len(preferred) > 1:
            raise RuntimeError("%s 压缩包里有多个同名 ELF" % tool)
        if len(others) == 1:
            return others[0][1]
        if not others:
            raise RuntimeError("%s 压缩包里没有 ELF" % tool)
        names = [n for n, _ in others]
        raise RuntimeError("%s 压缩包里 ELF 不唯一: %s" % (tool, names))

    if blob[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            members = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                members.append((info.filename, zf.read(info)))
        return from_members(members)
    if blob[:2] == b"\x1f\x8b" or blob[:3] == b"BZh":
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
        except tarfile.TarError as exc:
            raise RuntimeError("无法解包 %s: %s" % (tool, exc))
        members = []
        for info in tf.getmembers():
            if not info.isfile():
                continue
            extracted = tf.extractfile(info)
            if extracted is None:
                continue
            members.append((info.name, extracted.read()))
        return from_members(members)
    raise RuntimeError("%s 既不是 ELF 也不是 zip/tar" % tool)


def latest_release(repo):
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    payload = json.loads(http_get(url, timeout=60).decode("utf-8"))
    tag = payload.get("tag_name") or ""
    assets = payload.get("assets") or []
    if not tag or not assets:
        raise RuntimeError("%s 没有 latest release 资产" % repo)
    return tag, assets


def pin_one(tool):
    spec = SPECS[tool]
    tag, assets = latest_release(spec["repo"])
    asset = pick_asset(spec, assets)
    checksum_asset = pick_checksum(assets)
    name = asset["name"]
    url = asset.get("browser_download_url") or ""
    if not url.startswith("https://"):
        raise RuntimeError("%s 缺少 https 下载地址" % name)
    print("GET %s %s" % (tool, name), flush=True)
    blob = http_get(url)
    checksum_blob = http_get(checksum_asset["browser_download_url"])
    archive_sum = hashlib.sha256(blob).hexdigest()
    expected = checksum_for(checksum_blob.decode("utf-8", "replace"), name)
    if not expected:
        raise RuntimeError("%s 的 checksum 文件没有 %s 这一行" % (checksum_asset["name"], name))
    if expected != archive_sum:
        raise RuntimeError("%s 校验失败: 下载 %s 上游 %s" % (name, archive_sum, expected))
    elf = extract_elf(blob, tool)
    if len(elf) < 4096 or not elf.startswith(b"\x7fELF"):
        raise RuntimeError("%s 落地文件不是 ELF" % tool)
    digest = hashlib.sha256(elf).hexdigest()
    if not HEX64.match(digest):
        raise RuntimeError("内部哈希格式错误")
    return {
        "ok": True,
        "version": tag,
        "url": url,
        "sha256": digest,
        "asset": name,
        "archive_sha256": archive_sum,
        "elf": elf,
    }


def cmd_verify(manifest_path, optional_path):
    errors = []
    try:
        manifest = load_json(manifest_path)
    except (OSError, json.JSONDecodeError) as exc:
        die("清单无法解析 %s: %s" % (manifest_path, exc))
    tools = manifest.get("tools")
    if not isinstance(tools, list):
        die("清单 tools 不是数组")
    for entry in tools:
        name = str(entry.get("name") or "").strip()
        low = name.lower()
        if low in FORBIDDEN:
            errors.append("默认清单不得包含 %s" % name)
        category = entry.get("category")
        if category not in ("tunnel", "arsenal"):
            errors.append("%s 分类非法: %s" % (name, category))
        if low in TUNNELS and not entry.get("optional"):
            errors.append("%s 是隧道类，必须 optional" % name)
        if entry.get("optional"):
            if str(entry.get("sha256") or "").strip():
                errors.append("%s 是 optional，sha256 必须留空" % name)
            continue
        version = str(entry.get("version") or "").strip()
        url = str(entry.get("url") or "").strip()
        sha = str(entry.get("sha256") or "").strip().lower()
        platform = str(entry.get("platform") or "").strip()
        if not version:
            errors.append("%s 非 optional 必须有 version" % name)
        if not url.startswith("https://"):
            errors.append("%s 非 optional 必须有 https url" % name)
        if not HEX64.match(sha):
            errors.append("%s 非 optional 必须有 64 位十六进制 sha256" % name)
        if not platform:
            errors.append("%s 非 optional 必须有 platform" % name)
    if os.path.isfile(optional_path):
        try:
            optional = load_json(optional_path)
        except (OSError, json.JSONDecodeError) as exc:
            die("可选清单无法解析: %s" % exc)
        for entry in optional.get("tools") or []:
            name = entry.get("name")
            if not entry.get("optional"):
                errors.append("可选档 %s 必须 optional" % name)
            if str(entry.get("sha256") or "").strip():
                errors.append("可选档 %s 哈希必须留空" % name)
    else:
        errors.append("缺少 %s" % optional_path)
    if errors:
        for item in errors:
            print("verify: " + item, file=sys.stderr)
        raise SystemExit(1)
    print("verify ok: %s" % manifest_path)


def apply_pins(manifest, results):
    by_name = {}
    for entry in manifest.get("tools") or []:
        by_name[entry.get("name")] = entry
    for tool, info in results.items():
        entry = by_name.get(tool)
        if entry is None:
            print("skip write %s: 清单中无此条" % tool, file=sys.stderr)
            continue
        if not info.get("ok"):
            if not str(entry.get("sha256") or "").strip():
                entry["optional"] = True
            print("keep %s: %s" % (tool, info.get("error")), file=sys.stderr)
            continue
        entry["version"] = info["version"]
        entry["platform"] = "linux/amd64"
        entry["sha256"] = info["sha256"]
        entry["url"] = info["url"]
        entry["optional"] = False


def cmd_pin(manifest_path, write):
    manifest = load_json(manifest_path)
    results = {}
    for tool in RECON:
        try:
            info = pin_one(tool)
            elf = info.pop("elf")
            results[tool] = info
            print(
                "PIN %s %s sha256=%s asset=%s archive_sha256=%s url=%s"
                % (tool, info["version"], info["sha256"], info["asset"], info["archive_sha256"], info["url"])
            )
            again = hashlib.sha256(elf).hexdigest()
            if again != info["sha256"]:
                die("%s 重复哈希不一致" % tool)
        except Exception as exc:
            results[tool] = {"ok": False, "error": str(exc)}
            print("FAIL %s: %s" % (tool, exc), file=sys.stderr)
    if write:
        apply_pins(manifest, results)
        dump_json(manifest_path, manifest)
        print("wrote %s" % manifest_path)
    else:
        print("pin 未写 JSON（加 --write 才改清单）")
    return 0


def cmd_fetch(manifest_path, dest):
    manifest = load_json(manifest_path)
    os.makedirs(dest, exist_ok=True)
    failed = 0
    for entry in manifest.get("tools") or []:
        name = entry.get("name") or ""
        sha = str(entry.get("sha256") or "").strip().lower()
        url = str(entry.get("url") or "").strip()
        if not sha:
            print("SKIP %s: 未钉 sha256，不下载" % name)
            continue
        if not url.startswith("https://"):
            print("FAIL %s: 有 sha256 但没有 https url" % name, file=sys.stderr)
            failed += 1
            continue
        blob = http_get(url)
        elf = extract_elf(blob, name)
        digest = hashlib.sha256(elf).hexdigest()
        if digest != sha:
            print("FAIL %s: 落地 %s != 清单 %s" % (name, digest, sha), file=sys.stderr)
            failed += 1
            continue
        out = os.path.join(dest, name)
        with open(out, "wb") as f:
            f.write(elf)
        try:
            os.chmod(out, 0o755)
        except OSError:
            pass
        print("OK %s -> %s" % (name, out))
    if failed:
        raise SystemExit(1)


def parse_args(argv):
    if not argv:
        die("用法: tools-manifest.sh {verify|fetch|pin} [--write] [--dest DIR] [--manifest FILE]")
    cmd = argv[0]
    write = False
    dest = "data/tools"
    manifest = "packaging/tools-manifest.json"
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--write":
            write = True
        elif arg == "--dest" and i + 1 < len(argv):
            i += 1
            dest = argv[i]
        elif arg == "--manifest" and i + 1 < len(argv):
            i += 1
            manifest = argv[i]
        else:
            die("未知参数: %s" % arg)
        i += 1
    return cmd, write, dest, manifest


def main():
    cmd, write, dest, manifest = parse_args(sys.argv[1:])
    optional = os.path.join(os.path.dirname(manifest) or ".", "tools-manifest.optional.json")
    if cmd == "verify":
        cmd_verify(manifest, optional)
    elif cmd == "pin":
        cmd_pin(manifest, write)
    elif cmd == "fetch":
        cmd_fetch(manifest, dest)
    else:
        die("未知子命令: %s" % cmd)


if __name__ == "__main__":
    main()
PY
