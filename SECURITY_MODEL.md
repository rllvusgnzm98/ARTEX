# ARTEX threat model

_Status: built from code (no SECURITY_MODEL.md in the repo) plus the owner's answers. Items marked **[user]** come from the repository owner; everything else is inferred from the code._

## System overview
ARTEX is a self-hosted, AI-driven penetration-testing platform: a single Go binary (`cmd/artex`) with an embedded Next.js UI (`web/`), backed by PostgreSQL (`db/`) and local SQLite/FTS5 traffic stores (`traffic/`). LLM agents (`agent/`: Planner, Worker, MainAgent) run offensive tools against operator-defined targets, under scope/egress guards (`guard/`) and a tool-call approval engine (`intercept/`). Deployment: `Dockerfile` + `docker-compose.yml` (8787 published on all interfaces, recording proxy 8788 on 127.0.0.1) or systemd via `install.sh`/`packaging/`.

## Components
| Name | Code | Notes |
|---|---|---|
| Web UI | `web/` | Static export embedded via `server/webui_embed.go`; served publicly, auth enforced client-side + on `/api`. Camouflage gate `server/gate.go`, `config/gate.go`. |
| API & Auth | `server/` (HTTP handlers, `server/server.go` routes), `config/jwt.go`, `server/auth.go`, `server/jwtkeyring.go` | Single admin password (bcrypt), HS256 JWT (header, `artex_token` cookie, or `?token=` query). CORS `*`. |
| Agent Runtime | `agent/`, `llmpool/`, `llmrec/`, `sidequestion/`, `mcphttp/`, `skills/`, `tools/`, `server/customtool.go`, `server/hackbots_tools.go`, `server/engine*.go` | LLM agents executing shell commands/tools on the ARTEX host; custom tools (command/python/http). |
| Guardrails | `guard/` (RoE scope, egress, honeypot, tarpit), `intercept/` (allow/deny/ask rules, credential redaction), `honeydetect/` | The controls that keep agents in scope and away from the platform's own infra. |
| Offensive Infra | `session/` (HTTP shell footholds, encryption), `tunnel/` (SOCKS/port-forward processes), `traffic/` (go-mitmproxy recorder), `server/taskproxy.go`, `stage/` + `GET /s/{token}/{name}` | Talks to and is reachable by target machines. |
| Data Stores | `db/`, credential store (AES-GCM, key = `data/jwt.key`), workspace (`server/workspace.go`), `evidence/`, `report/` | Findings, assets, credentials, traffic, task archives. |
| Updater & Packaging | `selfupdate/`, `server/update.go`, `install.sh`, `update.sh`, `build.sh`, `Dockerfile`, `packaging/` | Downloads/replaces the binary; supply chain for tool manifests (`tools-manifest.sh`). |

## Trust boundaries & entry points
1. **Network → API (8787)**: unauthenticated: `/api/auth/status|init|login|refresh|rotate-key|change-password` (prefix-exempt in `requireAuth`), `/api/health`, `GET /s/{token}/{name}` (stage download, random token), the UI shell. Everything else under `/api/` requires a valid JWT. First-run `/api/auth/init` is open until the admin password is set.
2. **Browser → API**: CORS `Access-Control-Allow-Origin: *`; token accepted via cookie and query string (CSRF / token leakage surface).
3. **Targets → Platform**: data returned by targets (HTTP responses, banners, shell output, files) flows into LLM context, the traffic index, findings, and the UI (prompt injection, stored XSS, parser bugs). Footholds/tunnels/stage downloads accept connections from target hosts.
4. **LLM agent → Host**: agents run commands and tools on the ARTEX host; `guard/` + `intercept/` are the only barriers between a (possibly prompt-injected) agent and the host, the platform's own infrastructure, and out-of-scope systems.
5. **Third parties**: LLM providers, ScopeSentry sync (`server/sync_scopesentry.go`), MCP servers (`mcphttp/`), update server (`selfupdate/`), notification webhooks (`notify/`).

## Assets
- **[user] Most critical: the ARTEX host itself** — no RCE or escape from agents/attackers onto the host.
- The ARTEX host (code execution, data dir `data/` incl. `jwt.key` = JWT signing seed + AES master key for sessions/credentials).
- Captured target credentials, sessions/footholds, tunnels.
- LLM API keys and integration secrets (ScopeSentry API key, webhooks).
- Findings, evidence, recorded traffic, reports (client-confidential).
- Integrity of scope enforcement (an agent attacking out-of-scope systems is a legal/business incident).

## Attackers that matter
- **[user] Unauthenticated network attacker** reaching 8787: exposure is unknown, so treat it as internet-exposed.
- **[user] Hostile target (in scope)**: a system under test that returns malicious content to inject prompts, break out of RoE scope/egress controls, exploit parsers, or attack the operator's browser via stored data.
- **Malicious web page** in the operator's browser (CSRF / cross-origin reads given CORS `*`).
- **Compromised upstream** (update server, tool downloads, skills, MCP servers).
- **[user] Not an attacker:** the authenticated admin operator is fully trusted (single admin password; no multi-user/role model).

## Existing controls
- bcrypt admin password with minimum policy; first-init guarded by `InsertSettingIfAbsent`.
- JWT keyring rotation (`server/jwtkeyring.go`), 401 refresh.
- Camouflage gate (detect/enforce) for the UI shell only.
- RoE scope modes strict/warn/off for proxy, tunnel, session registration (`guard/roe.go`, `server/roe.go`); egress check (`guard/egress.go`) recognizing own infra hosts.
- Intercept rules allow/deny/ask with LLM judge and credential redaction (`intercept/`).
- Workspace path resolution `wsResolve`; stage downloads via random token with TTL/one-shot.
- Traffic proxy bound to 127.0.0.1:8788.
- Tool manifests pinned with hashes; `artex doctor -strict-tools`.

## Out of scope / accepted risk
- **[user]** Features that execute commands by design when the authenticated admin invokes them (custom tools, workspace writes, self-update, tunnels, agent shell tools) are accepted risk. Abuse of them by anyone other than the admin (an unauthenticated attacker, a hostile target via prompt injection) is still in scope.

## Infrastructure
- **[user]** No separate infrastructure repository; deployed with the repo's `Dockerfile` / `docker-compose.yml` (8787 published on all interfaces).

## Open questions
- Actual network exposure of 8787 in real deployments (treated as internet-exposed until known).
