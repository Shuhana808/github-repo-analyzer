# GitHub Repository Analyzer

   > Bounded, read-only architecture mapping, dependency-graph analysis, and heuristic first-pass code review for any repository.

Point it at a local directory, a GitHub/Git URL (including branch/subpath browser URLs like `/tree/main/packages/api`), or `owner/repo[@ref]` shorthand and get back four deterministic artifacts—`report.md`, `summary.json`, `report.json`, and an `architecture.mmd` Mermaid graph—plus a tailored summary adapted to your goal (`Onboarding`, `Security`, `Architecture`, or `Balanced`).

Zero external Python dependencies. Strictly read-only on the target repository.

---

## Read this first

**This is a heuristic first-pass triage, not a validated security audit.**

- **Read-only & non-executing:** Never executes repository code, tests, package managers, install scripts, git hooks, or build commands.
- **No compiler/SAST/CVE scans:** Static analyzers (Semgrep, CodeQL, mypy, ESLint), CVE scanners (`pip-audit`, `npm audit`, OSV), and taint analysis are **not** run. Dependency CVEs are **not** reported.
- **Unverified matches:** Every finding is labeled `unverified heuristic` with a relative `path:line`, scope (`production`, `test`, `example`, `docs`), severity, and confidence so you can verify it in seconds.

Use it to:

- Orient quickly on an unfamiliar codebase before contributing, forking, or auditing.
- Map internal module dependencies, circular dependencies, high fan-in hubs, and entry points.
- Surface a prioritized shortlist of production review targets (dynamic execution, shell calls, unsafe deserialization/YAML, dynamic SQL, and hardcoded secret patterns).

Do **not** use it:

- As the sole basis for a security-critical decision or signed audit.
- As proof of absence of bugs or vulnerabilities (`0 findings` means `0 configured patterns matched`).

---

## What it produces

Running the analyzer writes four files to the output directory:

| File | Contents |
|---|---|
| `summary.json` | Compact, bounded JSON digest (summary, prioritized top findings, entry points, routes/models, dependencies, graph metrics/insights, limitations) designed for fast, context-safe AI agent reads. |
| `report.md` | Human-readable Markdown report: language inventory, manifests, repo health & test presence, architecture map, inline or linked Mermaid graph, dependency insights, prioritized findings, compact TODO summary, and truncation/limitation disclosures. |
| `report.json` | Full structured data (`summary`, `files`, `findings`, `architecture`, `dependency_graph.metrics`, `dependency_graph.insights`). Authoritative source for citations and automation. |
| `architecture.mmd` | Standalone Mermaid `flowchart LR` dependency graph (bounded to 200 nodes / 400 edges) with color-coded entry points, cycles, high fan-in hubs, high fan-out modules, and isolated modules. |

See [`references/sample-report.md`](references/sample-report.md) for a real generated example, [`references/severity-standards.md`](references/severity-standards.md) for the severity & confidence rubric, and [`references/report-template.md`](references/report-template.md) for the chat summary template.

---

## Focus Modes

When invoked through an AI agent using [`SKILL.md`](SKILL.md), the summary adapts automatically to your prompt:

| Mode | Example prompt | What is prioritized |
|---|---|---|
| **Onboarding** | *"Help me understand `pallets/flask`"* | Directory layout, tech stack & manifests, repo health (git HEAD, CI, README/LICENSE, detected test frameworks), entry points, and 3–5 core files to read first. |
| **Security** | *"Do a security triage of `https://github.com/owner/repo`"* | High/medium findings in `production` scope first (test/example/docs separated), read-only Context Triage on up to top 8 production findings (`*(LLM interpretation)*`), exposed HTTP routes, risky sinks & auto-redacted `SECRET_*` matches with `path:line` and concrete follow-ups. |
| **Architecture** | *"Map dependencies and cycles in `/path/to/repo`"* | Circular module/package dependencies, high fan-in/fan-out hubs, largest files, unreachable/isolated modules (`unreachable != dead code`), and graph insights. |
| **Balanced** *(default)* | *"Analyze `owner/repo`"* | Top production findings (with read-only Context Triage on up to top 5 production high findings) + repo health & test presence + key architecture highlights + finding-driven next steps. |

---

## Quick start

### Via Agent / OpenClaw

```bash
openclaw run github-repo-analyzer "Analyze https://github.com/pallets/flask"
openclaw run github-repo-analyzer "Help me onboard onto pallets/click"
openclaw run github-repo-analyzer "Check architecture and cycles in /path/to/local/repo"
```

### Standalone CLI (Python >= 3.10, stdlib only)

```bash
# 1. Resolve a local path, GitHub/Git URL (including /tree/<ref>/<subdir>), or owner/repo[@ref]
REPO=$(python3 scripts/clone_repo.py "pallets/flask")

# Optional: target a specific branch/tag/SHA or monorepo subdirectory
REPO=$(python3 scripts/clone_repo.py "https://github.com/org/monorepo/tree/develop/packages/api")
# Or via explicit flags:
REPO=$(python3 scripts/clone_repo.py "org/monorepo" --ref develop --subdir packages/api)

# 2. Run the read-only analyzer (writes report.md, summary.json, report.json, architecture.mmd)
OUT=$(python3 scripts/analyze_repo.py "$REPO")
echo "Reports written to: $OUT"
```

For a **local repository** (or a single subdirectory of a local monorepo), pass `--out` outside the target repo so the repo stays untouched:

```bash
OUT=$(python3 scripts/analyze_repo.py /path/to/my-repo --subdir packages/api --out /tmp/repo-analyzer/my-repo-api-report)
```

---

## How it works

Two deterministic scripts with a clean stdout/stderr contract (stdout emits one resolved path; stderr logs diagnostics):

1. **`scripts/clone_repo.py <input> [--ref <ref>] [--subdir <path>]`**
   - Accepts a local directory, `https://github.com/owner/repo` (including pasted browser URLs like `/tree/<ref>/<subdir>`, `/blob/<ref>/<path>`, `/commit/<sha>`), GitLab `/-/tree/...`, `git@github.com:owner/repo.git`, or `owner/repo[@ref]`.
   - Local paths use no network, reject `--ref` (never mutate a local working tree), support `--subdir` safely inside the repo root, and are checked against `MAX_SIZE_MB`.
   - Remote inputs perform a shallow clone (`git clone --depth 1 --single-branch`, with full-clone + detached-checkout fallback for commit SHAs) into `WORK_ROOT`, or refresh an existing clone (`git fetch --depth 1` + `git reset --hard FETCH_HEAD`).
   - `git@github.com:` URLs are normalized to HTTPS so public clones work without SSH keys and `GITHUB_TOKEN` auth applies cleanly; credentials are always redacted from logs and error output.

2. **`scripts/analyze_repo.py <repo-path> [--subdir <path>] [--out <output-dir>]`**
   - **Inventory, health & onboarding:** Counts languages across 30+ extensions, builds a deterministic **Where to start reading** guide and top-level directory overview, locates root and nested manifests, reads git HEAD metadata + recent git churn hotspots & high-churn hubs (on non-shallow git repos), detects license type (SPDX/common licenses), extracts a brief README summary, discovers build/run/test commands from `package.json`, `pyproject.toml`, `Makefile`, `justfile`, `Taskfile.yml`, `docker-compose.yml`, and `.github/workflows/*.yml` (read-only), discovers environment variable names (keys only from `.env.example`/templates + source references), and detects CI configs, Dockerfiles, largest files, and test presence/frameworks (without executing tests).
   - **Architecture & dependency graph:** Parses Python imports with `ast.parse` and JS/TS (including `tsconfig.json`/`jsconfig.json` `baseUrl` & `paths` aliases), Go (including nested `go.mod`), Rust, and Java imports with conservative regex; extracts direct dependencies from root and nested `pyproject.toml`, `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle(.kts)`, `Gemfile`, `composer.json`, `pubspec.yaml`, and `*.csproj`/`*.fsproj`; detects entry points, HTTP/RPC routes across 15+ frameworks (including Next.js App Router/Pages API and gRPC/Protobuf), OpenAPI/Swagger/GraphQL/Protobuf API contract specs, and ORM/SQL/Prisma/GraphQL/Proto/type data models; computes full-repo and **production-only subgraph** metrics (SCCs, cycles, fan-in/fan-out, reachability); renders priority-selected `architecture.mmd` plus an inline package-level Mermaid overview for large repos.
   - **Heuristic code & secret scan:** Uses Python `ast` for Python call sinks (`PY_EVAL`, `PY_EXEC`, `PY_SHELL`, `PY_OS_SYSTEM`, `PY_PICKLE`, `PY_YAML_LOAD`, `PY_TLS_VERIFY_FALSE`, `PY_TAR_EXTRACTALL`) to avoid comment/docstring/string noise; context-aware JS/TS checks (`JS_EVAL`, `JS_NEW_FUNCTION`, `JS_CHILD_PROCESS`, `JS_TLS_REJECT_UNAUTH`, `JS_INNERHTML`, `JS_DANGEROUS_HTML`); conservative SQL string-building checks; and auto-redacted secret patterns (`SECRET_PRIVATE_KEY`, `SECRET_AWS_KEY`, `SECRET_GITHUB_TOKEN`, `SECRET_SLACK_TOKEN`, `SECRET_OPENAI_KEY`, `SECRET_GOOGLE_API_KEY`, `SECRET_ANTHROPIC_KEY`, `SECRET_STRIPE_KEY`, `SECRET_NPM_TOKEN`, `SECRET_PYPI_TOKEN`, `SECRET_DB_URL`).

---

## Configuration

All environment variables are optional. See [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `WORK_ROOT` | `/tmp/repo-analyzer` | Clone destination (and recommended report root for local repos). |
| `MAX_SIZE_MB` | `500` | Abort local scan (or warn after remote clone) above this size in MB. |
| `GIT_TIMEOUT` | `120` | Timeout in seconds per `git` operation. |
| `GITHUB_TOKEN` | *(unset)* | Optional HTTPS auth for private GitHub clones (fine-grained `repo:read`). |
| `MAX_FILES` | `20000` | Maximum supported files analyzed per repository. |

---

## Privacy & safety

- **Strictly read-only on target repos:** Never modifies, commits to, or writes inside the analyzed repository. Writes go only to `WORK_ROOT` and `--out`.
- **Sensitive files skipped:** `.env`, `.env.*`, `id_rsa`, `id_ed25519`, `credentials.json`, and `secrets.json` are skipped without being read.
- **Secrets auto-redacted:** Matched `SECRET_*` lines never echo secret values in `report.json` or `report.md`; only `path:line` and pattern type are recorded.
- **Untrusted data handling:** When run via [`SKILL.md`](SKILL.md), all repository files and report excerpts are treated strictly as untrusted data, never as instructions.

---

## Known limitations

Every report includes explicit limitations and truncation disclosures:

- **Heuristic imports & entry points:** Python uses `ast.parse`; JS/TS (with heuristic `tsconfig.json`/`jsconfig.json` `baseUrl` and `paths` alias resolution), Go (including nested `go.mod`), Rust, and Java use conservative regex. Dynamic imports, Go multi-file packages, and Rust macros can be missed.
- **Manifest-only dependencies:** Direct dependencies from supported manifests only; transitive dependencies and lockfiles are excluded.
- **Unreachable != dead code:** Tests, plugins, library APIs, and framework-loaded modules often appear unreachable from detected entry points.
- **Bounded caps:** `MAX_BYTES = 1 MB/file`, `MAX_ARCHITECTURE_BYTES = 32 MB/repo`, `MAX_FILES = 20,000` (configurable), findings capped at `2,000`. All budget hits and skipped-file counts are disclosed in `report.md` and `report.json`.

---

## Requirements & testing

- Python >= 3.10 (standard library only; no `pip install` required)
- `git` on `PATH` (for remote clones and git HEAD metadata)

Run the unit test suite:

```bash
python3 -m unittest discover -s tests -v
```

---

## Contributing & license

Issues, PRs, and false-positive reports (with rule ID, code snippet, and expected behavior) are welcome.

Licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0) (`PolyForm-Noncommercial-1.0.0`). See [`LICENSE`](LICENSE).

Free for personal, educational, and noncommercial use. Commercial use requires a separate commercial license—contact `shuhana.azmin@gmail.com` or purchase through an authorized marketplace.

Required Notice: Copyright 2026 Shuhana (https://github.com/Shuhana808/github-repo-analyzer)
