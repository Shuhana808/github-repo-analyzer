# Changelog

All notable changes to `github-repo-analyzer` are documented in this file.

## [1.0.0] - 2026-11-24

### Added
- **Browser URL, branch/commit & monorepo subpath support (`clone_repo.py`, `analyze_repo.py`):**
  - Automatically parses GitHub `/tree/<ref>[/<subdir>]`, `/blob/<ref>/<path>`, `/commit/<sha>`, GitLab `/-/tree/...`, and `owner/repo@<ref>` shorthand.
  - Added `--ref` (remote clones only, never mutates local repos) and `--subdir` flags with path-traversal guards and enclosing git-root metadata detection.
- **Compact `summary.json` artifact:** Bounded, context-safe digest generated alongside `report.md`, `report.json`, and `architecture.mmd` for fast AI agent reads.
- **Guided read-only Context Triage & finding-driven follow-ups (`SKILL.md`):** Instructs the agent to inspect surrounding lines for top production findings in Security/Balanced modes using non-overclaiming triage buckets and suggest concrete entity-anchored next steps.
- **Production-only dependency subgraph metrics:** Separates production coupling, cycles, and reachability from test/example/docs noise in `dependency_graph.metrics.production`.
- **Onboarding & configuration intelligence:** Deterministic `reading_order` ("Where to start reading"), environment variable surface discovery (key names only from `.env.example`/templates and source code), expanded command discovery (`justfile`, `Taskfile.yml`, `docker-compose.yml`, `.github/workflows/*.yml`), and read-only git churn hotspots & high-churn production hubs on non-shallow git repos.
- **Expanded ecosystem & security coverage:** Direct dependency parsers for `pom.xml`, `build.gradle(.kts)`, `Gemfile`, `composer.json`, `pubspec.yaml`, and `*.csproj`/`*.fsproj`; OpenAPI/Swagger, GraphQL, Protobuf, and Next.js App Router/Pages API detection; additional AST/regex security rules (`PY_TLS_VERIFY_FALSE`, `PY_TAR_EXTRACTALL`, `JS_NEW_FUNCTION`, `JS_TLS_REJECT_UNAUTH`) and auto-redacted secret patterns (`SECRET_ANTHROPIC_KEY`, `SECRET_STRIPE_KEY`, `SECRET_NPM_TOKEN`, `SECRET_PYPI_TOKEN`, `SECRET_DB_URL`).

### Changed
- Separated `TODO`/`FIXME`/`XXX` markers into a dedicated `todos` array (capped independently at 500) so hygiene markers never inflate `heuristic_findings` counts or consume the findings cap.
- Relocated legacy test-execution script (`run_tests.py`) to `excluded/` and removed duplicate `cli.py` so the active skill package stays 100% read-only and non-executing.
- Upgraded `examples/sample_project` and regenerated `references/sample-report.md` to showcase routes, data models, cycles, env vars, reading order, and production subgraph metrics.
- Unified product naming to `github-repo-analyzer` across reports and JSON metadata.
