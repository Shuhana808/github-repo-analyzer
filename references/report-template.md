# Report & Summary Templates

This file defines the two report formats used by `github-repo-analyzer`:

1. **Agent Chat Summary** — concise, Focus-Mode-tailored synthesis returned to the user in conversation (required by `SKILL.md`).
2. **Generated Disk Artifacts** — deterministic `report.md`, `summary.json`, `report.json`, and `architecture.mmd` written by `scripts/analyze_repo.py`.

---

## 1. Agent Chat Summary Template

Fill every section. Keep deterministic facts from `report.json` strictly separate from any added commentary, which must be tagged `*(LLM interpretation)*`.

```markdown
### Overview (Mode: <Onboarding | Security | Architecture | Balanced>)
<One paragraph, <= 80 words: repo name/HEAD, primary languages, manifests, detected entry points, and files/modules analyzed.>

### Focus Highlights
<!-- Adapt this section to the active Focus Mode:

- Onboarding:
  - Directory overview (summary.directory_overview) & README summary
  - Tech stack & direct dependencies (root + nested manifests & architecture.dependencies)
  - Repo health (git HEAD, README/LICENSE + license_type, CI configs, container files, discovered build/run/test commands, detected test files & frameworks)
  - Entry points, detected API routes & data models, and 3-5 core files to read first (entry points + top_fan_in_modules; mark rationale *(LLM interpretation)*)

- Security:
  - Production high/medium findings first (preserve id, severity, confidence, scope, path:line, evidence, recommendation, status)
  - Read-only Context Triage on up to top 8 production high/medium findings (~15–25 surrounding lines): tag each `*(LLM interpretation)*` as `Likely benign in context`, `Needs manual verification`, or `Elevated review priority` + concrete next check (never echo secret values)
  - Exposed HTTP route surface (architecture.routes, production scope first) when present
  - Non-production (test/example/docs) findings noted separately by count or brief summary
  - Auto-redacted SECRET_* matches cited by path:line with rotation reminder (never quote values)

- Architecture:
  - Module & package circular dependencies (cyclic_components, package_dependency_cycles)
  - High fan-in / fan-out hubs (top_fan_in_modules, top_fan_out_modules)
  - Detected API routes & data models/schemas (architecture.routes, architecture.models)
  - Largest files (repo_health.largest_files)
  - Isolated / unreachable modules (always state: unreachable != dead code)
  - Key dependency_graph.insights (id, severity, affected modules)

- Balanced (default):
  - Top heuristic findings (up to 10, production first; include severity breakdown + read-only Context Triage on up to top 5 production high findings tagged `*(LLM interpretation)*`)
  - Repo health (license type, discovered commands, read-only test presence)
  - Key architecture highlights (entry points, routes/models counts, cycles, top hubs, unreachable counts)
-->

### Outputs & Verification Note
- **Findings:** <N> total (<P> production, <NP> non-production; high: <H>, medium: <M>, low: <L>). *(If performed: Context-triaged <K> of <P_HM> production high/medium findings.)*
- **Artifacts:** `<OUT>/report.md`, `<OUT>/summary.json`, `<OUT>/report.json`, `<OUT>/architecture.mmd` *(mention any `%% Truncated:` header if present)*.
- **Reminder:** All findings are `unverified heuristic` review targets—verify each cited `path:line` in context before acting.

### Known Limitations
- <Quote summary.json["summary"]["limitations"] verbatim>
- <Mandatory truncation disclosures whenever findings_truncated == true, skipped_counts.file_budget > 0, or architecture.summary.skipped_files_due_to_budget > 0>

### Suggested Next Steps
- <2–3 concrete follow-ups anchored to actual entities in summary.json: e.g. trace `<route>` at `path:line` down to `<model>`, untangle cycle `<pkgA> <-> <pkgB>`, walk through `<top_fan_in_module>` or `<entry_point>`, or context-triage the remaining `<N>` findings.>
```

---

## 2. Generated `report.md` Sections (`scripts/report.py`)

For reference, `scripts/analyze_repo.py` automatically writes `report.md` with the following deterministic sections:

1. **Header & Summary** — repository path, read-only flag, files analyzed, lines counted, heuristic findings (with production/non-production and severity breakdown), TODO count, and standing caveat.
2. **Scan coverage & truncation disclosures** *(when applicable)* — findings cap, file budget, architecture byte budget, Python AST parse errors, and skipped-file counts (`sensitive`, `symlink`, `oversized`, `unreadable`, `unsupported`, `file_budget`).
3. **Language inventory & Directory overview** — file counts by language and top-level directory breakdown (files, lines, primary language, test count).
4. **Project manifests** — detected manifest, container, and build files (root and nested).
5. **Repository health & test presence** — git branch/commit/date, README summary, LICENSE type, CI configs, container files, discovered build/run/test commands (read-only), read-only test detection, and top 10 largest files.
6. **Architecture analysis** — entry points, detected API routes, detected data models/schemas, direct manifest dependencies (root + nested), module map (first 100), resolved internal imports (first 120), unresolved local imports (first 80), inline Mermaid diagram (or inline package-level overview + link to `architecture.mmd`), dependency insights, and architecture limitations.
7. **Findings** — code and secret heuristic findings sorted by severity and production scope first (with `SECRET_*` values auto-redacted).
8. **TODO / FIXME markers** *(when present)* — compact list of first 25 markers with total count.
9. **Top-level entries, Limitations, and Suggested next steps**.
