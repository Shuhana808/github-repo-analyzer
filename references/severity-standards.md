# Severity & Confidence Standards

This reference documents the exact schemas, severity levels, confidence levels, and interpretation guidance emitted by `scripts/analyze_repo.py` (`scripts/analyzer.py` and `scripts/dependency_graph.py`).

**Core principle:** Every emitted finding is an **unverified heuristic review target** (`"status": "unverified heuristic"`), not a confirmed bug or vulnerability. Never upgrade a heuristic match into a confirmed vulnerability without reading and verifying the code in context.

---

## 1. Heuristic Code & Secret Findings (`report.json["findings"]`)

Each finding contains these exact fields (present as-is; never invent fields):

`id`, `title`, `severity`, `confidence`, `scope`, `path`, `line`, `evidence`, `recommendation`, `status`

### Severity Rubric

Severity reflects **potential impact if the match is real and reachable from untrusted input**.

#### `high`

Potential code execution, command execution, unsafe deserialization, dynamic SQL construction, or exposed credentials.

| Rule ID | Detection Method | Meaning & Reviewer Verification |
|---|---|---|
| `PY_EVAL`, `PY_EXEC` | Python AST (`builtins.eval`, `builtins.exec`) | Dynamic Python execution. Check whether untrusted input can reach the argument; prefer `ast.literal_eval` or a constrained parser. |
| `PY_SHELL` | Python AST (`subprocess.*` with `shell=True`) | Shell-enabled subprocess call. Verify whether command arguments are static or user-controlled; prefer argument lists with `shell=False`. |
| `PY_OS_SYSTEM` | Python AST (`os.system`, `os.popen`) | Direct shell command execution. Check input origin; prefer `subprocess.run(..., shell=False)`. |
| `PY_PICKLE` | Python AST (`pickle.load(s)`, `marshal.load(s)`, `shelve.open`) | Unsafe Python deserialization. Confirm data source is strictly trusted; otherwise use JSON or a schema parser. |
| `PY_YAML_LOAD` | Python AST (`yaml.unsafe_load` or `yaml.load` without `SafeLoader`/`BaseLoader`) | Potentially unsafe YAML deserialization. Prefer `yaml.safe_load()` or `Loader=yaml.SafeLoader`. |
| `JS_EVAL`, `JS_NEW_FUNCTION` | Regex on JS/TS (non-comment lines) | Dynamic JS execution via `eval(...)` or `new Function(...)`. Verify input origin. |
| `JS_CHILD_PROCESS` | Context-aware regex on JS/TS (`child_process.exec(Sync)`, `execSync`, or bare `exec` when `child_process` is imported; ignores `RegExp.exec`) | Shell-enabled command execution. Verify command input; prefer `execFile`/`spawn` with an argument array. |
| `GO_EXEC_SHELL` | Regex on `.go` (`exec.Command("sh"|"bash"|"zsh", "-c", ...)`) | Shell invocation in Go. Pass executable and argument slice directly. |
| `SQL_BUILD` | Regex on `.py`, `.js`, `.ts`, `.java`, `.php`, `.rb`, `.go` requiring SQL clause pairs (`SELECT...FROM`, `INSERT INTO`, `UPDATE...SET`, `DELETE FROM`) with string concatenation/interpolation | Possible dynamically constructed SQL. Verify parameterized queries are used instead of string building. |
| `SECRET_PRIVATE_KEY`, `SECRET_AWS_KEY`, `SECRET_GITHUB_TOKEN`, `SECRET_SLACK_TOKEN`, `SECRET_OPENAI_KEY`, `SECRET_GOOGLE_API_KEY`, `SECRET_ANTHROPIC_KEY`, `SECRET_STRIPE_KEY`, `SECRET_NPM_TOKEN`, `SECRET_PYPI_TOKEN`, `SECRET_DB_URL` | Regex across analyzed text files | Potential hardcoded credential or DB URL with embedded password. Evidence is **always auto-redacted** at detection time (`[REDACTED — ...]`). Never echo secret values; verify whether live and rotate immediately if real. |

#### `medium`

Potential injection, disabled TLS verification, or risky sink with context-dependent exploitability.

| Rule ID | Detection Method | Meaning & Reviewer Verification |
|---|---|---|
| `JS_INNERHTML` | Regex on JS/TS (`.innerHTML =`) | Potential DOM XSS. Verify whether assigned HTML is trusted or sanitized; prefer `textContent`. |
| `JS_DANGEROUS_HTML` | Regex on JS/TS (`dangerouslySetInnerHTML`) | React raw HTML injection target. Verify HTML is sanitized (e.g., DOMPurify) before rendering. |
| `JS_TLS_REJECT_UNAUTH` | Regex on JS/TS (`rejectUnauthorized: false`) | TLS certificate verification disabled. Confirm this is strictly limited to local dev/test. |
| `PY_TLS_VERIFY_FALSE` | Python AST (`requests`/`httpx` calls with `verify=False`) | TLS certificate verification disabled. Confirm this is not used in production network calls. |
| `PY_TAR_EXTRACTALL` | Python AST (`*.extractall(...)` in files importing `tarfile`) | Potential archive path traversal (Zip Slip). Verify member validation or `filter="data"` (Python 3.12+). |

#### `low`

Observational code-hygiene markers; contextual only.

| Rule ID | Detection Method | Meaning & Reviewer Verification |
|---|---|---|
| `TODO` | Regex (`TODO`, `FIXME`, `XXX`) | Unfinished-work marker. Stored separately in `report.json["todos"]` (excluded from `heuristic_findings` and capped independently at 500) and summarized compactly in `report.md` (first 25 of total) so it never drowns out security findings. |

---

### Confidence Labels

Confidence reflects **pattern certainty**, orthogonal to severity:

| Confidence | Meaning |
|---|---|
| `high` | Very specific pattern (e.g., `SECRET_*` in production code, `TODO` markers). |
| `medium` | Structural/AST or scoped call match (e.g., `PY_EVAL`, `PY_SHELL`, `JS_CHILD_PROCESS`, `GO_EXEC_SHELL`), still requires checking untrusted-input reachability. |
| `low` | Broader heuristic with higher false-positive rate (e.g., `SQL_BUILD`, `JS_INNERHTML`, `JS_DANGEROUS_HTML`, or `SECRET_*` inside test/example/docs fixtures). |

---

### Scope Classification (`scope`)

Findings are automatically sorted **severity first (`high` -> `medium` -> `low`), then `production` before non-production**:

- `production`: Default for all paths not matching non-production conventions. Always triage these first.
- `test`: Paths under `test/`, `tests/`, `__tests__/`, `spec/`, `specs/`, `testing/`, `fixtures/`, `testdata/`, or filenames like `conftest.py`, `test_*.py`, `*_test.*`, `*.test.*`, `*.spec.*`.
- `example`: Paths under `example(s)/`, `sample(s)/`, `demo(s)/`, `benchmark(s)/`.
- `docs`: Paths under `doc/`, `docs/`, `documentation/`.

---

## 2. Dependency Graph Insights (`report.json["architecture"]["dependency_graph"]["insights"]`)

Each insight contains: `id`, `category`, `severity`, `title`, `summary`, `modules` (or `packages`), `evidence`, `recommendation`.

| Severity | Categories | Interpretation |
|---|---|---|
| `medium` | `circular_dependency`, `package_dependency_cycle` | Mutually dependent modules or top-level packages. Review coupling boundaries and consider extracting shared interfaces/utilities. |
| `low` | `high_fan_out`, `not_reachable_from_entry_points` | Module importing many internal modules, or module not reached from detected entry points. **Unreachable != dead code** (tests, plugins, library APIs, and framework-loaded files frequently appear here). |
| `info` | `high_fan_in`, `isolated_modules` | High-impact hub module imported by many others (treat changes carefully), or module with no resolved internal imports. |

---

## 3. Handling Edge Cases & Anti-Patterns

- **Secrets:** Never quote matched secret values—even partially. Cite `path:line`, the rule ID, and advise immediate rotation if live. Test/example fixtures receive `confidence: "low"` automatically.
- **Zero findings:** State explicitly that `0` configured patterns matched and that this does **not** prove the repository is bug-free or secure.
- **LLM commentary & Context Triage separation:** Keep verbatim facts from `summary.json`/`report.json` (`status: "unverified heuristic"`) distinct from any read-only Context Triage or impact analysis, which must be tagged `*(LLM interpretation)*`. Use only the three non-overclaiming triage buckets (`Likely benign in context`, `Needs manual verification`, `Elevated review priority`) and never certify code as guaranteed safe or claim a confirmed exploit without execution.
- **No fabricated severities:** Do not invent `CRITICAL` or `GOOD` labels or claim tests/static-analysis tools were run when reporting outputs from `analyze_repo.py`.
