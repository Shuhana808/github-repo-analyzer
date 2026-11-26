from __future__ import annotations

import ast
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath
from .architecture import MODEL_EXTRA_SUFFIXES, SOURCE_SUFFIXES, _parse_toml, analyze_architecture

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "node_modules", "vendor", "dist", "build",
    ".venv", "venv", "target", "coverage", ".next", ".gradle",
}
SENSITIVE = {
    ".env", ".env.local", ".env.production", ".env.development", ".env.staging",
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "credentials.json", "secrets.json", ".npmrc", ".pypirc", ".netrc",
}
_SAFE_ENV_TEMPLATES = {
    ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults",
}
_SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
MANIFESTS = {
    "pyproject.toml": "Python", "requirements.txt": "Python", "setup.py": "Python",
    "package.json": "JavaScript/TypeScript", "Cargo.toml": "Rust", "go.mod": "Go",
    "pom.xml": "Java", "build.gradle": "Java/Kotlin", "build.gradle.kts": "Kotlin",
    "Gemfile": "Ruby", "composer.json": "PHP", "pubspec.yaml": "Dart/Flutter",
    "CMakeLists.txt": "C/C++", "Package.swift": "Swift",
}
EXT = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript/React",
    ".ts": "TypeScript", ".tsx": "TypeScript/React", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".java": "Java", ".kt": "Kotlin", ".scala": "Scala",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
    ".fs": "F#", ".ex": "Elixir", ".exs": "Elixir",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".c": "C", ".h": "C/C++",
    ".swift": "Swift", ".dart": "Dart", ".html": "HTML", ".css": "CSS",
    ".scss": "SCSS", ".sql": "SQL", ".prisma": "Prisma",
    ".graphql": "GraphQL", ".gql": "GraphQL", ".proto": "Protobuf",
    ".csproj": "C#", ".fsproj": "F#",
    ".sh": "Shell", ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML", ".md": "Markdown",
}
MAX_BYTES = 1_000_000
MAX_FILES = int(os.environ.get("MAX_FILES", "20000"))
MAX_ARCHITECTURE_BYTES = 32 * 1024 * 1024
ARCHITECTURE_MANIFESTS = {
    "pyproject.toml", "requirements.txt", "package.json", "go.mod", "Cargo.toml",
    "tsconfig.json", "jsconfig.json",
    "composer.json", "Gemfile", "pom.xml", "build.gradle", "build.gradle.kts", "pubspec.yaml",
}
EXTRA_CONFIG_NAMES = {
    "Dockerfile", "Makefile", "makefile", "GNUmakefile",
    "justfile", "Justfile", "Taskfile.yml", "Taskfile.yaml",
    "tsconfig.json", "jsconfig.json",
}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

# Context-aware JS child_process patterns to avoid RegExp.exec() false positives.
_JS_CHILD_PROCESS_IMPORT = re.compile(r"""['"](?:node:)?child_process['"]""")
_JS_CHILD_PROCESS_QUALIFIED = re.compile(r"\bchild_process\.exec(?:Sync)?\s*\(|(?<!\.)\bexecSync\s*\(")
_JS_CHILD_PROCESS_BARE = re.compile(r"(?<!\.)\bexec\s*\(")

# Regex rules for non-Python / cross-language patterns (Python call sinks use AST below).
RULES = [
    (
        "JS_EVAL",
        re.compile(r"\beval\s*\("),
        "Potential dynamic code execution",
        "Review whether untrusted input can reach eval().",
        "high",
        "medium",
        JS_EXTENSIONS,
    ),
    (
        "JS_NEW_FUNCTION",
        re.compile(r"\bnew\s+Function\s*\("),
        "Dynamic JS Function constructor",
        "Review whether untrusted input can reach new Function(); avoid dynamic code generation.",
        "high",
        "medium",
        JS_EXTENSIONS,
    ),
    (
        "JS_TLS_REJECT_UNAUTH",
        re.compile(r"\brejectUnauthorized\s*:\s*false\b"),
        "TLS certificate verification disabled",
        "Verify whether disabling TLS verification is strictly restricted to local development.",
        "medium",
        "high",
        JS_EXTENSIONS,
    ),
    (
        "JS_INNERHTML",
        re.compile(r"\.innerHTML\s*="),
        "HTML injection review target",
        "Check whether assigned HTML includes untrusted content; prefer textContent or sanitization.",
        "medium",
        "low",
        JS_EXTENSIONS,
    ),
    (
        "JS_DANGEROUS_HTML",
        re.compile(r"\bdangerouslySetInnerHTML\b"),
        "React raw HTML injection review target",
        "Verify HTML passed to dangerouslySetInnerHTML is strictly sanitized.",
        "medium",
        "low",
        JS_EXTENSIONS,
    ),
    (
        "GO_EXEC_SHELL",
        re.compile(r'exec\.Command\s*\(\s*"(?:sh|bash|zsh)"\s*,\s*"-c"'),
        "Shell-invoking exec.Command call",
        "Avoid invoking a shell with interpolated arguments; pass executable and args directly.",
        "high",
        "medium",
        {".go"},
    ),
    (
        "SQL_BUILD",
        re.compile(
            r"(?:\bSELECT\b.{1,80}\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b.{1,60}\bSET\b|\bDELETE\s+FROM\b)"
            r".{0,120}(?:\+\s*[\w(\"'`]|%s\b.*%\s*[\w(]|\$\{|\.format\s*\()"
            r"|\bf(?:\"\"\"|'''|\"|').{0,40}"
            r"(?:\bSELECT\b.{1,80}\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b.{1,60}\bSET\b|\bDELETE\s+FROM\b)"
            r".{0,120}\{[^}]+\}",
            re.I,
        ),
        "Possible dynamically constructed SQL",
        "Verify queries use parameterized statements rather than concatenating user-controlled values.",
        "high",
        "low",
        {".py", ".js", ".ts", ".java", ".php", ".rb", ".go"},
    ),
    (
        "TODO",
        re.compile(r"\b(?:TODO|FIXME|XXX)\b", re.I),
        "TODO/FIXME marker",
        "Check whether this marker represents unfinished work relevant to the release.",
        "low",
        "high",
        None,
    ),
]

# Secret patterns — evidence is ALWAYS redacted at detection time (never echoes matched text).
SECRET_RULES = [
    (
        "SECRET_PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Embedded private key header",
        "Remove private key material from source control and rotate the key immediately.",
        "high",
        "high",
    ),
    (
        "SECRET_AWS_KEY",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Possible AWS access key ID",
        "Verify whether this is a live AWS credential; remove from source and rotate if real.",
        "high",
        "high",
    ),
    (
        "SECRET_GITHUB_TOKEN",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})\b"),
        "Possible GitHub token",
        "Revoke and rotate this token if valid, and store secrets outside the repository.",
        "high",
        "high",
    ),
    (
        "SECRET_SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "Possible Slack API token",
        "Revoke and rotate this token if valid, and load it from environment configuration.",
        "high",
        "high",
    ),
    (
        "SECRET_OPENAI_KEY",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
        "Possible OpenAI API key",
        "Revoke and rotate this key if valid, and inject it via environment variables.",
        "high",
        "high",
    ),
    (
        "SECRET_GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Possible Google API key",
        "Verify key restrictions and rotate if sensitive; avoid committing API keys to source.",
        "high",
        "high",
    ),
    (
        "SECRET_ANTHROPIC_KEY",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "Possible Anthropic API key",
        "Revoke and rotate this key if valid, and inject it via environment variables.",
        "high",
        "high",
    ),
    (
        "SECRET_STRIPE_KEY",
        re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"),
        "Possible Stripe live API key",
        "Revoke and rotate this live Stripe key immediately; never commit payment credentials.",
        "high",
        "high",
    ),
    (
        "SECRET_NPM_TOKEN",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "Possible npm access token",
        "Revoke and rotate this npm token if valid, and load it from CI secrets.",
        "high",
        "high",
    ),
    (
        "SECRET_PYPI_TOKEN",
        re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}\b"),
        "Possible PyPI API token",
        "Revoke and rotate this PyPI token if valid, and use trusted publishing or CI secrets.",
        "high",
        "high",
    ),
    (
        "SECRET_DB_URL",
        re.compile(
            r"""\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"""
            r"""(?![^/\s:@]*\$)[^/\s:@]{1,64}:"""
            r"""(?!\$\{|<|changeme\b|password\b|pass\b|secret\b|example\b|test\b|dummy\b)[^/\s@]{6,128}@"""
            r"""(?!localhost\b|127\.0\.0\.1\b|example\.com\b)[^\s"'`]+""",
            re.I,
        ),
        "Possible database URL with embedded password",
        "Remove hardcoded database credentials from source, rotate the password, and load via environment configuration.",
        "high",
        "medium",
    ),
]

_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "fixtures", "testdata"}
_EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos", "benchmark", "benchmarks"}
_DOCS_DIRS = {"doc", "docs", "documentation"}
_SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
_SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}


def classify_path_scope(rel_path: str) -> str:
    """Classify a relative POSIX path as production, test, example, or docs."""
    p = PurePosixPath(rel_path)
    dir_parts = {part.lower() for part in p.parts[:-1]}
    name = p.name.lower()
    stem = p.stem.lower()
    if (
        dir_parts & _TEST_DIRS
        or name == "conftest.py"
        or name.startswith("test_")
        or stem.endswith("_test")
        or ".test." in name
        or ".spec." in name
    ):
        return "test"
    if dir_parts & _EXAMPLE_DIRS:
        return "example"
    if dir_parts & _DOCS_DIRS:
        return "docs"
    return "production"


def _is_comment_line(line: str, suffix: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return True
    if suffix in {".py", ".rb", ".sh", ".yaml", ".yml", ".toml"}:
        return stripped.startswith("#")
    if suffix in JS_EXTENSIONS | {".java", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".swift", ".dart", ".php"}:
        return stripped.startswith(("//", "/*", "*"))
    return False


def _call_target(func: ast.AST, module_aliases: dict[str, str], symbol_aliases: dict[str, tuple[str, str]]) -> tuple[str | None, str | None]:
    """Resolve an AST call target into (module_name, func_name)."""
    if isinstance(func, ast.Name):
        if func.id in symbol_aliases:
            return symbol_aliases[func.id]
        return (None, func.id)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = module_aliases.get(func.value.id, func.value.id)
        return (base, func.attr)
    return (None, None)


def _scan_python_ast(rel: str, content: str, lines: list[str], scope: str) -> tuple[list[dict], bool]:
    """Run AST-based Python security heuristics (ignores comments, docstrings, and strings)."""
    try:
        tree = ast.parse(content, filename=rel)
    except (SyntaxError, ValueError):
        return ([], True)

    module_aliases: dict[str, str] = {}
    symbol_aliases: dict[str, tuple[str, str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".", 1)[0]
                module_aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name != "*":
                    local = alias.asname or alias.name
                    symbol_aliases[local] = (node.module, alias.name)

    found: list[dict] = []

    def add(rid: str, title: str, rec: str, severity: str, confidence: str, lineno: int) -> None:
        evidence = lines[lineno - 1].strip()[:240] if 1 <= lineno <= len(lines) else ""
        found.append({
            "id": rid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "scope": scope,
            "path": rel,
            "line": lineno,
            "evidence": evidence,
            "recommendation": rec,
            "status": "unverified heuristic",
        })

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        mod, fn = _call_target(node.func, module_aliases, symbol_aliases)
        lineno = getattr(node, "lineno", 1)

        if fn == "eval" and mod in {None, "builtins"}:
            add(
                "PY_EVAL",
                "Potential dynamic code execution",
                "Review whether untrusted input can reach eval(); prefer ast.literal_eval or a constrained parser.",
                "high",
                "medium",
                lineno,
            )
        elif fn == "exec" and mod in {None, "builtins"}:
            add(
                "PY_EXEC",
                "Potential dynamic code execution",
                "Review whether exec() is necessary and whether input is externally controlled.",
                "high",
                "medium",
                lineno,
            )
        elif mod == "subprocess" and fn in _SUBPROCESS_FUNCS:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                add(
                    "PY_SHELL",
                    "Shell-enabled subprocess call",
                    "Check for untrusted command data; prefer argument lists with shell=False.",
                    "high",
                    "medium",
                    lineno,
                )
        elif mod == "os" and fn in {"system", "popen"}:
            add(
                "PY_OS_SYSTEM",
                "Shell command execution via os.system/popen",
                "Check for untrusted command data; prefer subprocess.run with argument lists and shell=False.",
                "high",
                "medium",
                lineno,
            )
        elif (mod in {"pickle", "cPickle", "_pickle"} and fn in {"load", "loads"}) or (
            mod == "marshal" and fn in {"load", "loads"}
        ) or (mod == "shelve" and fn == "open"):
            add(
                "PY_PICKLE",
                "Unsafe Python deserialization review target",
                "Never deserialize untrusted data with pickle/marshal/shelve; use JSON or a safe schema.",
                "high",
                "medium",
                lineno,
            )
        elif mod == "yaml" and fn in {"load", "unsafe_load"}:
            if fn == "unsafe_load":
                is_safe = False
            else:
                loader_kw = next((kw.value for kw in node.keywords if kw.arg == "Loader"), None)
                loader_arg = loader_kw or (node.args[1] if len(node.args) >= 2 else None)
                loader_name = None
                if isinstance(loader_arg, ast.Name):
                    loader_name = loader_arg.id
                elif isinstance(loader_arg, ast.Attribute):
                    loader_name = loader_arg.attr
                is_safe = loader_name in _SAFE_YAML_LOADERS
            if not is_safe:
                add(
                    "PY_YAML_LOAD",
                    "Potentially unsafe YAML load",
                    "Use yaml.safe_load() or pass Loader=yaml.SafeLoader when parsing YAML.",
                    "high",
                    "medium",
                    lineno,
                )
        elif fn in {"get", "post", "put", "delete", "patch", "head", "options", "request", "Client", "AsyncClient"} and (
            mod in {"requests", "httpx"} or (isinstance(node.func, ast.Attribute) and mod in {"session", "client", "http"})
        ):
            verify_false = any(
                kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
                for kw in node.keywords
            )
            if verify_false:
                add(
                    "PY_TLS_VERIFY_FALSE",
                    "TLS certificate verification disabled",
                    "Verify whether verify=False is intentional; disabling TLS verification exposes traffic to MITM.",
                    "medium",
                    "high",
                    lineno,
                )
        elif fn == "extractall" and (
            "tarfile" in module_aliases.values()
            or any(m == "tarfile" for m, _ in symbol_aliases.values())
        ):
            add(
                "PY_TAR_EXTRACTALL",
                "Potentially unsafe tarfile.extractall call",
                "Verify archive members are validated or pass filter='data' (Python 3.12+) to prevent path traversal.",
                "medium",
                "low",
                lineno,
            )

    return (found, False)


def _find_git_root(root: Path) -> Path | None:
    """Walk upward from root to locate an enclosing .git directory/file, if any."""
    cur = root.resolve()
    for candidate in (cur, *cur.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _git_metadata(root: Path) -> dict:
    """Collect read-only git metadata (branch, short SHA, last commit date) with a short timeout."""
    git_root = _find_git_root(root)
    is_git = git_root is not None
    subdir = None
    if git_root is not None and git_root != root.resolve():
        try:
            subdir = root.resolve().relative_to(git_root).as_posix()
        except ValueError:
            subdir = None
    info = {
        "is_git_repo": is_git,
        "branch": None,
        "head_commit": None,
        "last_commit_date": None,
    }
    if subdir:
        info["subdir"] = subdir
    if not is_git:
        return info

    def _run(*args: str) -> str | None:
        try:
            proc = subprocess.run(
                ["git", *args],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=5,
            )
            out = proc.stdout.strip()
            return out if proc.returncode == 0 and out else None
        except (OSError, subprocess.SubprocessError):
            return None

    info["branch"] = _run("rev-parse", "--abbrev-ref", "HEAD")
    info["head_commit"] = _run("rev-parse", "--short", "HEAD")
    info["last_commit_date"] = _run("log", "-1", "--format=%cI")
    return info


def _read_small_text(path: Path, max_bytes: int = 8192) -> str:
    """Safely read up to max_bytes from a regular non-symlink file."""
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        with path.open("rb") as fh:
            return fh.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _detect_license_type(root: Path, contents: dict[str, str], has_license: bool) -> str | None:
    """Heuristically identify license SPDX/type from LICENSE file or manifests."""
    license_patterns = (
        ("Apache-2.0", re.compile(r"Apache License\s*,?\s*Version\s*2\.0|SPDX-License-Identifier:\s*Apache-2\.0", re.I)),
        ("AGPL-3.0", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE|SPDX-License-Identifier:\s*AGPL-3\.0", re.I)),
        ("LGPL-3.0", re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE.*Version\s*3|SPDX-License-Identifier:\s*LGPL-3\.0", re.I | re.S)),
        ("LGPL-2.1", re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE.*Version\s*2\.1|SPDX-License-Identifier:\s*LGPL-2\.1", re.I | re.S)),
        ("GPL-3.0", re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version\s*3|SPDX-License-Identifier:\s*GPL-3\.0", re.I | re.S)),
        ("GPL-2.0", re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version\s*2|SPDX-License-Identifier:\s*GPL-2\.0", re.I | re.S)),
        ("MPL-2.0", re.compile(r"Mozilla Public License\s*,?\s*Version\s*2\.0|SPDX-License-Identifier:\s*MPL-2\.0", re.I)),
        ("MIT", re.compile(r"MIT License|Permission is hereby granted,\s*free of charge|SPDX-License-Identifier:\s*MIT|\A\s*MIT\s*\Z", re.I)),
        ("ISC", re.compile(r"ISC License|Permission to use,\s*copy,\s*modify,\s*and/or distribute this software|SPDX-License-Identifier:\s*ISC", re.I)),
        ("BSD-3-Clause", re.compile(r"BSD 3-Clause|Neither the name of the|SPDX-License-Identifier:\s*BSD-3-Clause", re.I)),
        ("BSD-2-Clause", re.compile(r"BSD 2-Clause|Redistributions in binary form must reproduce|SPDX-License-Identifier:\s*BSD-2-Clause", re.I)),
        ("Unlicense", re.compile(r"The Unlicense|free and unencumbered software released into the public domain|SPDX-License-Identifier:\s*Unlicense", re.I)),
        ("BSL-1.0", re.compile(r"Boost Software License", re.I)),
    )
    for p in sorted(root.iterdir()):
        if p.is_file() and p.name.lower().startswith(("license", "licence", "copying")):
            text = _read_small_text(p, 4096)
            for label, pat in license_patterns:
                if pat.search(text):
                    return label

    # Fallback to root manifest license fields.
    pkg_raw = contents.get("package.json", "")
    if pkg_raw:
        try:
            pkg = json.loads(pkg_raw)
            lic = pkg.get("license")
            if isinstance(lic, str) and lic.strip():
                return lic.strip()[:40]
            if isinstance(lic, dict) and isinstance(lic.get("type"), str):
                return lic["type"].strip()[:40]
        except (ValueError, TypeError):
            pass

    pyproject = _parse_toml(contents.get("pyproject.toml", ""))
    if isinstance(pyproject, dict):
        lic = (pyproject.get("project") or {}).get("license")
        if isinstance(lic, str) and lic.strip():
            return lic.strip()[:40]
        if isinstance(lic, dict) and isinstance(lic.get("text"), str) and lic["text"].strip():
            return lic["text"].strip()[:40]

    cargo = _parse_toml(contents.get("Cargo.toml", ""))
    if isinstance(cargo, dict):
        lic = (cargo.get("package") or {}).get("license")
        if isinstance(lic, str) and lic.strip():
            return lic.strip()[:40]

    return "Custom / Unclassified" if has_license else None


def _extract_readme_summary(root: Path) -> str | None:
    """Extract a short plain-text summary (title + first paragraph) from a root README."""
    readme_file = None
    for p in sorted(root.iterdir()):
        if p.is_file() and p.name.lower().startswith("readme"):
            readme_file = p
            break
    if not readme_file:
        return None
    text = _read_small_text(readme_file, 8192)
    if not text:
        return None

    title = ""
    paragraph_lines: list[str] = []
    in_code = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        if not line:
            if paragraph_lines:
                break
            continue
        # Skip HTML tags, badges, horizontal rules, and image-only lines.
        if line.startswith(("<", "![", "[![", "---", "===", "***")):
            continue
        if line.startswith("#"):
            if not title:
                title = line.lstrip("#").strip()
            continue
        cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", line)
        cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
        cleaned = cleaned.lstrip("> ").strip()
        if cleaned:
            paragraph_lines.append(cleaned)
            if len(" ".join(paragraph_lines)) >= 200:
                break

    summary_parts = [p for p in (title, " ".join(paragraph_lines)) if p]
    if not summary_parts:
        return None
    combined = " — ".join(summary_parts) if len(summary_parts) == 2 else summary_parts[0]
    combined = re.sub(r"\s+", " ", combined).strip()
    return combined[:240]


_PRIORITY_SCRIPTS = {
    "dev": 0, "start": 1, "serve": 2, "run": 3, "build": 4, "test": 5,
    "lint": 6, "typecheck": 7, "check": 8, "format": 9, "install": 10,
}


def _discover_commands(root: Path, contents: dict[str, str]) -> list[dict]:
    """Discover build/run/test/CLI commands from manifests and Makefile (read-only)."""
    commands: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(source: str, name: str, command: str) -> None:
        key = (source, name)
        if key in seen or not name or not command:
            return
        seen.add(key)
        commands.append({"source": source, "name": name[:60], "command": command.strip()[:160]})

    # 1. package.json scripts (root and nested)
    for path in sorted(contents):
        if PurePosixPath(path).name != "package.json":
            continue
        try:
            pkg = json.loads(contents[path])
        except (ValueError, TypeError):
            continue
        scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
        if isinstance(scripts, dict):
            ordered = sorted(
                ((k, v) for k, v in scripts.items() if isinstance(k, str) and isinstance(v, str)),
                key=lambda item: (_PRIORITY_SCRIPTS.get(item[0].lower(), 50), item[0]),
            )
            for script_name, cmd in ordered[:15]:
                add(path, script_name, cmd)

    # 2. pyproject.toml console scripts (root and nested)
    for path in sorted(contents):
        if PurePosixPath(path).name != "pyproject.toml":
            continue
        parsed = _parse_toml(contents[path])
        if not isinstance(parsed, dict):
            continue
        project = parsed.get("project") or {}
        poetry = (parsed.get("tool") or {}).get("poetry") or {}
        for table in (project.get("scripts"), project.get("gui-scripts"), poetry.get("scripts")):
            if isinstance(table, dict):
                for script_name, target in sorted(table.items()):
                    if isinstance(script_name, str) and isinstance(target, str):
                        add(path, script_name, target)

    # 3. Root Makefile targets
    for mk_name in ("Makefile", "makefile", "GNUmakefile"):
        mk_path = root / mk_name
        if mk_path.is_file() and not mk_path.is_symlink():
            mk_text = _read_small_text(mk_path, 32768)
            targets = re.findall(r"(?m)^([A-Za-z][A-Za-z0-9_.-]*)\s*:(?!=)", mk_text)
            ordered_targets = sorted(
                set(t for t in targets if not t.startswith("_")),
                key=lambda t: (_PRIORITY_SCRIPTS.get(t.lower(), 50), t),
            )
            for target in ordered_targets[:15]:
                add(mk_name, target, f"make {target}")
            break

    # 4. justfile / Justfile recipes
    for jf_name in ("justfile", "Justfile"):
        jf_path = root / jf_name
        if jf_path.is_file() and not jf_path.is_symlink():
            jf_text = _read_small_text(jf_path, 32768)
            recipes = re.findall(r"(?m)^([A-Za-z][A-Za-z0-9_-]*)(?:\s+[^:\n]*)?:", jf_text)
            ordered_recipes = sorted(
                {r for r in recipes if r.lower() not in {"set", "alias", "export", "import"} and not r.startswith("_")},
                key=lambda t: (_PRIORITY_SCRIPTS.get(t.lower(), 50), t),
            )
            for recipe in ordered_recipes[:15]:
                add(jf_name, recipe, f"just {recipe}")
            break

    # 5. Taskfile.yml / Taskfile.yaml tasks
    for tf_name in ("Taskfile.yml", "Taskfile.yaml"):
        tf_path = root / tf_name
        if tf_path.is_file() and not tf_path.is_symlink():
            tf_text = _read_small_text(tf_path, 32768)
            in_tasks = False
            tf_targets: list[str] = []
            for line in tf_text.splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if not line[0].isspace():
                    in_tasks = line.strip().startswith("tasks:")
                    continue
                if in_tasks:
                    m = re.match(r"^\s{2}([A-Za-z][A-Za-z0-9_:-]*)\s*:", line)
                    if m:
                        tf_targets.append(m.group(1))
            for t in sorted(set(tf_targets), key=lambda x: (_PRIORITY_SCRIPTS.get(x.lower(), 50), x))[:15]:
                add(tf_name, t, f"task {t}")
            break

    # 6. docker-compose / compose services
    for dc_name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        dc_path = root / dc_name
        if dc_path.is_file() and not dc_path.is_symlink():
            dc_text = _read_small_text(dc_path, 32768)
            in_services = False
            services: list[str] = []
            for line in dc_text.splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if not line[0].isspace():
                    in_services = line.strip().startswith("services:")
                    continue
                if in_services:
                    m = re.match(r"^\s{2}([A-Za-z0-9_.-]+)\s*:", line)
                    if m:
                        services.append(m.group(1))
            for svc in sorted(set(services))[:10]:
                add(dc_name, f"service:{svc}", f"docker compose up {svc}")
            break

    # 7. GitHub Actions workflow run commands (authoritative CI build/test/lint steps)
    gh_workflows = root / ".github" / "workflows"
    if gh_workflows.is_dir():
        _ci_cmd_hint = re.compile(
            r"\b(?:pytest|unittest|npm\s+(?:run|test|ci)|pnpm|yarn|vitest|jest|go\s+(?:test|build|vet)|"
            r"cargo\s+(?:test|build|clippy|check)|mvn|gradle|ruff|mypy|eslint|flake8|black|make|just|task)\b",
            re.I,
        )
        for wf in sorted(gh_workflows.iterdir())[:10]:
            if not wf.is_file() or wf.suffix.lower() not in {".yml", ".yaml"} or wf.is_symlink():
                continue
            wf_text = _read_small_text(wf, 32768)
            rel_wf = wf.relative_to(root).as_posix()
            step_idx = 0
            for m in re.finditer(r"(?m)^\s*(?:-\s*)?run\s*:\s*([^\n|#]+)", wf_text):
                cmd_str = m.group(1).strip().strip("\"'")
                if cmd_str and not cmd_str.startswith(("|", ">")) and _ci_cmd_hint.search(cmd_str):
                    step_idx += 1
                    add(rel_wf, f"ci:{step_idx}", cmd_str)
                    if step_idx >= 5:
                        break

    return commands[:50]


_ENV_CODE_PATTERNS = (
    # Python: os.environ["KEY"], os.environ.get("KEY"), os.getenv("KEY")
    re.compile(r"""\bos\.(?:environ\.get|getenv)\s*\(\s*['"]([A-Z][A-Z0-9_]{2,})['"]"""),
    re.compile(r"""\bos\.environ\s*\[\s*['"]([A-Z][A-Z0-9_]{2,})['"]\s*\]"""),
    # JS/TS: process.env.KEY, process.env["KEY"], import.meta.env.KEY
    re.compile(r"""\b(?:process|import\.meta)\.env\.([A-Z][A-Z0-9_]{2,})\b"""),
    re.compile(r"""\b(?:process|import\.meta)\.env\s*\[\s*['"]([A-Z][A-Z0-9_]{2,})['"]\s*\]"""),
    # Go: os.Getenv("KEY"), os.LookupEnv("KEY")
    re.compile(r"""\bos\.(?:Getenv|LookupEnv)\s*\(\s*"([A-Z][A-Z0-9_]{2,})" """.strip()),
    # Rust: env::var("KEY"), option_env!("KEY")
    re.compile(r"""\b(?:env::var|option_env!)\s*\(\s*"([A-Z][A-Z0-9_]{2,})" """.strip()),
    # Java/Kotlin: System.getenv("KEY")
    re.compile(r"""\bSystem\.getenv\s*\(\s*"([A-Z][A-Z0-9_]{2,})" """.strip()),
    # Ruby / PHP: ENV["KEY"], ENV.fetch("KEY"), getenv("KEY"), $_ENV["KEY"]
    re.compile(r"""\bENV(?:\.fetch\s*\(|\s*\[)\s*['"]([A-Z][A-Z0-9_]{2,})['"]"""),
    re.compile(r"""(?:\bgetenv\s*\(|\$_ENV\s*\[)\s*['"]([A-Z][A-Z0-9_]{2,})['"]"""),
)
_ENV_IGNORE_NAMES = {"PATH", "HOME", "USER", "PWD", "TERM", "LANG", "SHELL", "TMPDIR", "NODE_ENV", "CI"}


def _discover_env_vars(root: Path, contents: dict[str, str]) -> list[dict]:
    """Discover environment variable names from safe .env templates (keys only) and source code."""
    refs: dict[str, set[str]] = {}
    in_example: set[str] = set()

    # 1. Safe .env template files at root and one level deep (KEY NAMES ONLY — never values).
    template_candidates: list[Path] = []
    try:
        for p in sorted(root.iterdir()):
            if p.is_file() and p.name.lower() in _SAFE_ENV_TEMPLATES:
                template_candidates.append(p)
            elif p.is_dir() and p.name not in SKIP_DIRS and not p.is_symlink():
                try:
                    for sub in sorted(p.iterdir()):
                        if sub.is_file() and sub.name.lower() in _SAFE_ENV_TEMPLATES:
                            template_candidates.append(sub)
                except OSError:
                    pass
    except OSError:
        pass

    for tpl in template_candidates[:20]:
        text = _read_small_text(tpl, 32768)
        rel = tpl.relative_to(root).as_posix()
        for line in text.splitlines():
            m = re.match(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,})\s*=", line)
            if m:
                key = m.group(1)
                in_example.add(key)
                refs.setdefault(key, set()).add(rel)

    # 2. Source code env var references (production files prioritized).
    for path in sorted(contents):
        suffix = PurePosixPath(path).suffix.lower()
        if suffix not in SOURCE_SUFFIXES:
            continue
        if classify_path_scope(path) != "production":
            continue
        text = contents[path]
        for pat in _ENV_CODE_PATTERNS:
            for m in pat.finditer(text):
                key = m.group(1)
                if key in _ENV_IGNORE_NAMES:
                    continue
                refs.setdefault(key, set()).add(path)

    items = [
        {
            "name": name,
            "defined_in_example": name in in_example,
            "sources": sorted(sources)[:10],
        }
        for name, sources in refs.items()
    ]
    items.sort(key=lambda item: (0 if item["defined_in_example"] else 1, -len(item["sources"]), item["name"]))
    return items[:80]


def _collect_git_hotspots(root: Path, files: list[dict]) -> tuple[list[dict], str | None]:
    """Collect recent git commit churn per analyzed file on non-shallow git repos (strictly read-only)."""
    git_root = _find_git_root(root)
    if git_root is None:
        return ([], "not a git repository")

    try:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if shallow.returncode == 0 and shallow.stdout.strip().lower() == "true":
            return ([], "skipped (shallow clone)")
    except (OSError, subprocess.SubprocessError):
        return ([], "git unavailable")

    root_resolved = root.resolve()
    rel_prefix = ""
    if root_resolved != git_root:
        try:
            rel_prefix = root_resolved.relative_to(git_root).as_posix().rstrip("/") + "/"
        except ValueError:
            rel_prefix = ""

    file_scope = {f["path"]: f["scope"] for f in files}
    try:
        proc = subprocess.run(
            ["git", "log", "-n", "200", "--since=180.days", "--name-only", "--pretty=format:", "--", "."],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return ([], "git log failed")
    except (OSError, subprocess.SubprocessError):
        return ([], "git log timed out")

    counts: Counter[str] = Counter()
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip().replace("\\", "/")
        if not line:
            continue
        if rel_prefix and line.startswith(rel_prefix):
            line = line[len(rel_prefix):]
        if line in file_scope:
            counts[line] += 1

    hotspots = [
        {"path": path, "commits": commits, "scope": file_scope[path]}
        for path, commits in counts.most_common(10)
    ]
    return (hotspots, None)


def _compute_reading_order(root: Path, architecture: dict, repo_health: dict) -> list[dict]:
    """Build a deterministic 5-6 file 'Where to Start Reading' onboarding guide."""
    order: list[dict] = []
    seen: set[str] = set()

    def add(path: str, reason: str) -> None:
        if not path or path in seen:
            return
        seen.add(path)
        order.append({"path": path, "reason": reason})

    # 1. Root README
    try:
        for p in sorted(root.iterdir()):
            if p.is_file() and p.name.lower().startswith("readme"):
                add(p.name, "Project overview and setup documentation")
                break
    except OSError:
        pass

    # 2. Primary production entry points (up to 2)
    prod_entries = [
        e for e in (architecture.get("entry_points") or [])
        if classify_path_scope(e.get("path", "")) == "production"
    ]
    prod_entries.sort(key=lambda e: (len(PurePosixPath(e["path"]).parts), e["path"]))
    for e in prod_entries[:2]:
        add(e["path"], f"Entry point ({e.get('reason', 'detected')})")

    # 3. Top production fan-in hubs (up to 2)
    prod_graph = ((architecture.get("dependency_graph") or {}).get("metrics") or {}).get("production") or {}
    for hub in (prod_graph.get("top_fan_in_modules") or []):
        if hub.get("degree", 0) >= 1 and len(order) < 5:
            add(hub["path"], f"Core production hub imported by {hub['degree']} production module(s)")

    # 4. Primary production route file or API spec
    route_counts: Counter[str] = Counter(
        r["path"] for r in (architecture.get("routes") or []) if r.get("scope") == "production"
    )
    if route_counts and len(order) < 6:
        top_route_file, r_cnt = route_counts.most_common(1)[0]
        add(top_route_file, f"Defines {r_cnt} production API route(s)")
    elif (architecture.get("api_specs") or []) and len(order) < 6:
        spec = architecture["api_specs"][0]
        add(spec["path"], f"{spec['kind']} API contract specification")

    # 5. Primary production model/schema file
    model_counts: Counter[str] = Counter(
        m["path"] for m in (architecture.get("models") or []) if m.get("scope") == "production"
    )
    if model_counts and len(order) < 6:
        top_model_file, m_cnt = model_counts.most_common(1)[0]
        add(top_model_file, f"Defines {m_cnt} production data model(s)/schema(s)")

    # Fallback: largest production file if still short
    if len(order) < 3:
        for lf in repo_health.get("largest_files") or []:
            if lf.get("scope") == "production" and len(order) < 4:
                add(lf["path"], f"Key production source file ({lf['lines']} lines)")

    return order[:6]


def _directory_overview(files: list[dict]) -> list[dict]:
    """Summarize files, lines, and dominant language per top-level directory."""
    buckets: dict[str, dict] = {}
    for f in files:
        parts = PurePosixPath(f["path"]).parts
        top = parts[0] if len(parts) > 1 else "(root)"
        bucket = buckets.setdefault(
            top,
            {"directory": top, "files": 0, "lines": 0, "production_files": 0, "test_files": 0, "_langs": Counter()},
        )
        bucket["files"] += 1
        bucket["lines"] += int(f.get("lines", 0) or 0)
        if f.get("scope") == "test":
            bucket["test_files"] += 1
        elif f.get("scope") == "production":
            bucket["production_files"] += 1
        bucket["_langs"][f.get("language", "Unknown")] += 1

    overview = []
    for bucket in buckets.values():
        primary_lang = bucket["_langs"].most_common(1)[0][0] if bucket["_langs"] else "Unknown"
        overview.append({
            "directory": bucket["directory"],
            "files": bucket["files"],
            "lines": bucket["lines"],
            "primary_language": primary_lang,
            "production_files": bucket["production_files"],
            "test_files": bucket["test_files"],
        })
    overview.sort(key=lambda item: (-item["lines"], -item["files"], item["directory"]))
    return overview[:30]


def _collect_repo_health(root: Path, files: list[dict], contents: dict[str, str]) -> dict:
    """Gather read-only repository health, CI, container, license, commands, and test-presence signals."""
    top_names = [p.name for p in root.iterdir()]
    top_lower = {name.lower() for name in top_names}
    has_readme = any(name.startswith("readme") for name in top_lower)
    has_license = any(name.startswith(("license", "licence", "copying")) for name in top_lower)
    license_type = _detect_license_type(root, contents, has_license)
    readme_summary = _extract_readme_summary(root) if has_readme else None
    commands = _discover_commands(root, contents)

    ci_configs: list[str] = []
    gh_workflows = root / ".github" / "workflows"
    if gh_workflows.is_dir():
        for wf in sorted(gh_workflows.iterdir()):
            if wf.is_file() and wf.suffix.lower() in {".yml", ".yaml"}:
                ci_configs.append(wf.relative_to(root).as_posix())
    for candidate in (".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml", ".travis.yml"):
        if (root / candidate).is_file():
            ci_configs.append(candidate)

    container_files: list[str] = []
    for f in files:
        name = PurePosixPath(f["path"]).name.lower()
        if name == "dockerfile" or name.startswith("dockerfile.") or (
            name.endswith((".yml", ".yaml")) and ("docker-compose" in name or name.startswith("compose."))
        ):
            container_files.append(f["path"])

    test_files = [f for f in files if f["scope"] == "test"]
    test_dirs = sorted({
        str(PurePosixPath(f["path"]).parent)
        for f in test_files
        if str(PurePosixPath(f["path"]).parent) != "."
    })[:20]

    frameworks: set[str] = set()
    pyprojects = [text for path, text in contents.items() if PurePosixPath(path).name == "pyproject.toml"]
    requirements_texts = [text for path, text in contents.items() if PurePosixPath(path).name == "requirements.txt"]
    package_jsons = [text for path, text in contents.items() if PurePosixPath(path).name == "package.json"]
    all_py_meta = "\n".join(pyprojects + requirements_texts)

    if (
        (root / "pytest.ini").is_file()
        or (root / "conftest.py").is_file()
        or any(PurePosixPath(f["path"]).name in {"pytest.ini", "conftest.py"} for f in files)
        or "[tool.pytest" in all_py_meta
        or re.search(r"(?i)\bpytest\b", all_py_meta)
    ):
        frameworks.add("pytest")
    if any(f["path"].endswith(".py") for f in test_files) and "pytest" not in frameworks:
        frameworks.add("unittest")
    for package_json in package_jsons:
        try:
            pkg = json.loads(package_json)
            if not isinstance(pkg, dict):
                continue
            all_deps = set((pkg.get("dependencies") or {}).keys()) | set((pkg.get("devDependencies") or {}).keys())
            test_script = str((pkg.get("scripts") or {}).get("test", "")).lower()
            for fw in ("vitest", "jest", "mocha", "playwright", "cypress"):
                if fw in all_deps or fw in test_script:
                    frameworks.add(fw)
        except (ValueError, TypeError):
            pass
    if any(f["path"].endswith("_test.go") for f in test_files):
        frameworks.add("go test")
    has_cargo = (root / "Cargo.toml").is_file() or any(PurePosixPath(p).name == "Cargo.toml" for p in contents)
    if has_cargo and (
        any(f["path"].endswith(".rs") for f in test_files)
        or any("#[cfg(test)]" in text for path, text in contents.items() if path.endswith(".rs"))
    ):
        frameworks.add("cargo test")
    if (root / "phpunit.xml").is_file() or (root / "phpunit.xml.dist").is_file():
        frameworks.add("phpunit")
    has_gemfile = (root / "Gemfile").is_file() or any(PurePosixPath(f["path"]).name == "Gemfile" for f in files)
    if has_gemfile and any("spec" in PurePosixPath(f["path"]).parts for f in test_files):
        frameworks.add("rspec")

    largest_files = [
        {"path": f["path"], "language": f["language"], "lines": f["lines"], "scope": f["scope"]}
        for f in sorted(files, key=lambda item: (-item["lines"], item["path"]))[:10]
    ]
    env_vars = _discover_env_vars(root, contents)
    git_hotspots, git_hotspots_note = _collect_git_hotspots(root, files)

    return {
        "git": _git_metadata(root),
        "has_readme": has_readme,
        "readme_summary": readme_summary,
        "has_license": has_license,
        "license_type": license_type,
        "ci_configs": sorted(set(ci_configs))[:20],
        "container_files": sorted(set(container_files))[:20],
        "commands": commands,
        "env_vars": env_vars,
        "git_hotspots": git_hotspots,
        "git_hotspots_note": git_hotspots_note,
        "tests": {
            "detected": bool(test_files or frameworks),
            "test_file_count": len(test_files),
            "test_directories": test_dirs,
            "frameworks": sorted(frameworks),
        },
        "largest_files": largest_files,
    }


def _is_sensitive_filename(name: str, suffix: str) -> bool:
    name_l = name.lower()
    if name_l in _SAFE_ENV_TEMPLATES:
        return False
    if name_l in SENSITIVE or name_l.startswith(".env."):
        return True
    if suffix in _SENSITIVE_SUFFIXES:
        return True
    if name_l.endswith(".json") and (
        "service-account" in name_l or "service_account" in name_l or "credentials" in name_l
    ):
        return True
    return False


def iter_files(root: Path, skipped: dict[str, list[str]] | None = None):
    if skipped is None:
        skipped = {
            "sensitive": [],
            "symlink": [],
            "oversized": [],
            "unreadable": [],
            "unsupported": [],
            "file_budget": [],
        }
    count = 0
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache"))
        for name in sorted(names):
            p = Path(current) / name
            rel = p.relative_to(root).as_posix()
            suffix = p.suffix.lower()
            if _is_sensitive_filename(name, suffix):
                skipped["sensitive"].append(rel)
                continue
            try:
                if p.is_symlink():
                    skipped["symlink"].append(rel)
                    continue
                if p.stat().st_size > MAX_BYTES:
                    skipped["oversized"].append(rel)
                    continue
            except OSError:
                skipped["unreadable"].append(rel)
                continue
            is_openapi_json = suffix == ".json" and ("openapi" in name.lower() or "swagger" in name.lower())
            if suffix not in EXT and name not in MANIFESTS and name not in EXTRA_CONFIG_NAMES and not is_openapi_json:
                skipped["unsupported"].append(rel)
                continue
            count += 1
            if count > MAX_FILES:
                skipped["file_budget"].append(rel)
                continue
            yield p


def analyze_repository(repo_path):
    root = Path(repo_path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    files, findings, todo_items, manifests = [], [], [], []
    contents: dict[str, str] = {}
    architecture_bytes = architecture_skipped_files = 0
    python_ast_parse_errors = 0
    langs = Counter()
    skipped: dict[str, list[str]] = {
        "sensitive": [],
        "symlink": [],
        "oversized": [],
        "unreadable": [],
        "unsupported": [],
        "file_budget": [],
    }
    for p in iter_files(root, skipped):
        rel = p.relative_to(root).as_posix()
        try:
            raw = p.read_bytes()
            content = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            skipped["unreadable"].append(rel)
            continue
        suffix = p.suffix.lower()
        name_l = p.name.lower()
        scope = classify_path_scope(rel)
        is_openapi_candidate = suffix in {".yaml", ".yml", ".json"} and (
            "openapi" in name_l or "swagger" in name_l
        )
        if (
            suffix in SOURCE_SUFFIXES
            or suffix in MODEL_EXTRA_SUFFIXES
            or suffix in {".csproj", ".fsproj"}
            or p.name in ARCHITECTURE_MANIFESTS
            or is_openapi_candidate
        ):
            if architecture_bytes + len(raw) <= MAX_ARCHITECTURE_BYTES:
                contents[rel] = content
                architecture_bytes += len(raw)
            else:
                architecture_skipped_files += 1
        lines = content.splitlines()
        lang = EXT.get(suffix, MANIFESTS.get(p.name, "Project file"))
        langs[lang] += 1
        if p.name in MANIFESTS or p.name in EXTRA_CONFIG_NAMES:
            manifests.append(rel)
        files.append({"path": rel, "language": lang, "lines": len(lines), "bytes": len(raw), "scope": scope})

        if suffix == ".py":
            py_findings, parse_err = _scan_python_ast(rel, content, lines, scope)
            findings.extend(py_findings)
            if parse_err:
                python_ast_parse_errors += 1

        has_js_child_process = suffix in JS_EXTENSIONS and bool(_JS_CHILD_PROCESS_IMPORT.search(content))

        for n, line in enumerate(lines, 1):
            for rid, pattern, title, rec, severity, confidence in SECRET_RULES:
                if pattern.search(line):
                    findings.append({
                        "id": rid,
                        "title": title,
                        "severity": severity,
                        "confidence": "low" if scope != "production" else confidence,
                        "scope": scope,
                        "path": rel,
                        "line": n,
                        "evidence": f"[REDACTED — {title} pattern matched; inspect line and rotate if live]",
                        "recommendation": rec,
                        "status": "unverified heuristic",
                    })
            if suffix in JS_EXTENSIONS and not _is_comment_line(line, suffix):
                if _JS_CHILD_PROCESS_QUALIFIED.search(line) or (
                    has_js_child_process and _JS_CHILD_PROCESS_BARE.search(line)
                ):
                    findings.append({
                        "id": "JS_CHILD_PROCESS",
                        "title": "Shell-enabled child_process call",
                        "severity": "high",
                        "confidence": "medium",
                        "scope": scope,
                        "path": rel,
                        "line": n,
                        "evidence": line.strip()[:240],
                        "recommendation": "Check for untrusted command input; prefer execFile/spawn with an argument array.",
                        "status": "unverified heuristic",
                    })
            for rid, pattern, title, rec, severity, confidence, extensions in RULES:
                if extensions is not None and suffix not in extensions:
                    continue
                if rid != "TODO" and _is_comment_line(line, suffix):
                    continue
                if pattern.search(line):
                    item = {
                        "id": rid,
                        "title": title,
                        "severity": severity,
                        "confidence": confidence,
                        "scope": scope,
                        "path": rel,
                        "line": n,
                        "evidence": line.strip()[:240],
                        "recommendation": rec,
                        "status": "unverified heuristic",
                    }
                    if rid == "TODO":
                        todo_items.append(item)
                    else:
                        findings.append(item)

    architecture = analyze_architecture(contents, skipped_files_due_to_budget=architecture_skipped_files)
    repo_health = _collect_repo_health(root, files, contents)
    # Cross-reference git churn hotspots with high fan-in production hubs (highest refactoring risk).
    prod_hub_map = {
        h["path"]: h["degree"]
        for h in ((architecture.get("dependency_graph") or {}).get("metrics") or {}).get("production", {}).get("top_fan_in_modules", [])
        if h.get("degree", 0) >= 2
    }
    hotspot_hubs = [
        {"path": h["path"], "commits": h["commits"], "production_in_degree": prod_hub_map[h["path"]]}
        for h in repo_health.get("git_hotspots", [])
        if h["path"] in prod_hub_map
    ]
    repo_health["hotspot_hubs"] = hotspot_hubs
    reading_order = _compute_reading_order(root, architecture, repo_health)
    findings.sort(
        key=lambda f: (
            {"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3),
            0 if f["scope"] == "production" else 1,
            f["path"],
            f["line"],
        )
    )
    todo_items.sort(
        key=lambda f: (
            0 if f["scope"] == "production" else 1,
            f["path"],
            f["line"],
        )
    )
    dirs = sorted({str(Path(f["path"]).parent) for f in files if str(Path(f["path"]).parent) != "."})
    dir_overview = _directory_overview(files)
    truncated = len(findings) > 2000
    todos_truncated = len(todo_items) > 500
    prod_count = sum(1 for f in findings if f["scope"] == "production")
    sev_counts = Counter(f["severity"] for f in findings)
    prod_sev_counts = Counter(f["severity"] for f in findings if f["scope"] == "production")
    return {
        "product": "github-repo-analyzer",
        "version": "1.0.0",
        "repository": str(root),
        "read_only": True,
        "summary": {
            "files_analyzed": len(files),
            "total_lines": sum(f["lines"] for f in files),
            "languages": dict(langs.most_common()),
            "manifests": sorted(manifests),
            "top_level_entries": sorted(p.name for p in root.iterdir())[:100],
            "directories": dirs[:200],
            "directory_overview": dir_overview,
            "reading_order": reading_order,
            "todo_markers": len(todo_items),
            "todos_in_report": min(len(todo_items), 500),
            "todos_truncated": todos_truncated,
            "heuristic_findings": len(findings),
            "production_findings": prod_count,
            "non_production_findings": len(findings) - prod_count,
            "findings_by_severity": {
                "high": sev_counts.get("high", 0),
                "medium": sev_counts.get("medium", 0),
                "low": sev_counts.get("low", 0),
            },
            "production_findings_by_severity": {
                "high": prod_sev_counts.get("high", 0),
                "medium": prod_sev_counts.get("medium", 0),
                "low": prod_sev_counts.get("low", 0),
            },
            "findings_in_report": min(len(findings), 2000),
            "findings_truncated": truncated,
            "python_ast_parse_errors": python_ast_parse_errors,
            "skipped_counts": {k: len(v) for k, v in skipped.items()},
            "repo_health": repo_health,
            "architecture": architecture["summary"],
            "limitations": [
                "Pattern matches and AST heuristics are not confirmed vulnerabilities or bugs.",
                "Generated, vendor, binary, oversized and sensitive files are skipped.",
                "No code is executed and no tests are run.",
                "Architecture mapping is heuristic; import and entry-point detection may be incomplete.",
                "Transitive dependency and lockfile resolution are not included.",
            ],
        },
        "files": files,
        "findings": findings[:2000],
        "todos": todo_items[:500],
        "architecture": architecture,
    }
