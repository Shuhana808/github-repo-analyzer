#!/usr/bin/env python3
"""architecture.py — Dependency-free, read-only repository architecture analysis.

Combines two complementary capabilities in a single module:
1. Library API (``analyze_architecture``) used by ``scripts/analyzer.py`` to build
   import graphs (AST for Python; conservative regex + tsconfig/jsconfig aliases
   for JS/TS; Go, Rust, and Java), extract manifest dependencies, detect entry
   points, routes, and data models, and compute dependency-graph metrics/insights.
2. Standalone scanner & CLI (``scan``, ``render_summary``, ``main``):
       python scripts/architecture.py <repo-path> [--json | --summary]

Stdout (CLI): JSON architecture map (default) or human-readable Markdown summary.
Stderr (CLI): diagnostic / log messages.
Exit (CLI):   0 on success, non-zero on failure.

Environment overrides (standalone scan):
    MAX_FILES          default 50000  (cap on scanned source files)
    SCAN_TIMEOUT       default 60     (seconds, total budget)
"""

from __future__ import annotations

import ast
import json
import os
import posixpath
import re
import sys
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import NoReturn

try:
    from .dependency_graph import analyze_dependency_graph
except ImportError:
    _SCRIPTS_DIR = str(Path(__file__).resolve().parent)
    if _SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, _SCRIPTS_DIR)
    from dependency_graph import analyze_dependency_graph  # type: ignore[no-redef]


# ---- Config & classification tables ----------------------------------------

MAX_FILES = int(os.environ.get("MAX_FILES", "50000"))
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "60"))

SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java",
    ".kt", ".go", ".rs", ".rb", ".php", ".cs", ".cpp", ".cc",
    ".c", ".h", ".hpp", ".swift", ".dart", ".ex", ".exs", ".scala", ".fs",
}
JS_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
MODEL_EXTRA_SUFFIXES = {".sql", ".prisma", ".graphql", ".gql", ".proto"}

# Directories never worth scanning in standalone mode.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist",
    "build", "target", ".next", ".nuxt", ".turbo", ".cache", "coverage",
    ".tox", ".idea", ".vscode", "bin", "obj",
}

# Binary / noise extensions to skip when reading file contents.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".webm",
    ".lock", ".min.js", ".min.css", ".map",
    ".pyc", ".pyo",
}

# Language classification by extension (standalone scanner).
LANG_BY_EXT = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala",
    ".rb": "Ruby", ".php": "PHP",
    ".ex": "Elixir", ".exs": "Elixir",
    ".dart": "Dart",
    ".cs": "C#", ".fs": "F#",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".sql": "SQL", ".prisma": "Prisma",
    ".graphql": "GraphQL", ".gql": "GraphQL", ".proto": "Protobuf",
    ".html": "HTML", ".css": "CSS", ".scss": "CSS", ".sass": "CSS",
    ".vue": "Vue", ".svelte": "Svelte",
}

# Dependency manifest filenames -> ecosystem.
DEP_MANIFESTS = {
    "package.json": "npm",
    "package-lock.json": "npm-lock",
    "yarn.lock": "yarn-lock",
    "pnpm-lock.yaml": "pnpm-lock",
    "requirements.txt": "pip",
    "Pipfile": "pipenv",
    "Pipfile.lock": "pipenv-lock",
    "pyproject.toml": "pyproject",
    "poetry.lock": "poetry-lock",
    "setup.py": "setuptools",
    "setup.cfg": "setuptools-cfg",
    "go.mod": "go",
    "go.sum": "go-lock",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo-lock",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler-lock",
    "composer.json": "composer",
    "composer.lock": "composer-lock",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "*.csproj": "dotnet",
    "*.fsproj": "dotnet",
    "mix.exs": "mix",
    "pubspec.yaml": "pub",
}

# Entry-point filename / glob hints checked relative to repo root (standalone scan).
ENTRY_HINTS = [
    "main.py", "__main__.py", "app.py", "wsgi.py", "asgi.py", "manage.py",
    "server.py", "run.py", "cli.py",
    "index.js", "index.mjs", "index.cjs", "server.js", "app.js", "main.js",
    "index.ts", "server.ts", "app.ts", "main.ts", "cli.ts",
    "main.go", "cmd/*/main.go",
    "main.rs", "src/main.rs", "src/lib.rs",
    "Main.java", "Application.java",
    "main.c", "main.cpp",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "Makefile", "makefile", "GNUmakefile",
    "Procfile", "justfile", "Taskfile.yml",
]

# Route-pattern regexes per framework family, gated by normalized language name.
ROUTE_PATTERNS = [
    # ---- Python ---------------------------------------------------------
    (re.compile(r"@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete|patch|head|options)\s*\(\s*[\"']([^\"']+)[\"']"),
     "Python-web", {"Python"}),
    (re.compile(r"(?:path|re_path)\s*\(\s*r?[\"']([^\"']+)[\"']"),
     "Django-url", {"Python"}),
    (re.compile(r"add_url_rule\s*\(\s*[\"']([^\"']+)[\"']"),
     "Flask", {"Python"}),

    # ---- Node / JS / TS -------------------------------------------------
    (re.compile(r"\b(?:app|router|server|fastify)\.(?:get|post|put|delete|patch|all|use|route)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]"),
     "Node-web", {"JavaScript", "TypeScript"}),

    # ---- Go -------------------------------------------------------------
    (re.compile(r"(?:HandleFunc|Handle|GET|POST|PUT|DELETE|PATCH|Any)\s*\(\s*\"([^\"]+)\""),
     "Go-web", {"Go"}),
    (re.compile(r"\.(?:GET|POST|PUT|DELETE|PATCH|Group|Route)\s*\(\s*\"([^\"]+)\""),
     "Go-router", {"Go"}),
    (re.compile(r"\b(?:web|beego)\s*\.\s*(?:Router|Include|NSNamespace|AutoRouter)\s*\(\s*\"([^\"]+)\""),
     "Beego", {"Go"}),
    (re.compile(r"//\s*@router\s+(\S+)"),
     "Beego-annotation", {"Go"}),

    # ---- Rust -----------------------------------------------------------
    (re.compile(r"#\[(?:get|post|put|delete|patch|head|options)\s*\(\s*\"([^\"]+)\"\s*\)"),
     "Rust-web", {"Rust"}),
    (re.compile(r"#\[route\s*\(\s*\"([^\"]+)\""),
     "Rust-web", {"Rust"}),
    (re.compile(r"\.route\s*\(\s*\"([^\"]+)\"\s*,\s*(?:get|post|put|delete|patch|head|options|any|on)\s*\("),
     "axum", {"Rust"}),

    # ---- JVM ------------------------------------------------------------
    (re.compile(r"@(?:RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\s*\(\s*(?:value\s*=\s*)?\"([^\"]+)\""),
     "Spring", {"Java", "Kotlin"}),
    (re.compile(r"\b(?:get|post|put|delete|patch|head|options|route)\s*\(\s*\"([^\"]+)\"\s*\)\s*\{"),
     "Ktor", {"Kotlin"}),
    (re.compile(r"\b(?:get|post|put|delete|patch)\s*\(\s*\"(/[^\"]*)\"\s*\)"),
     "Ktor", {"Kotlin"}),
    (re.compile(r"\b(?:app|javalin)\s*\.\s*(?:get|post|put|delete|patch|before|after)\s*\(\s*\"([^\"]+)\""),
     "Javalin", {"Java", "Kotlin"}),

    # ---- Ruby -----------------------------------------------------------
    (re.compile(r"^\s*(?:get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
     "Rails", {"Ruby"}),

    # ---- PHP ------------------------------------------------------------
    (re.compile(r"Route::(?:get|post|put|delete|patch|any|match)\s*\(\s*['\"]([^'\"]+)['\"]"),
     "Laravel", {"PHP"}),

    # ---- Elixir / Phoenix ----------------------------------------------
    (re.compile(r"^\s*(?:get|post|put|patch|delete|options|head)\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
     "Phoenix", {"Elixir"}),
    (re.compile(r"^\s*resources\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
     "Phoenix-resources", {"Elixir"}),
    (re.compile(r"^\s*(?:live|forward|pipe_through|scope)\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
     "Phoenix-scope", {"Elixir"}),

    # ---- Swift / Vapor -------------------------------------------------
    (re.compile(r"\b(?:app|routes)\s*\.\s*(?:get|post|put|delete|patch|on)\s*\(\s*((?:\"[^\"]*\"\s*,?\s*)+)\)"),
     "Vapor", {"Swift"}),

    # ---- .NET -----------------------------------------------------------
    (re.compile(r"\[Http(?:Get|Post|Put|Delete|Patch|Head|Options)\s*\(\s*\"([^\"]+)\"\s*\)\]"),
     "ASP.NET", {"C#", "F#"}),
    (re.compile(r"\[Route\s*\(\s*\"([^\"]+)\"\s*\)\]"),
     "ASP.NET-route", {"C#", "F#"}),

    # ---- Dart -----------------------------------------------------------
    (re.compile(r"\b(?:router|app|server)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]"),
     "Dart-web", {"Dart"}),
]

# Data-model heuristics.
MODEL_PATTERNS = [
    (re.compile(r"^class\s+(\w+)\s*\([^)]*(?:Model|Base|DeclarativeBase)[^)]*\)", re.MULTILINE), "ORM-class"),
    (re.compile(r"@Entity\b"), "JPA-entity"),
    (re.compile(r"^model\s+(\w+)\s*\{", re.MULTILINE), "Prisma-model"),
    (re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"']?(\w+)", re.IGNORECASE), "SQL-table"),
    (re.compile(r"type\s+(\w+)\s+struct\s*\{"), "Go-struct"),
    (re.compile(r"^export\s+(?:interface|type)\s+(\w+)", re.MULTILINE), "TS-type"),
    (re.compile(r"@dataclass(?:\([^)]*\))?\s*\n\s*class\s+(\w+)"), "Python-dataclass"),
    (re.compile(r"^\s*(?:type|input|interface)\s+([A-Z]\w*)\s*(?:implements\s+[^{]+)?\{", re.MULTILINE), "GraphQL-type"),
    (re.compile(r"^\s*message\s+(\w+)\s*\{", re.MULTILINE), "Proto-message"),
    (re.compile(r"^\s*service\s+(\w+)\s*\{", re.MULTILINE), "Proto-service"),
]

_SCOPE_TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "fixtures", "testdata"}
_SCOPE_EXAMPLE_DIRS = {"example", "examples", "sample", "samples", "demo", "demos", "benchmark", "benchmarks"}
_SCOPE_DOCS_DIRS = {"doc", "docs", "documentation"}
_NON_MODEL_LANGUAGES = {"", "CSS", "HTML", "Shell", "Vue", "Svelte", "Unknown"}


# ---- Data structures (standalone scanner) ----------------------------------

@dataclass
class FileInfo:
    path: str
    language: str
    size_bytes: int
    lines: int


@dataclass
class ArchitectureMap:
    repo: str
    scanned_at: str
    total_files: int
    total_bytes: int
    languages: dict[str, int]
    manifests: list[str]
    entry_points: list[str]
    routes: list[dict]
    models: list[dict]
    top_level_dirs: list[str]
    large_files: list[dict]
    warnings: list[str] = field(default_factory=list)


# ---- Shared language, scope, and config helpers ----------------------------

def _language(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    return {
        ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript/React",
        ".ts": "TypeScript", ".tsx": "TypeScript/React", ".mjs": "JavaScript",
        ".cjs": "JavaScript", ".java": "Java", ".kt": "Kotlin", ".go": "Go",
        ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".cs": "C#",
        ".cpp": "C++", ".cc": "C++", ".c": "C", ".h": "C/C++",
        ".hpp": "C++", ".swift": "Swift", ".dart": "Dart",
        ".ex": "Elixir", ".exs": "Elixir", ".scala": "Scala", ".fs": "F#",
        ".sql": "SQL", ".prisma": "Prisma",
        ".graphql": "GraphQL", ".gql": "GraphQL", ".proto": "Protobuf",
    }.get(suffix, "Unknown")


def _route_language(path: str) -> str:
    """Normalize language names to match ROUTE_PATTERNS language gates."""
    lang = _language(path)
    if lang == "JavaScript/React":
        return "JavaScript"
    if lang == "TypeScript/React":
        return "TypeScript"
    return lang


def classify_language(path: Path) -> str:
    return LANG_BY_EXT.get(path.suffix.lower(), "")


def _path_scope(rel_path: str) -> str:
    p = PurePosixPath(rel_path)
    dir_parts = {part.lower() for part in p.parts[:-1]}
    name = p.name.lower()
    stem = p.stem.lower()
    if (
        dir_parts & _SCOPE_TEST_DIRS
        or name == "conftest.py"
        or name.startswith("test_")
        or stem.endswith("_test")
        or ".test." in name
        or ".spec." in name
    ):
        return "test"
    if dir_parts & _SCOPE_EXAMPLE_DIRS:
        return "example"
    if dir_parts & _SCOPE_DOCS_DIRS:
        return "docs"
    return "production"


def _strip_jsonc(raw: str) -> str:
    """Strip // comments, /* */ comments, and trailing commas from tsconfig/jsconfig JSONC."""
    out: list[str] = []
    i = 0
    n = len(raw)
    in_str = False
    while i < n:
        ch = raw[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(raw[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif ch == "/" and i + 1 < n and raw[i + 1] == "/":
            i += 2
            while i < n and raw[i] != "\n":
                i += 1
        elif ch == "/" and i + 1 < n and raw[i + 1] == "*":
            i += 2
            while i + 1 < n and not (raw[i] == "*" and raw[i + 1] == "/"):
                i += 1
            i += 2
        else:
            out.append(ch)
            i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def _load_js_configs(contents: dict[str, str]) -> dict[str, dict]:
    """Parse tsconfig.json / jsconfig.json files into per-directory alias configs."""
    configs: dict[str, dict] = {}
    for path in sorted(contents):
        name = PurePosixPath(path).name.lower()
        if name not in {"tsconfig.json", "jsconfig.json"}:
            continue
        parent = str(PurePosixPath(path).parent)
        # Prefer tsconfig.json over jsconfig.json when both exist in the same directory.
        if parent in configs and name == "jsconfig.json":
            continue
        try:
            data = json.loads(_strip_jsonc(contents[path]))
        except (ValueError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        compiler = data.get("compilerOptions")
        if not isinstance(compiler, dict):
            continue
        base_url = compiler.get("baseUrl")
        base_url_str = base_url.strip() if isinstance(base_url, str) and base_url.strip() else None
        raw_paths = compiler.get("paths")
        path_rules: list[tuple[str, str, list[str]]] = []
        if isinstance(raw_paths, dict):
            for pattern, targets in raw_paths.items():
                if not isinstance(pattern, str) or not isinstance(targets, list):
                    continue
                valid_targets = [t for t in targets if isinstance(t, str) and t.strip()]
                if not valid_targets:
                    continue
                if "*" in pattern:
                    prefix, suffix = pattern.split("*", 1)
                else:
                    prefix, suffix = pattern, ""
                path_rules.append((prefix, suffix, valid_targets))
            # Match longest prefix first so more specific aliases win.
            path_rules.sort(key=lambda item: (-len(item[0]), item[0]))
        if base_url_str or path_rules:
            configs[parent] = {
                "config_dir": "" if parent == "." else parent,
                "base_url": base_url_str,
                "paths": path_rules,
            }
    return configs


def _nearest_config(source: str, configs: dict[str, dict]) -> dict | None:
    """Find the nearest ancestor tsconfig/jsconfig for a source file."""
    if not configs:
        return None
    cur = PurePosixPath(source).parent
    while True:
        key = str(cur)
        if key in configs:
            return configs[key]
        if key in {".", ""}:
            break
        cur = cur.parent
    return None


def _parse_toml(raw: str) -> dict | None:
    if not raw:
        return None
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(raw)
    except (ImportError, ValueError):
        try:
            import tomli  # optional compatibility parser
            return tomli.loads(raw)
        except (ImportError, ValueError):
            return None


# ---- Unified route & model extraction --------------------------------------

def _normalize_vapor_route(route: str) -> str:
    """Join multi-arg Vapor path segments into a single '/a/b' path (idempotent)."""
    parts = re.findall(r'"([^"]*)"', route)
    if not parts:
        return route
    return "/" + "/".join(p.strip("/") for p in parts if p.strip("/"))


def _route_allowed_for_file(family: str, rel_path: str, text: str) -> bool:
    """Apply framework-specific false-positive guards."""
    lower_path = rel_path.replace("\\", "/").lower()
    if family.startswith("Phoenix"):
        return (
            lower_path.endswith("router.ex")
            or "/router/" in lower_path
            or lower_path.endswith("/routes.ex")
        )
    if family == "Rails":
        return lower_path.endswith(".rb")
    if family == "Django-url":
        return (
            lower_path.endswith("urls.py")
            or "django.urls" in text
            or "from django" in text
        )
    return True


def _resolve_rust_web_family(text: str) -> tuple[str, bool]:
    """Disambiguate actix-web vs rocket macros from imports in the same file."""
    has_rocket = "use rocket" in text or "rocket::" in text
    has_actix = "actix_web" in text or "actix-web" in text
    if has_rocket and not has_actix:
        return "rocket", False
    if has_actix:
        return "actix-web", False
    return "rust-web", True


def _extract_routes_for_file(rel_path: str, text: str, lang: str) -> list[dict]:

    """Extract normalized, filtered, deduplicated HTTP routes from a single file."""
    if not text or not lang:
        return []
    applicable = [
        (pattern, family)
        for pattern, family, langs in ROUTE_PATTERNS
        if not langs or lang in langs
    ]
    if not applicable:
        return []

    rust_resolved: tuple[str, bool] | None = (
        _resolve_rust_web_family(text) if lang == "Rust" else None
    )

    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for pattern, family in applicable:
        resolved_family = family
        uncertain = False
        if family == "Rust-web" and rust_resolved is not None:
            resolved_family, uncertain = rust_resolved

        if not _route_allowed_for_file(resolved_family, rel_path, text):
            continue

        for match in pattern.finditer(text):
            route = (match.group(1) if match.groups() else match.group(0)).strip()
            if not route or len(route) > 200:
                continue
            if resolved_family == "Vapor":
                route = _normalize_vapor_route(route)
            key = (route, resolved_family)
            if key in seen:
                continue
            seen.add(key)
            entry: dict = {
                "route": route,
                "framework": resolved_family,
                "line": text.count("\n", 0, match.start()) + 1,
            }
            if uncertain:
                entry["uncertain"] = True
            hits.append(entry)
    return hits


_MODEL_LANGUAGE_GATES = {
    "GraphQL-type": {"GraphQL"},
    "Proto-message": {"Protobuf"},
    "Proto-service": {"Protobuf"},
    "Prisma-model": {"Prisma"},
}


def _extract_models_for_file(text: str, lang: str) -> list[dict]:
    """Extract deduplicated data-model/schema definitions from a single file."""
    if not text or lang in _NON_MODEL_LANGUAGES:
        return []
    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for pattern, kind in MODEL_PATTERNS:
        allowed_langs = _MODEL_LANGUAGE_GATES.get(kind)
        if allowed_langs is not None and lang not in allowed_langs:
            continue
        for match in pattern.finditer(text):
            name = (match.group(1) if match.groups() else match.group(0)).strip()
            if not name or len(name) > 100:
                continue
            key = (name, kind)
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "name": name,
                "kind": kind,
                "line": text.count("\n", 0, match.start()) + 1,
            })
    return hits


_NEXTJS_METHOD_RE = re.compile(r"\bexport\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
_PROTO_RPC_RE = re.compile(r"\brpc\s+(\w+)\s*\(")


def _extract_nextjs_file_routes(rel_path: str, text: str) -> list[dict]:
    """Detect Next.js App Router (app/**/route.*) and Pages API (pages/api/**) routes."""
    p = PurePosixPath(rel_path)
    if p.suffix.lower() not in JS_SUFFIXES:
        return []
    parts = list(p.parts)
    # Strip optional leading src/
    if parts and parts[0] == "src":
        parts = parts[1:]
    if len(parts) >= 2 and parts[0] == "app" and p.stem == "route":
        segs = [seg for seg in parts[1:-1] if not (seg.startswith("(") and seg.endswith(")"))]
        route_path = "/" + "/".join(segs)
        methods = _NEXTJS_METHOD_RE.findall(text)
        label = f"{','.join(sorted(set(methods)))} {route_path}" if methods else route_path
        return [{"route": label, "framework": "Next.js-AppRouter", "line": 1}]
    if len(parts) >= 3 and parts[0] == "pages" and parts[1] == "api":
        segs = list(parts[1:-1])
        if p.stem != "index":
            segs.append(p.stem)
        route_path = "/" + "/".join(segs)
        return [{"route": route_path, "framework": "Next.js-PagesAPI", "line": 1}]
    return []


def _extract_api_specs(contents: dict[str, str]) -> list[dict]:
    """Detect OpenAPI/Swagger, GraphQL, and Protobuf API contract files."""
    specs: list[dict] = []
    for path in sorted(contents):
        p = PurePosixPath(path)
        name_l = p.name.lower()
        suffix = p.suffix.lower()
        text = contents[path]
        if suffix in {".graphql", ".gql"}:
            specs.append({"path": path, "kind": "GraphQL"})
        elif suffix == ".proto":
            specs.append({"path": path, "kind": "Protobuf"})
        elif suffix in {".yaml", ".yml", ".json"} and (
            "openapi" in name_l
            or "swagger" in name_l
            or re.search(r'(?m)^"?(?:openapi|swagger)"?\s*:\s*"?[23]\.', text[:2000])
        ):
            specs.append({"path": path, "kind": "OpenAPI/Swagger"})
    return specs[:60]


def _extract_routes_and_models(contents: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Extract heuristic HTTP/RPC routes and data models across all in-memory contents."""
    routes: list[dict] = []
    models: list[dict] = []

    for path in sorted(contents):
        suffix = PurePosixPath(path).suffix.lower()
        if suffix not in SOURCE_SUFFIXES and suffix not in MODEL_EXTRA_SUFFIXES:
            continue
        text = contents[path]
        if not text:
            continue
        scope = _path_scope(path)
        lang = _route_language(path)

        file_route_hits = _extract_routes_for_file(path, text, lang) + _extract_nextjs_file_routes(path, text)
        if suffix == ".proto":
            for m in _PROTO_RPC_RE.finditer(text):
                file_route_hits.append({
                    "route": m.group(1),
                    "framework": "gRPC/Protobuf",
                    "line": text.count("\n", 0, m.start()) + 1,
                })

        for hit in file_route_hits:
            entry = {
                "route": hit["route"],
                "framework": hit["framework"],
                "path": path,
                "line": hit["line"],
                "scope": scope,
            }
            if hit.get("uncertain"):
                entry["uncertain"] = True
            routes.append(entry)

        for hit in _extract_models_for_file(text, lang):
            models.append({
                "name": hit["name"],
                "kind": hit["kind"],
                "path": path,
                "line": hit["line"],
                "scope": scope,
            })

    routes.sort(key=lambda r: (0 if r["scope"] == "production" else 1, r["framework"], r["path"], r["line"]))
    models.sort(key=lambda m: (0 if m["scope"] == "production" else 1, m["kind"], m["path"], m["line"]))
    return routes, models


# ---- Import parsing & resolution (analyze_architecture) --------------------

def _python_module(path: str) -> str:
    p = PurePosixPath(path)
    parts = list(p.with_suffix("").parts)
    if parts and parts[0] in {"src", "lib", "python"}:
        parts.pop(0)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _python_target(module: str, source_paths: set[str]) -> str | None:
    if not module:
        return None
    stem = module.replace(".", "/")
    for prefix in ("", "src/", "lib/", "python/"):
        for candidate in (prefix + stem + ".py", prefix + stem + "/__init__.py"):
            if candidate in source_paths:
                return candidate
    return None


def _python_local_roots(source_paths: set[str]) -> set[str]:
    roots = set()
    source_dirs = {"src", "lib", "python"}
    for path in source_paths:
        parts = PurePosixPath(path).parts
        if not parts:
            continue
        if parts[0] in source_dirs and len(parts) > 1:
            roots.add(parts[1].removesuffix(".py"))
        else:
            roots.add(parts[0].removesuffix(".py"))
    return roots


def _parse_python(path: str, content: str, source_paths: set[str]) -> list[dict]:
    imports: list[dict] = []
    try:
        tree = ast.parse(content, filename=path)
    except (SyntaxError, ValueError):
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append({"specifier": alias.name, "line": node.lineno, "kind": "import"})
        elif isinstance(node, ast.ImportFrom):
            parts = _python_module(path).split(".") if _python_module(path) else []
            # Relative imports are interpreted from the containing package.
            if node.level:
                if path.endswith("/__init__.py"):
                    package = parts
                else:
                    package = parts[:-1]
                keep = max(0, len(package) - node.level + 1)
                base = package[:keep]
            else:
                base = []
            if node.module:
                module = ".".join(base + node.module.split("."))
                imports.append({"specifier": module, "line": node.lineno, "kind": "from-import"})
                # ``from package import child`` may refer to a sibling module rather
                # than an attribute. Add that edge only when the child file exists.
                for alias in node.names:
                    child = module + "." + alias.name
                    if alias.name != "*" and _python_target(child, source_paths):
                        imports.append({
                            "specifier": child,
                            "line": node.lineno,
                            "kind": "from-import-submodule",
                        })
            else:
                for alias in node.names:
                    module = ".".join(base + alias.name.split("."))
                    imports.append({"specifier": module, "line": node.lineno, "kind": "relative-import"})
    return imports


_JS_IMPORT_PATTERNS = (
    ("import", re.compile(r"^\s*import\s+(?:[^;\n]*?\s+from\s+)?['\"]([^'\"]+)['\"]", re.M)),
    ("export-from", re.compile(r"^\s*export\s+[^;\n]*?\s+from\s+['\"]([^'\"]+)['\"]", re.M)),
    ("require", re.compile(r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")),
    ("dynamic-import", re.compile(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")),
)


def _parse_imports(path: str, content: str) -> list[dict]:
    suffix = PurePosixPath(path).suffix.lower()
    found: list[dict] = []
    if suffix == ".py":
        return _parse_python(path, content, set())
    if suffix in JS_SUFFIXES:
        seen: set[tuple[str, int, str]] = set()
        for kind, pattern in _JS_IMPORT_PATTERNS:
            for match in pattern.finditer(content):
                specifier = match.group(1)
                line = content.count("\n", 0, match.start()) + 1
                item = (specifier, line, kind)
                if item not in seen:
                    seen.add(item)
                    found.append({"specifier": specifier, "line": line, "kind": kind})
        return found
    if suffix == ".go":
        # Handles both import "x" and import (...) forms.
        for match in re.finditer(r"\bimport\s*(?:\((.*?)\)|\"([^\"]+)\")", content, re.S):
            if match.group(2) is not None:
                found.append({
                    "specifier": match.group(2),
                    "line": content.count("\n", 0, match.start(2)) + 1,
                    "kind": "go-import",
                })
            else:
                block = match.group(1) or ""
                block_start = match.start(1)
                for q in re.finditer(r'"([^\"]+)"', block):
                    found.append({
                        "specifier": q.group(1),
                        "line": content.count("\n", 0, block_start + q.start()) + 1,
                        "kind": "go-import",
                    })
        return found
    if suffix == ".rs":
        for match in re.finditer(r"^\s*(?:pub\s+)?use\s+([\w:]+)", content, re.M):
            found.append({
                "specifier": match.group(1),
                "line": content.count("\n", 0, match.start()) + 1,
                "kind": "rust-use",
            })
        for match in re.finditer(r"^\s*(?:pub\s+)?mod\s+(\w+)\s*;", content, re.M):
            found.append({
                "specifier": "self::" + match.group(1),
                "line": content.count("\n", 0, match.start()) + 1,
                "kind": "rust-mod",
            })
        return found
    if suffix == ".java":
        for match in re.finditer(r"^\s*import\s+(?:static\s+)?([\w.*]+)\s*;", content, re.M):
            found.append({
                "specifier": match.group(1),
                "line": content.count("\n", 0, match.start()) + 1,
                "kind": "java-import",
            })
    return found


_JS_CANDIDATE_SUFFIXES = (
    "", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json",
    "/index.js", "/index.jsx", "/index.ts", "/index.tsx", "/index.mjs", "/index.cjs",
)


def _match_js_candidate(base: str, paths: set[str]) -> str | None:
    norm = posixpath.normpath(base)
    if norm == ".":
        return None
    # TypeScript ESM often imports "./foo.js" when the source file is "./foo.ts" or "./foo.tsx".
    stem_variants = [norm]
    if norm.endswith((".js", ".jsx", ".mjs", ".cjs")):
        stem_variants.append(norm.rsplit(".", 1)[0])
    for variant in stem_variants:
        for suffix in _JS_CANDIDATE_SUFFIXES:
            candidate = variant + suffix
            if candidate in paths:
                return candidate
    return None


def _resolve_js(source: str, specifier: str, paths: set[str]) -> str | None:
    parent = PurePosixPath(source).parent
    base = posixpath.normpath(str(parent / specifier))
    return _match_js_candidate(base, paths)


def _resolve_js_with_config(
    source: str,
    specifier: str,
    paths: set[str],
    js_configs: dict[str, dict],
) -> tuple[str | None, bool]:
    """Resolve JS/TS relative imports, tsconfig/jsconfig path aliases, and baseUrl imports.

    Returns (target_path, is_local_reference) so external packages stay external_or_stdlib.
    """
    if specifier.startswith("."):
        target = _resolve_js(source, specifier, paths)
        return (target, True)

    cfg = _nearest_config(source, js_configs)
    if not cfg:
        return (None, False)

    config_dir = cfg["config_dir"]
    base_url = cfg["base_url"]
    base_root = posixpath.normpath(posixpath.join(config_dir, base_url)) if base_url else config_dir
    if base_root == ".":
        base_root = ""

    # 1. Explicit compilerOptions.paths alias match.
    for prefix, suffix, targets in cfg["paths"]:
        if suffix:
            matched = (
                specifier.startswith(prefix)
                and specifier.endswith(suffix)
                and len(specifier) >= len(prefix) + len(suffix)
            )
            wildcard = specifier[len(prefix):len(specifier) - len(suffix)] if matched else ""
        elif prefix and specifier.startswith(prefix):
            matched = True
            wildcard = specifier[len(prefix):]
        elif not prefix and not suffix:
            matched = True
            wildcard = specifier
        else:
            matched = specifier == prefix
            wildcard = ""
        if not matched:
            continue
        for target_tpl in targets:
            rel_target = target_tpl.replace("*", wildcard) if "*" in target_tpl else target_tpl
            candidate_base = posixpath.join(base_root, rel_target) if base_root else rel_target
            resolved = _match_js_candidate(candidate_base, paths)
            if resolved:
                return (resolved, True)
        # Only mark as unresolved local if an explicit non-wildcard-all alias matched.
        if prefix or suffix:
            return (None, True)

    # 2. compilerOptions.baseUrl resolution (only when it resolves to an actual repo file).
    if base_url and not specifier.startswith(("node:", "http:", "https:")):
        candidate_base = posixpath.join(base_root, specifier) if base_root else specifier
        resolved = _match_js_candidate(candidate_base, paths)
        if resolved:
            return (resolved, True)

    return (None, False)


def _resolve_rust(source: str, specifier: str, source_paths: set[str]) -> str | None:
    if specifier.startswith("crate::"):
        base = PurePosixPath("src")
        segments = specifier[len("crate::"):].split("::")
    elif specifier.startswith("self::"):
        source_path = PurePosixPath(source)
        parent = source_path.parent
        if source_path.name in {"main.rs", "lib.rs", "mod.rs"}:
            base = parent
        else:
            base = parent / source_path.stem
        segments = specifier[len("self::"):].split("::")
    elif specifier.startswith("super::"):
        source_path = PurePosixPath(source)
        parent = source_path.parent
        if source_path.name not in {"main.rs", "lib.rs", "mod.rs"}:
            parent = parent / source_path.stem
        base = parent.parent
        segments = specifier[len("super::"):].split("::")
    else:
        return None

    # A use path may end in a type/function rather than a module. Resolve the
    # longest existing module-file prefix instead of treating every segment as a module.
    for size in range(len(segments), 0, -1):
        candidate = str(base.joinpath(*segments[:size]))
        for path in (candidate + ".rs", candidate + "/mod.rs"):
            if path in source_paths:
                return path
    return None


def _manifest_dependencies(contents: dict[str, str]) -> list[dict]:
    deps: dict[tuple[str, str], dict] = {}

    def add(name: str, version: str | None, source: str, kind: str = "runtime") -> None:
        name = name.strip().strip('"\'')
        if not name or name.lower() in {"python", "node", "go", "rust", "java"}:
            return
        key = (name.lower(), source)
        deps[key] = {
            "name": name,
            "version": (version or "unspecified").strip().strip('"\''),
            "source": source,
            "type": kind,
        }

    for path in sorted(contents):
        name_only = PurePosixPath(path).name
        raw = contents[path]
        if not raw:
            continue

        if name_only == "pyproject.toml":
            parsed = _parse_toml(raw)
            if parsed is not None:
                project = parsed.get("project", {}) or {}
                for dep in project.get("dependencies", []) or []:
                    if isinstance(dep, str):
                        m = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", dep)
                        if m:
                            add(m.group(1), m.group(2) or "unspecified", path)
                for group, values in (project.get("optional-dependencies", {}) or {}).items():
                    for dep in values or []:
                        if isinstance(dep, str):
                            m = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", dep)
                            if m:
                                add(m.group(1), m.group(2) or "unspecified", path, f"optional:{group}")
                poetry = (parsed.get("tool", {}) or {}).get("poetry", {}) or {}
                for dep_name, spec in (poetry.get("dependencies", {}) or {}).items():
                    if dep_name.lower() != "python":
                        version = spec if isinstance(spec, str) else (spec or {}).get("version", "unspecified")
                        add(dep_name, str(version), path)
            else:
                in_deps = False
                for line in raw.splitlines():
                    if re.match(r"^\s*\[.*dependencies.*\]\s*$", line):
                        in_deps = True
                    elif re.match(r"^\s*\[", line):
                        in_deps = False
                    elif in_deps:
                        m = re.match(r"\s*[\"']?([A-Za-z0-9_.-]+)[\"']?\s*=\s*[\"']([^\"']+)", line)
                        if m:
                            add(m.group(1), m.group(2), path)

        elif name_only == "requirements.txt":
            for line in raw.splitlines():
                line = line.split("#", 1)[0].strip()
                m = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", line)
                if m and not line.startswith(("-", ".", "/")):
                    add(m.group(1), m.group(2) or "unspecified", path)

        elif name_only == "package.json":
            try:
                data = json.loads(raw)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                for field_name, kind in (
                    ("dependencies", "runtime"),
                    ("devDependencies", "development"),
                    ("peerDependencies", "peer"),
                    ("optionalDependencies", "optional"),
                ):
                    for dep_name, version in (data.get(field_name, {}) or {}).items():
                        add(dep_name, str(version), path, kind)

        elif name_only == "go.mod":
            for block in re.findall(r"(?ms)^require\s*\((.*?)^\)", raw):
                for line in block.splitlines():
                    m = re.match(r"\s*([\w./-]+)\s+(v[\w.+-]+)(?:\s*(//\s*indirect))?", line)
                    if m:
                        add(m.group(1), m.group(2), path, "indirect" if m.group(3) else "runtime")
            for m in re.finditer(r"(?m)^require\s+([\w./-]+)\s+(v[\w.+-]+)(?:\s*(//\s*indirect))?", raw):
                add(m.group(1), m.group(2), path, "indirect" if m.group(3) else "runtime")

        elif name_only == "Cargo.toml":
            parsed = _parse_toml(raw)
            if parsed is not None:
                for section, kind in (
                    ("dependencies", "runtime"),
                    ("dev-dependencies", "development"),
                    ("build-dependencies", "build"),
                ):
                    for dep_name, spec in (parsed.get(section, {}) or {}).items():
                        version = spec if isinstance(spec, str) else (spec or {}).get("version", "unspecified")
                        add(dep_name, str(version), path, kind)

        elif name_only == "composer.json":
            try:
                data = json.loads(raw)
            except (ValueError, TypeError):
                data = None
            if isinstance(data, dict):
                for field_name, kind in (("require", "runtime"), ("require-dev", "development")):
                    for dep_name, version in (data.get(field_name, {}) or {}).items():
                        if dep_name.lower() == "php" or dep_name.lower().startswith("ext-"):
                            continue
                        add(dep_name, str(version), path, kind)

        elif name_only == "Gemfile":
            for m in re.finditer(
                r"""(?m)^\s*gem\s+['"]([A-Za-z0-9_.-]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""",
                raw,
            ):
                add(m.group(1), m.group(2) or "unspecified", path, "runtime")

        elif name_only == "pom.xml":
            try:
                xml_root = ET.fromstring(raw)
            except ET.ParseError:
                xml_root = None
            if xml_root is not None:
                for dep_el in xml_root.iter():
                    if dep_el.tag.rsplit("}", 1)[-1] != "dependency":
                        continue
                    gid = aid = ver = scope_txt = ""
                    for child in dep_el:
                        tag = child.tag.rsplit("}", 1)[-1]
                        val = (child.text or "").strip()
                        if tag == "groupId":
                            gid = val
                        elif tag == "artifactId":
                            aid = val
                        elif tag == "version":
                            ver = val
                        elif tag == "scope":
                            scope_txt = val.lower()
                    if aid:
                        dep_name = f"{gid}:{aid}" if gid else aid
                        kind = "development" if scope_txt == "test" else (scope_txt or "runtime")
                        add(dep_name, ver or "unspecified", path, kind)

        elif name_only in {"build.gradle", "build.gradle.kts"}:
            for m in re.finditer(
                r"""\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|ksp|kapt)\s*\(?\s*['"]([^'":\s]+:[^'":\s]+(?::[^'"\s]+)?)['"]""",
                raw,
            ):
                cfg, coord = m.group(1), m.group(2)
                parts = coord.split(":")
                dep_name = f"{parts[0]}:{parts[1]}"
                ver = parts[2] if len(parts) >= 3 else "unspecified"
                kind = "development" if cfg.startswith("test") else "runtime"
                add(dep_name, ver, path, kind)

        elif name_only == "pubspec.yaml":
            section = None
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not line[0].isspace():
                    if stripped.startswith("dependencies:"):
                        section = "runtime"
                    elif stripped.startswith("dev_dependencies:"):
                        section = "development"
                    else:
                        section = None
                    continue
                if section and re.match(r"^  [A-Za-z0-9_.-]+\s*:", line):
                    m = re.match(r"^\s{2}([A-Za-z0-9_.-]+)\s*:\s*([^\s#]*)", line)
                    if m and m.group(1).lower() not in {"flutter", "sdk"}:
                        add(m.group(1), m.group(2) or "unspecified", path, section)

        elif PurePosixPath(path).suffix.lower() in {".csproj", ".fsproj"}:
            for m in re.finditer(
                r"""<PackageReference\s+[^>]*Include\s*=\s*['"]([^'"]+)['"][^>]*(?:Version\s*=\s*['"]([^'"]+)['"])?""",
                raw,
            ):
                add(m.group(1), m.group(2) or "unspecified", path, "runtime")

    return sorted(deps.values(), key=lambda d: (d["name"].lower(), d["source"], d["type"]))


def _resolve_manifest_relative(manifest_path: str, rel_target: str, source_paths: set[str]) -> str | None:
    parent = PurePosixPath(manifest_path).parent
    cleaned = rel_target.lstrip("./")
    candidate = cleaned if str(parent) in {".", ""} else posixpath.normpath(posixpath.join(str(parent), cleaned))
    if candidate in source_paths:
        return candidate
    return _match_js_candidate(candidate, source_paths)


def _entry_points(contents: dict[str, str], source_paths: set[str], module_names: dict[str, str]) -> list[dict]:
    entries: dict[str, dict] = {}
    known_names = {
        "__main__.py", "main.py", "app.py", "server.py", "manage.py", "wsgi.py", "asgi.py", "cli.py",
        "main.js", "index.js", "server.js", "app.js", "main.ts", "index.ts", "server.ts",
        "main.tsx", "main.go", "main.rs",
    }
    for path in sorted(source_paths):
        name = PurePosixPath(path).name.lower()
        content = contents[path]
        reason = None
        if name in known_names:
            reason = "conventional entry-point filename"
        suffix = PurePosixPath(path).suffix.lower()
        if suffix == ".py" and re.search(r"if\s+__name__\s*==\s*['\"]__main__['\"]\s*:", content):
            reason = "Python __main__ guard"
        elif (
            suffix == ".go"
            and re.search(r"(?m)^\s*package\s+main\b", content)
            and re.search(r"(?m)^\s*func\s+main\s*\(", content)
        ):
            reason = "Go package main with main function"
        elif suffix == ".rs" and re.search(r"(?m)^\s*(?:pub\s+)?fn\s+main\s*\(", content):
            reason = "Rust main function"
        elif suffix == ".java" and re.search(r"\bstatic\s+void\s+main\s*\(\s*String\s*\[\]", content):
            reason = "Java main method"
        if reason:
            entries[path] = {"path": path, "language": _language(path), "reason": reason}

    # Python console scripts declared in root or nested pyproject.toml files.
    for path in sorted(contents):
        if PurePosixPath(path).name != "pyproject.toml":
            continue
        parsed_pyproject = _parse_toml(contents[path])
        if not isinstance(parsed_pyproject, dict):
            continue
        parent = str(PurePosixPath(path).parent)
        prefix = "" if parent in {".", ""} else parent + "/"
        project = parsed_pyproject.get("project", {}) or {}
        poetry = (parsed_pyproject.get("tool", {}) or {}).get("poetry", {}) or {}
        script_tables = [project.get("scripts", {}), project.get("gui-scripts", {}), poetry.get("scripts", {})]
        for table in script_tables:
            for script_name, target in (table or {}).items():
                if not isinstance(target, str):
                    continue
                module = target.split(":", 1)[0].strip()
                resolved = None
                if prefix:
                    scoped_paths = {p[len(prefix):] for p in source_paths if p.startswith(prefix)}
                    sub_resolved = _python_target(module, scoped_paths)
                    if sub_resolved:
                        resolved = prefix + sub_resolved
                if not resolved:
                    resolved = _python_target(module, source_paths)
                if resolved:
                    entries[resolved] = {
                        "path": resolved,
                        "language": _language(resolved),
                        "reason": f"{path} script '{script_name}'",
                    }

    # package.json metadata and scripts (root and nested monorepo packages).
    for path in sorted(contents):
        if PurePosixPath(path).name != "package.json":
            continue
        try:
            package = json.loads(contents[path])
        except (ValueError, TypeError):
            package = {}
        if not isinstance(package, dict):
            continue
        for field_name in ("main", "module", "browser"):
            candidate = package.get(field_name)
            if isinstance(candidate, str):
                resolved = _resolve_manifest_relative(path, candidate, source_paths)
                if resolved:
                    entries[resolved] = {
                        "path": resolved,
                        "language": _language(resolved),
                        "reason": f"{path} {field_name} field",
                    }
        for script_name, script in (package.get("scripts", {}) or {}).items():
            if isinstance(script, str):
                match = re.search(
                    r"(?:node|tsx?|ts-node|vite|next|nuxt)\s+([\w./-]+\.(?:js|jsx|ts|tsx|mjs|cjs))",
                    script,
                )
                if match:
                    resolved = _resolve_manifest_relative(path, match.group(1), source_paths)
                    if resolved:
                        entries[resolved] = {
                            "path": resolved,
                            "language": _language(resolved),
                            "reason": f"{path} script '{script_name}'",
                        }
    return sorted(entries.values(), key=lambda e: e["path"])


def _load_go_modules(contents: dict[str, str]) -> dict[str, str]:
    """Map directory path ('.' for root) to its Go module path from go.mod."""
    modules: dict[str, str] = {}
    for path in sorted(contents):
        if PurePosixPath(path).name != "go.mod":
            continue
        m = re.search(r"(?m)^module\s+([^\s]+)", contents[path])
        if m:
            modules[str(PurePosixPath(path).parent)] = m.group(1).strip()
    return modules


def _nearest_go_module(source: str, go_modules: dict[str, str]) -> tuple[str, str] | None:
    if not go_modules:
        return None
    cur = PurePosixPath(source).parent
    while True:
        key = str(cur)
        if key in go_modules:
            return ("" if key == "." else key, go_modules[key])
        if key in {".", ""}:
            break
        cur = cur.parent
    return None


# ---- Main library API (used by scripts/analyzer.py) ------------------------

def analyze_architecture(contents: dict[str, str], skipped_files_due_to_budget: int = 0) -> dict:
    """Build a static module/import/dependency overview from relative paths to text."""
    source_paths = {p for p in contents if PurePosixPath(p).suffix.lower() in SOURCE_SUFFIXES}
    source_paths = {p for p in source_paths if not PurePosixPath(p).name.startswith(".")}
    module_names = {
        p: _python_module(p) if p.endswith(".py") else str(PurePosixPath(p).with_suffix(""))
        for p in source_paths
    }

    go_modules = _load_go_modules(contents)
    js_configs = _load_js_configs(contents)

    go_dirs: dict[str, list[str]] = defaultdict(list)
    java_packages: dict[str, list[str]] = defaultdict(list)
    for path in source_paths:
        directory = str(PurePosixPath(path).parent)
        if path.endswith(".go"):
            go_dirs[directory].append(path)
        if path.endswith(".java"):
            package_match = re.search(r"(?m)^\s*package\s+([\w.]+)\s*;", contents[path])
            if package_match:
                java_packages[package_match.group(1)].append(path)

    imports: list[dict] = []
    python_local_roots = _python_local_roots({p for p in source_paths if p.endswith(".py")})
    for source in sorted(source_paths):
        suffix = PurePosixPath(source).suffix.lower()
        candidates = (
            _parse_python(source, contents[source], source_paths)
            if suffix == ".py"
            else _parse_imports(source, contents[source])
        )
        for candidate in candidates:
            spec = candidate["specifier"]
            target = None
            classification = "external_or_stdlib"
            if suffix == ".py":
                module = spec.lstrip(".") if spec.startswith(".") else spec
                target = _python_target(module, source_paths)
                if target:
                    classification = "internal"
                elif spec.startswith(".") or module.split(".", 1)[0] in python_local_roots:
                    classification = "unresolved_local"
            elif suffix in JS_SUFFIXES:
                target, is_local = _resolve_js_with_config(source, spec, source_paths, js_configs)
                if target:
                    classification = "internal"
                elif is_local:
                    classification = "unresolved_local"
            elif suffix == ".go":
                go_ctx = _nearest_go_module(source, go_modules)
                if go_ctx:
                    mod_dir, go_module = go_ctx
                    if spec == go_module or spec.startswith(go_module + "/"):
                        rel_sub = spec[len(go_module):].lstrip("/")
                        rel_dir = (
                            posixpath.join(mod_dir, rel_sub)
                            if (mod_dir and rel_sub)
                            else (rel_sub or mod_dir or ".")
                        )
                        options = sorted(go_dirs.get(rel_dir, []))
                        if options:
                            target = options[0]
                            classification = "internal"
                        else:
                            classification = "unresolved_local"
            elif suffix == ".rs":
                target = _resolve_rust(source, spec, source_paths)
                if target:
                    classification = "internal"
                elif spec.startswith(("crate::", "self::", "super::")):
                    classification = "unresolved_local"
            elif suffix == ".java":
                if spec.endswith(".*"):
                    package = spec[:-2]
                    options = sorted(java_packages.get(package, []))
                else:
                    package, _, class_name = spec.rpartition(".")
                    options = [
                        p for p in java_packages.get(package, [])
                        if PurePosixPath(p).stem == class_name
                    ]
                if options:
                    target = options[0]
                    classification = "internal"
                elif spec.startswith(("java.", "javax.", "jakarta.")):
                    classification = "external_or_stdlib"

            imports.append({
                "source": source,
                "specifier": spec,
                "line": candidate["line"],
                "kind": candidate["kind"],
                "classification": classification,
                "target": target,
            })

    outgoing: Counter[str] = Counter()
    incoming: Counter[str] = Counter()
    for edge in imports:
        if edge["classification"] == "internal" and edge["target"]:
            outgoing[edge["source"]] += 1
            incoming[edge["target"]] += 1

    entries = _entry_points(contents, source_paths, module_names)
    entry_paths = {e["path"] for e in entries}
    modules = [
        {
            "path": path,
            "language": _language(path),
            "module_name": module_names[path],
            "internal_imports": outgoing[path],
            "imported_by": incoming[path],
            "is_entry_point": path in entry_paths,
        }
        for path in sorted(source_paths)
    ]

    deps = _manifest_dependencies(contents)
    routes, models = _extract_routes_and_models(contents)
    api_specs = _extract_api_specs(contents)
    graph = analyze_dependency_graph(modules, imports, entries)
    modules = graph["modules"]
    counts = Counter(edge["classification"] for edge in imports)
    return {
        "summary": {
            "source_files": len(source_paths),
            "modules": len(modules),
            "entry_points": len(entries),
            "import_edges": len(imports),
            "internal_imports": counts.get("internal", 0),
            "external_or_stdlib_imports": counts.get("external_or_stdlib", 0),
            "unresolved_local_imports": counts.get("unresolved_local", 0),
            "direct_dependencies": len(deps),
            "routes": len(routes),
            "models": len(models),
            "api_specs": len(api_specs),
            "js_alias_configs": len(js_configs),
            "skipped_files_due_to_budget": skipped_files_due_to_budget,
        },
        "entry_points": entries,
        "modules": modules,
        "imports": sorted(imports, key=lambda e: (e["source"], e["line"], e["specifier"])),
        "dependencies": deps,
        "routes": routes[:500],
        "models": models[:500],
        "api_specs": api_specs,
        "dependency_graph": {
            "metrics": graph["metrics"],
            "insights": graph["insights"],
            "unique_edges": graph["unique_edges"],
        },
        "limitations": [
            "Python imports use AST parsing; other language imports are detected with conservative text patterns (tsconfig/jsconfig baseUrl and paths aliases are resolved heuristically).",
            "External and standard-library imports are grouped together unless a local target is resolved.",
            "Dependency versions are read from root and nested manifests; transitive dependencies and lockfile resolution are not included.",
            "Dynamic imports, generated code, reflection, conditional compilation, and complex workspace overrides may be missed.",
            "Entry-point, route, and data-model detection is heuristic and may include conventional filenames or patterns that are not active at runtime.",
            "A bounded content budget is used; some source or manifest files may be omitted in very large repositories.",
        ],
    }


# ---- Standalone scanner helpers & CLI --------------------------------------

def log(msg: str) -> None:
    print(f"[architecture] {msg}", file=sys.stderr, flush=True)


def die(msg: str) -> NoReturn:
    print(f"[architecture] ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def should_skip(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    if any(part in SKIP_DIRS for part in rel.parts):
        return True
    if path.suffix.lower() in SKIP_EXTS:
        return True
    if path.name.endswith((".min.js", ".min.css")):
        return True
    return False


def read_text(path: Path, max_bytes: int = 2_000_000) -> str:
    """Best-effort UTF-8 read with a size cap. Returns '' on failure."""
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def walk_repo(root: Path, deadline: float) -> tuple[list[FileInfo], list[str]]:
    """Walk the repo once, returning FileInfo list and warnings."""
    files: list[FileInfo] = []
    warnings: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        if time.monotonic() > deadline:
            warnings.append(f"scan timeout reached at {dirpath}; partial results")
            break
        # Prune in-place so os.walk doesn't descend.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if should_skip(p, root):
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            lang = classify_language(p)
            if not lang:
                continue
            lines = 0
            text = read_text(p)
            if text:
                lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
            files.append(FileInfo(
                path=p.relative_to(root).as_posix(),
                language=lang,
                size_bytes=st.st_size,
                lines=lines,
            ))
            if len(files) >= MAX_FILES:
                warnings.append(f"file cap reached at MAX_FILES={MAX_FILES}; partial results")
                return files, warnings
    return files, warnings


def find_manifests(root: Path) -> list[str]:
    """Locate dependency manifests at repo root and one level deep."""
    found: list[str] = []
    names = set(DEP_MANIFESTS) - {"*.csproj", "*.fsproj"}
    for p in root.iterdir() if root.is_dir() else []:
        if p.is_file() and p.name in names:
            found.append(p.name)
    for p in root.glob("*/*"):
        if p.is_file() and (p.name in names or p.suffix in (".csproj", ".fsproj")):
            found.append(p.relative_to(root).as_posix())
    return sorted(set(found))


def find_entry_points(root: Path) -> list[str]:
    hits: list[str] = []
    for hint in ENTRY_HINTS:
        if "*" in hint:
            for m in root.glob(hint):
                if m.is_file():
                    hits.append(m.relative_to(root).as_posix())
        else:
            p = root / hint
            if p.is_file():
                hits.append(hint)
    seen: set[str] = set()
    unique: list[str] = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique[:50]


def extract_routes(files: list[FileInfo], root: Path, deadline: float) -> list[dict]:
    """Extract normalized HTTP routes for standalone scans, gated by language."""
    routes: list[dict] = []
    for fi in files:
        if time.monotonic() > deadline:
            break
        if not fi.language:
            continue
        text = read_text(root / fi.path)
        if not text:
            continue
        for hit in _extract_routes_for_file(fi.path, text, fi.language):
            entry: dict = {
                "route": hit["route"],
                "file": fi.path,
                "line": hit["line"],
                "framework": hit["framework"],
            }
            if hit.get("uncertain"):
                entry["uncertain"] = True
            routes.append(entry)
    return routes


def post_process_routes(routes: list[dict], files: list[FileInfo], root: Path) -> list[dict]:
    """Resolve family ambiguity, normalize framework shapes, deduplicate, and sort (idempotent)."""
    text_cache: dict[str, str] = {}

    def text_of(path: str) -> str:
        if path not in text_cache:
            text_cache[path] = read_text(root / path)
        return text_cache[path]

    normalized: list[dict] = []
    for r in routes:
        family = r["framework"]
        route = r["route"]
        file_path = r["file"]

        if family == "Vapor":
            r = {**r, "route": _normalize_vapor_route(route)}
        elif family in ("Rust-web", "actix-web", "rocket"):
            text = text_of(file_path)
            resolved_family, uncertain = _resolve_rust_web_family(text)
            if uncertain and family in ("actix-web", "rocket"):
                r = {**r, "framework": "actix-web", "uncertain": True}
            else:
                r = {**r, "framework": resolved_family}
                if uncertain:
                    r["uncertain"] = True
        elif not _route_allowed_for_file(family, file_path, text_of(file_path)):
            continue

        normalized.append(r)

    seen: set[tuple[str, str, str]] = set()
    result: list[dict] = []
    for r in normalized:
        key = (r["file"], r["route"], r["framework"])
        if key in seen:
            continue
        seen.add(key)
        result.append(r)

    result.sort(key=lambda r: (r["framework"], r["file"], r["line"]))
    return result


def extract_models(files: list[FileInfo], root: Path, deadline: float) -> list[dict]:
    """Extract ORM model / type / SQL table definitions for standalone scans."""
    models: list[dict] = []
    for fi in files:
        if time.monotonic() > deadline:
            break
        if not fi.language or fi.language in _NON_MODEL_LANGUAGES:
            continue
        text = read_text(root / fi.path)
        if not text:
            continue
        for hit in _extract_models_for_file(text, fi.language):
            models.append({
                "name": hit["name"],
                "kind": hit["kind"],
                "file": fi.path,
                "line": hit["line"],
            })
    return models


def top_level_dirs(root: Path) -> list[str]:
    if not root.is_dir():
        return []
    return sorted(
        p.name for p in root.iterdir()
        if p.is_dir() and p.name not in SKIP_DIRS and not p.name.startswith(".")
    )


def find_large_files(files: list[FileInfo], threshold_lines: int = 500, limit: int = 20) -> list[dict]:
    big = [f for f in files if f.lines >= threshold_lines]
    big.sort(key=lambda f: f.lines, reverse=True)
    return [
        {"path": f.path, "lines": f.lines, "language": f.language}
        for f in big[:limit]
    ]


def scan(root: Path) -> ArchitectureMap:
    started = time.monotonic()
    deadline = started + SCAN_TIMEOUT
    log(f"scanning {root} (timeout={SCAN_TIMEOUT}s, max_files={MAX_FILES})")

    files, warnings = walk_repo(root, deadline)
    log(f"walked {len(files)} source files")

    lang_counts = Counter(f.language for f in files)
    total_bytes = sum(f.size_bytes for f in files)

    manifests = find_manifests(root)
    entries = find_entry_points(root)
    routes = extract_routes(files, root, deadline)
    routes = post_process_routes(routes, files, root)
    models = extract_models(files, root, deadline)
    large = find_large_files(files)
    dirs = top_level_dirs(root)

    log(
        f"found {len(entries)} entry points, {len(routes)} routes, "
        f"{len(models)} models, {len(large)} large files"
    )

    return ArchitectureMap(
        repo=str(root),
        scanned_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        total_files=len(files),
        total_bytes=total_bytes,
        languages=dict(lang_counts.most_common()),
        manifests=manifests,
        entry_points=entries,
        routes=routes,
        models=models,
        top_level_dirs=dirs,
        large_files=large,
        warnings=warnings,
    )


def render_summary(am: ArchitectureMap) -> str:
    """Human-readable Markdown summary for standalone CLI runs."""
    out: list[str] = []
    out.append(f"# Architecture: {am.repo}")
    out.append(f"Files: {am.total_files}  |  Size: {am.total_bytes // 1024} KB")
    out.append("")
    out.append("## Languages")
    for lang, count in am.languages.items():
        out.append(f"- {lang}: {count}")
    out.append("")
    out.append("## Dependency manifests")
    out.extend(f"- {m}" for m in am.manifests) if am.manifests else out.append("- (none found)")
    out.append("")
    out.append("## Entry points")
    out.extend(f"- {e}" for e in am.entry_points) if am.entry_points else out.append("- (none detected)")
    out.append("")
    out.append(f"## Routes ({len(am.routes)})")
    for r in am.routes[:40]:
        out.append(f"- `{r['framework']}` {r['route']}  — {r['file']}:{r['line']}")
    if len(am.routes) > 40:
        out.append(f"- … {len(am.routes) - 40} more")
    out.append("")
    out.append(f"## Models ({len(am.models)})")
    for m in am.models[:40]:
        out.append(f"- `{m['kind']}` {m['name']}  — {m['file']}:{m['line']}")
    if len(am.models) > 40:
        out.append(f"- … {len(am.models) - 40} more")
    out.append("")
    out.append("## Large files (>= 500 lines)")
    for f in am.large_files:
        out.append(f"- {f['path']} ({f['lines']} lines, {f['language']})")
    if not am.large_files:
        out.append("- (none)")
    if am.warnings:
        out.append("")
        out.append("## Warnings")
        out.extend(f"- {w}" for w in am.warnings)
    return "\n".join(out)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}

    if len(args) != 1:
        die(f"usage: {Path(argv[0]).name} <repo-path> [--json | --summary]")
    if "--json" in flags and "--summary" in flags:
        die("--json and --summary are mutually exclusive")

    root = Path(args[0]).expanduser()
    if not root.exists():
        die(f"path does not exist: {root}")
    if not root.is_dir():
        die(f"not a directory: {root}")

    am = scan(root.resolve())

    if "--summary" in flags:
        print(render_summary(am))
    else:
        print(json.dumps(asdict(am), indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        die("interrupted")
