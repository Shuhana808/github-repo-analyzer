#!/usr/bin/env python3
"""analyze_repo.py — Analyze repo on a resolved repository path (or subdirectory).

Usage:
    python scripts/analyze_repo.py <repo-path> [--subdir <rel-path>] [--out <output-dir>]

Stdout: absolute path of the output directory (single line).
Stderr: all diagnostic / log messages.
Exit:   0 on success, non-zero on failure.

If --out is omitted, the output directory defaults outside the repository root:
    - For a repo root: <parent-of-repo>/<repo-name>-report
    - For a subdirectory inside a git repo: <parent-of-git-root>/<git-root-name>-<subdir>-report

Writes report.md, report.json, summary.json, and architecture.mmd.
This wrapper keeps stdout clean so the caller can capture the output path
with $() exactly as it captures the clone path from clone_repo.py.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.analyzer import _find_git_root, analyze_repository  # noqa: E402
from scripts.report import write_reports                         # noqa: E402


def log(msg: str) -> None:
    print(f"[analyze_repo] {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"[analyze_repo] ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def _resolve_target_dir(repo_path: Path, subdir: str | None) -> Path:
    """Resolve optional relative --subdir safely inside repo_path."""
    if not subdir or not subdir.strip():
        return repo_path
    raw_norm = subdir.strip().replace("\\", "/")
    if raw_norm.startswith("/") or Path(raw_norm).is_absolute():
        die(f"invalid --subdir (must be a relative path inside the repository): {subdir}")
    cleaned = raw_norm.strip("/")
    if not cleaned or cleaned == ".":
        return repo_path
    if ".." in PurePosixPath(cleaned).parts:
        die(f"invalid --subdir (must be a relative path inside the repository): {subdir}")
    target = (repo_path / cleaned).resolve()
    try:
        target.relative_to(repo_path)
    except ValueError:
        die(f"--subdir escapes repository root: {subdir}")
    if not target.exists():
        die(f"subdirectory does not exist in repository: {cleaned}")
    if not target.is_dir():
        die(f"subdirectory path is not a directory: {cleaned}")
    return target


def _default_out_dir(repo_path: Path, target_path: Path) -> Path:
    """Compute a default report directory guaranteed to sit outside any enclosing git repo."""
    git_root = _find_git_root(target_path)
    anchor = git_root if git_root is not None else repo_path
    if target_path != anchor:
        try:
            rel = target_path.relative_to(anchor).as_posix()
            safe_rel = re.sub(r"[^A-Za-z0-9._-]", "_", rel)[:64]
            return anchor.parent / f"{anchor.name}-{safe_rel}-report"
        except ValueError:
            pass
    return anchor.parent / f"{anchor.name}-report"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="analyze_repo",
        description="Read-only repository analysis: architecture, dependency graph, and heuristic findings.",
    )
    parser.add_argument("repository", help="Absolute path to a resolved repository")
    parser.add_argument(
        "--subdir",
        default=None,
        help="Optional relative subdirectory inside the repository to analyze (useful for monorepos)",
    )
    parser.add_argument(
        "--out",
        help="Output directory (default: outside repository root)",
    )
    args = parser.parse_args(argv[1:])

    repo_path = Path(args.repository).expanduser().resolve()
    if not repo_path.is_dir():
        die(f"repository path is not a directory: {repo_path}")

    target_path = _resolve_target_dir(repo_path, args.subdir)

    out_dir = (
        Path(args.out).expanduser().resolve()
        if args.out
        else _default_out_dir(repo_path, target_path)
    )

    log(f"analyzing: {target_path}")
    log(f"output to: {out_dir}")

    try:
        result = analyze_repository(target_path)
        md, js = write_reports(result, out_dir)
    except (OSError, ValueError) as exc:
        die(f"analysis failed: {exc}")

    summary = result.get("summary", {})
    arch = result.get("architecture", {}).get("summary", {})
    graph = result.get("architecture", {}).get("dependency_graph", {}).get("metrics", {})
    health = summary.get("repo_health", {})
    tests = health.get("tests", {})

    log(
        f"analyzed {summary.get('files_analyzed', 0)} files, "
        f"mapped {arch.get('modules', 0)} modules, "
        f"{arch.get('import_edges', 0)} imports, "
        f"{arch.get('entry_points', 0)} entry points, "
        f"{arch.get('direct_dependencies', 0)} direct dependencies, "
        f"{arch.get('routes', 0)} routes, "
        f"{arch.get('models', 0)} models"
    )
    lic_label = health.get("license_type") or ("yes" if health.get("has_license") else "no")
    log(
        f"health: tests={tests.get('test_file_count', 0)} "
        f"({', '.join(tests.get('frameworks') or ['none'])}), "
        f"ci={len(health.get('ci_configs') or [])}, "
        f"readme={'yes' if health.get('has_readme') else 'no'}, "
        f"license={lic_label}, "
        f"commands={len(health.get('commands') or [])}"
    )
    log(
        f"graph: {graph.get('cyclic_components', 0)} cycle groups, "
        f"{graph.get('isolated_modules', 0)} isolated modules"
    )
    log(
        f"findings: {summary.get('heuristic_findings', 0)} "
        f"(production: {summary.get('production_findings', 0)}, "
        f"non-production: {summary.get('non_production_findings', 0)}; "
        f"report: {md.name}, json: {js.name}, summary: summary.json)"
    )
    log("reminder: heuristic findings require manual verification")

    # Machine-readable result: single line on stdout.
    print(str(out_dir))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        die("interrupted", code=130)
