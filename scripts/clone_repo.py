#!/usr/bin/env python3
"""clone_repo.py — Normalize a local path or Git URL into a working repo directory.

Usage:
    python clone_repo.py <local-path | github-url | owner/repo[@ref]> [--ref <ref>] [--subdir <path>]

Supported inputs:
    - Local directory path (no network)
    - https://github.com/owner/repo[.git]
    - https://github.com/owner/repo/tree/<ref>[/<subdir>]
    - https://github.com/owner/repo/blob/<ref>/<path>
    - https://github.com/owner/repo/commit/<sha>
    - https://gitlab.com/group/repo[/-/tree/<ref>[/<subdir>]]
    - git@github.com:owner/repo[.git]
    - owner/repo or owner/repo@<ref>

Stdout: absolute path of the resolved repository (or target subdirectory) (single line).
Stderr: all diagnostic / log messages.
Exit:   0 on success, non-zero on failure.

Environment overrides:
    WORK_ROOT     default /tmp/repo-analyzer
    MAX_SIZE_MB   default 500
    GIT_TIMEOUT   default 120   (seconds, per git operation)
    GITHUB_TOKEN  optional; injected for private HTTPS clones
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

# ---- Config -----------------------------------------------------------------
WORK_ROOT = Path(os.environ.get("WORK_ROOT", "/tmp/repo-analyzer"))
MAX_SIZE_MB = int(os.environ.get("MAX_SIZE_MB", "500"))
GIT_TIMEOUT = int(os.environ.get("GIT_TIMEOUT", "120"))
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()


# ---- Logging ----------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[clone_repo] {msg}", file=sys.stderr, flush=True)


def die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"[clone_repo] ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


# ---- Input normalization ----------------------------------------------------
_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHORTHAND_REF_RE = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s]+)$")
_GITHUB_HOSTS = {"github.com", "www.github.com"}
_GITHUB_NON_CODE_SECTIONS = {
    "issues", "pulls", "pull", "actions", "projects", "wiki", "security",
    "pulse", "graphs", "settings", "releases", "tags", "branches", "commits",
    "compare", "discussions", "network", "stargazers", "watchers", "forks",
}


def _clean_subdir(raw: str | None) -> str | None:
    """Normalize a relative POSIX subdirectory path, or return None if empty."""
    if not raw:
        return None
    cleaned = raw.strip().replace("\\", "/").strip("/")
    if not cleaned or cleaned == ".":
        return None
    return cleaned


def parse_repo_input(raw: str) -> tuple[str, str | None, str | None]:
    """Parse raw input into (clone_url, ref, subdir).

    Returns ('', None, None) if the input should be treated as a local path.
    """
    raw = raw.strip()
    if not raw:
        return ("", None, None)

    if raw.startswith("git@github.com:"):
        return (f"https://github.com/{raw[len('git@github.com:'):]}", None, None)

    if raw.startswith("file://"):
        return (raw, None, None)

    if raw.startswith(("http://", "https://")):
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        path = unquote(parts.path or "")
        segments = [seg for seg in path.split("/") if seg]

        # GitHub browser URLs: /owner/repo[/tree|blob|commit/<ref>[/<subdir>]]
        if host in _GITHUB_HOSTS and len(segments) >= 2:
            owner, repo = segments[0], segments[1]
            rest = segments[2:]
            scheme = parts.scheme or "https"
            canonical_host = "github.com"

            if not rest:
                # Preserve exact .git vs non-.git form for plain repo URLs.
                return (f"{scheme}://{canonical_host}/{owner}/{repo}", None, None)

            repo_base = repo.removesuffix(".git")
            base_url = f"{scheme}://{canonical_host}/{owner}/{repo_base}.git"
            section = rest[0]

            if section == "tree" and len(rest) >= 2:
                ref = rest[1]
                subdir = _clean_subdir("/".join(rest[2:]))
                return (base_url, ref, subdir)

            if section == "blob" and len(rest) >= 3:
                ref = rest[1]
                file_rel = PurePosixPath(*rest[2:])
                parent = str(file_rel.parent)
                subdir = None if parent in {".", ""} else _clean_subdir(parent)
                return (base_url, ref, subdir)

            if section == "commit" and len(rest) >= 2:
                return (base_url, rest[1], None)

            if section in _GITHUB_NON_CODE_SECTIONS:
                return (base_url, None, None)

        # GitLab browser URLs: /group[/sub]/repo/-/tree|blob/<ref>[/<subdir>]
        if "/-/" in path:
            before, after = path.split("/-/", 1)
            after_parts = [seg for seg in after.split("/") if seg]
            repo_path = before.rstrip("/")
            if repo_path and after_parts:
                base_url = f"{parts.scheme}://{parts.netloc}{repo_path}"
                if not base_url.endswith(".git"):
                    base_url += ".git"
                section = after_parts[0]
                if section == "tree" and len(after_parts) >= 2:
                    return (base_url, after_parts[1], _clean_subdir("/".join(after_parts[2:])))
                if section == "blob" and len(after_parts) >= 3:
                    file_rel = PurePosixPath(*after_parts[2:])
                    parent = str(file_rel.parent)
                    subdir = None if parent in {".", ""} else _clean_subdir(parent)
                    return (base_url, after_parts[1], subdir)
                if section == "commit" and len(after_parts) >= 2:
                    return (base_url, after_parts[1], None)

        # Generic http(s) URL: strip query & fragment only.
        clean_path = parts.path.rstrip("/") if parts.path != "/" else ""
        return (f"{parts.scheme}://{parts.netloc}{clean_path}", None, None)

    # owner/repo@ref shorthand — only when not a real local path.
    m_ref = _SHORTHAND_REF_RE.match(raw)
    if m_ref and not Path(raw).exists():
        owner_repo, ref = m_ref.group(1), m_ref.group(2)
        return (f"https://github.com/{owner_repo.removesuffix('.git')}.git", ref, None)

    # owner/repo shorthand — only when the token doesn't correspond to a real path.
    if _SHORTHAND_RE.match(raw) and not Path(raw).exists():
        return (f"https://github.com/{raw.removesuffix('.git')}.git", None, None)

    return ("", None, None)


def normalize_url(raw: str) -> str:
    """Return an HTTPS clone URL, or '' if the input is a local path."""
    url, _ref, _subdir = parse_repo_input(raw)
    return url


def derive_dest_name(url: str, ref: str | None = None) -> str:
    """Turn a clone URL (and optional ref) into a filesystem-safe directory name."""
    s = re.sub(r"^https?://", "", url)
    s = re.sub(r"^git@", "", s)
    s = s.replace(":", "/")
    s = s.removesuffix(".git")
    s = re.sub(r"[^A-Za-z0-9._-]", "_", s)
    if ref:
        safe_ref = re.sub(r"[^A-Za-z0-9._-]", "_", ref.strip())[:64]
        if safe_ref:
            s = f"{s}__ref_{safe_ref}"
    return s


def redact(text: str) -> str:
    """Strip any embedded credentials or GITHUB_TOKEN before logging."""
    cleaned = re.sub(r"://[^/@\s]+@", "://***@", text)
    if GITHUB_TOKEN:
        cleaned = cleaned.replace(GITHUB_TOKEN, "***")
    return cleaned


def resolve_subdir(repo_root: Path, subdir: str | None) -> Path:
    """Resolve and validate a relative subdirectory strictly inside repo_root."""
    if not subdir or not subdir.strip():
        return repo_root
    raw_norm = subdir.strip().replace("\\", "/")
    if raw_norm.startswith("/") or Path(raw_norm).is_absolute():
        die(f"invalid --subdir (must be a relative path inside the repository): {subdir}")
    cleaned = _clean_subdir(raw_norm)
    if not cleaned:
        return repo_root
    if ".." in PurePosixPath(cleaned).parts:
        die(f"invalid --subdir (must be a relative path inside the repository): {subdir}")
    target = (repo_root / cleaned).resolve()
    root_resolved = repo_root.resolve()
    try:
        target.relative_to(root_resolved)
    except ValueError:
        die(f"--subdir escapes repository root: {subdir}")
    if not target.exists():
        die(f"subdirectory does not exist in repository: {cleaned}")
    if not target.is_dir():
        die(f"subdirectory path is not a directory: {cleaned}")
    return target


# ---- Size guard -------------------------------------------------------------
def dir_size_mb(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total // (1024 * 1024)


# ---- Git helpers ------------------------------------------------------------
def run_git(
    args: list[str],
    cwd: Path | None = None,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run git with a timeout, non-zero exit check, and no interactive prompt."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        capture_output=capture,
        text=True,
        timeout=GIT_TIMEOUT,
        check=check,
    )


def clone_url(url: str) -> str:
    """Inject GITHUB_TOKEN into HTTPS GitHub URLs when present."""
    if GITHUB_TOKEN and url.startswith("https://github.com/"):
        return url.replace(
            "https://github.com/",
            f"https://x-access-token:{GITHUB_TOKEN}@github.com/",
            1,
        )
    return url


def _clone_fresh(auth_url: str, url: str, dest: Path, ref: str | None) -> None:
    """Clone url into dest, optionally checking out ref (branch, tag, or commit SHA)."""
    if ref:
        log(f"cloning ref '{ref}' (shallow, depth=1)…")
        try:
            run_git(["clone", "--depth", "1", "--single-branch", "--branch", ref, auth_url, str(dest)])
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            log(f"shallow branch/tag clone failed for ref '{ref}'; retrying full clone + checkout…")
            shutil.rmtree(dest, ignore_errors=True)
            try:
                run_git(["clone", auth_url, str(dest)])
                run_git(["checkout", "--detach", ref], cwd=dest)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                shutil.rmtree(dest, ignore_errors=True)
                stderr = redact((getattr(e, "stderr", "") or "").strip())
                die(
                    f"git clone/checkout failed for {redact(url)} (ref={ref}): "
                    f"{stderr or type(e).__name__}"
                )

    log("cloning (shallow, depth=1)…")
    try:
        run_git(["clone", "--depth", "1", "--single-branch", auth_url, str(dest)])
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        log("shallow clone failed; retrying full clone…")
        shutil.rmtree(dest, ignore_errors=True)
        try:
            run_git(["clone", auth_url, str(dest)])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            stderr = redact((getattr(e, "stderr", "") or "").strip())
            die(f"git clone failed for {redact(url)}: {stderr or type(e).__name__}")


# ---- Branch 1: local path ---------------------------------------------------
def handle_local(raw: str, subdir: str | None = None, ref: str | None = None) -> Path:
    if ref:
        die(
            f"--ref '{ref}' cannot be used with a local repository path (strictly read-only; "
            f"never switches branches in a local working tree)."
        )
    p = Path(raw).expanduser()
    if not p.exists():
        die(f"path does not exist and is not a recognizable URL: {raw}")
    if not p.is_dir():
        die(f"not a directory: {raw}")
    resolved = p.resolve()
    log(f"using local repository: {resolved}")
    if not (resolved / ".git").exists():
        log(f"warning: {resolved} is not a git repository root (no .git). Proceeding read-only.")
    target = resolve_subdir(resolved, subdir)
    if target != resolved:
        log(f"resolved subdirectory: {target}")
    size = dir_size_mb(target)
    if size > MAX_SIZE_MB:
        die(
            f"local repo target is {size}MB, exceeds MAX_SIZE_MB={MAX_SIZE_MB}. "
            f"Set MAX_SIZE_MB higher or pass --subdir to narrow scope."
        )
    return target


# ---- Branch 2: remote URL ---------------------------------------------------
def handle_remote(url: str, ref: str | None = None, subdir: str | None = None) -> Path:
    safe_name = derive_dest_name(url, ref=ref)
    dest = WORK_ROOT / safe_name
    log(f"resolved URL: {redact(url)}")
    if ref:
        log(f"target ref:   {ref}")
    if subdir:
        log(f"target subdir:{subdir}")
    log(f"destination:  {dest}")

    # Refresh an existing clone instead of re-cloning.
    if (dest / ".git").is_dir():
        fetch_target = ref or "HEAD"
        log(f"existing clone found; refreshing (fetch --depth 1 origin {fetch_target})")
        try:
            run_git(["fetch", "--depth", "1", "origin", fetch_target], cwd=dest)
            run_git(["reset", "--hard", "FETCH_HEAD"], cwd=dest)
            return resolve_subdir(dest.resolve(), subdir)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log(f"refresh failed ({type(e).__name__}); removing and re-cloning")
            shutil.rmtree(dest, ignore_errors=True)

    # Fresh clone (with ref/commit support and full-clone fallback).
    auth_url = clone_url(url)
    _clone_fresh(auth_url, url, dest, ref)

    if not (dest / ".git").is_dir():
        die(f"clone finished but {dest} is not a git repo")

    target = resolve_subdir(dest.resolve(), subdir)
    size = dir_size_mb(target)
    if size > MAX_SIZE_MB:
        log(f"warning: target is {size}MB (limit {MAX_SIZE_MB}MB). Downstream scans may be slow.")
    return target


# ---- Entry point ------------------------------------------------------------
def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog=Path(argv[0]).name,
        description="Resolve a local path, GitHub/Git URL (including /tree/<ref>/<subdir>), or owner/repo[@ref].",
    )
    parser.add_argument(
        "target",
        help="Local directory path, GitHub/Git URL, or owner/repo[@ref] shorthand",
    )
    parser.add_argument(
        "--ref",
        default=None,
        help="Branch, tag, or commit SHA to check out for remote clones (overrides URL ref)",
    )
    parser.add_argument(
        "--subdir",
        default=None,
        help="Relative subdirectory inside the repository to target (overrides URL subpath)",
    )
    args = parser.parse_args(argv[1:])

    if not args.target.strip():
        die("target input must not be empty")
    if shutil.which("git") is None:
        die("required command not found: git")

    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    url, url_ref, url_subdir = parse_repo_input(args.target)
    ref = args.ref.strip() if args.ref and args.ref.strip() else url_ref
    subdir = args.subdir if args.subdir is not None else url_subdir

    resolved = (
        handle_local(args.target, subdir=subdir, ref=ref)
        if not url
        else handle_remote(url, ref=ref, subdir=subdir)
    )

    # Single-line, machine-readable result for the caller.
    print(str(resolved))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        die("interrupted", code=130)
    except subprocess.TimeoutExpired:
        die(f"git operation exceeded GIT_TIMEOUT={GIT_TIMEOUT}s")
