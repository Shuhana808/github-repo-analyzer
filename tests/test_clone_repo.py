"""Tests for scripts/clone_repo.py.

Focus: input normalization, dest-name derivation, credential redaction, and
the local-path branch. Remote cloning is tested only against file:// URLs and
guarded by the presence of `git` on PATH.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Load the script as a module without requiring it to be on sys.path.
_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "clone_repo.py"
_spec = importlib.util.spec_from_file_location("clone_repo", _SCRIPT)
clone_repo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(clone_repo)  # type: ignore[union-attr]


class NormalizeUrlTests(unittest.TestCase):
    def test_https_github_passthrough(self):
        self.assertEqual(
            clone_repo.normalize_url("https://github.com/owner/repo.git"),
            "https://github.com/owner/repo.git",
        )

    def test_https_github_no_git_suffix(self):
        self.assertEqual(
            clone_repo.normalize_url("https://github.com/owner/repo"),
            "https://github.com/owner/repo",
        )

    def test_ssh_github_converted_to_https(self):
        self.assertEqual(
            clone_repo.normalize_url("git@github.com:owner/repo.git"),
            "https://github.com/owner/repo.git",
        )

    def test_owner_repo_shorthand(self):
        self.assertEqual(
            clone_repo.normalize_url("owner/repo"),
            "https://github.com/owner/repo.git",
        )

    def test_owner_repo_shorthand_strips_git(self):
        self.assertEqual(
            clone_repo.normalize_url("owner/repo.git"),
            "https://github.com/owner/repo.git",
        )

    def test_local_path_returns_empty(self):
        # /tmp always exists in these tests and contains no slash-free form,
        # so the shorthand branch is correctly skipped.
        self.assertEqual(clone_repo.normalize_url("/tmp"), "")

    def test_nonexistent_shorthand_is_still_url(self):
        # A string shaped like owner/repo that is not a real directory
        # must be treated as a GitHub shorthand.
        self.assertEqual(
            clone_repo.normalize_url("someowner/somerepo"),
            "https://github.com/someowner/somerepo.git",
        )

    def test_real_relative_dir_is_local(self):
        # If the string corresponds to a real directory, treat as local path.
        with tempfile.TemporaryDirectory() as td:
            prev = os.getcwd()
            try:
                os.chdir(td)
                os.makedirs("fakeowner/somerepo")
                self.assertEqual(clone_repo.normalize_url("fakeowner/somerepo"), "")
            finally:
                os.chdir(prev)

    def test_empty_string(self):
        self.assertEqual(clone_repo.normalize_url(""), "")

    def test_unsupported_scheme(self):
        # ftp:// is not a supported scheme and is not a local path.
        self.assertEqual(clone_repo.normalize_url("ftp://example.com/x"), "")


class ParseRepoInputTests(unittest.TestCase):
    def test_github_tree_branch_and_subdir(self):
        url, ref, subdir = clone_repo.parse_repo_input(
            "https://github.com/owner/monorepo/tree/develop/packages/api/"
        )
        self.assertEqual(url, "https://github.com/owner/monorepo.git")
        self.assertEqual(ref, "develop")
        self.assertEqual(subdir, "packages/api")

    def test_github_tree_branch_only(self):
        url, ref, subdir = clone_repo.parse_repo_input(
            "https://github.com/owner/repo/tree/v2.1.0"
        )
        self.assertEqual(url, "https://github.com/owner/repo.git")
        self.assertEqual(ref, "v2.1.0")
        self.assertIsNone(subdir)

    def test_github_blob_resolves_parent_subdir(self):
        url, ref, subdir = clone_repo.parse_repo_input(
            "https://github.com/owner/repo/blob/main/services/auth/app.py#L10"
        )
        self.assertEqual(url, "https://github.com/owner/repo.git")
        self.assertEqual(ref, "main")
        self.assertEqual(subdir, "services/auth")

    def test_github_blob_at_root_has_no_subdir(self):
        url, ref, subdir = clone_repo.parse_repo_input(
            "https://github.com/owner/repo/blob/main/README.md"
        )
        self.assertEqual(url, "https://github.com/owner/repo.git")
        self.assertEqual(ref, "main")
        self.assertIsNone(subdir)

    def test_github_commit_url(self):
        url, ref, subdir = clone_repo.parse_repo_input(
            "https://github.com/owner/repo/commit/deadbeef1234"
        )
        self.assertEqual(url, "https://github.com/owner/repo.git")
        self.assertEqual(ref, "deadbeef1234")
        self.assertIsNone(subdir)

    def test_github_query_fragment_and_non_code_section(self):
        url1, ref1, sub1 = clone_repo.parse_repo_input(
            "https://github.com/owner/repo/?tab=readme-ov-file#install"
        )
        self.assertEqual((url1, ref1, sub1), ("https://github.com/owner/repo", None, None))
        url2, ref2, sub2 = clone_repo.parse_repo_input(
            "https://github.com/owner/repo/issues/42"
        )
        self.assertEqual((url2, ref2, sub2), ("https://github.com/owner/repo.git", None, None))

    def test_gitlab_tree_url(self):
        url, ref, subdir = clone_repo.parse_repo_input(
            "https://gitlab.com/group/sub/repo/-/tree/main/pkg/core"
        )
        self.assertEqual(url, "https://gitlab.com/group/sub/repo.git")
        self.assertEqual(ref, "main")
        self.assertEqual(subdir, "pkg/core")

    def test_owner_repo_at_ref_shorthand(self):
        url, ref, subdir = clone_repo.parse_repo_input("pallets/flask@3.0.0")
        self.assertEqual(url, "https://github.com/pallets/flask.git")
        self.assertEqual(ref, "3.0.0")
        self.assertIsNone(subdir)


class SubdirAndRefGuardTests(unittest.TestCase):
    def test_derive_dest_name_varies_by_ref(self):
        a = clone_repo.derive_dest_name("https://github.com/owner/repo.git")
        b = clone_repo.derive_dest_name("https://github.com/owner/repo.git", ref="develop")
        self.assertNotEqual(a, b)
        self.assertIn("develop", b)

    def test_resolve_subdir_blocks_traversal_and_absolute(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "packages" / "api").mkdir(parents=True)
            (root / "etc").mkdir()
            self.assertEqual(
                clone_repo.resolve_subdir(root, "packages/api"),
                (root / "packages" / "api").resolve(),
            )
            with self.assertRaises(SystemExit):
                clone_repo.resolve_subdir(root, "../outside")
            with self.assertRaises(SystemExit):
                clone_repo.resolve_subdir(root, "/etc")
            with self.assertRaises(SystemExit):
                clone_repo.resolve_subdir(root, "does/not/exist")

    def test_handle_local_rejects_ref_and_supports_subdir(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sub").mkdir()
            self.assertEqual(clone_repo.handle_local(td, subdir="sub"), (root / "sub").resolve())
            with self.assertRaises(SystemExit):
                clone_repo.handle_local(td, ref="main")


class DeriveDestNameTests(unittest.TestCase):
    def test_https_url(self):
        name = clone_repo.derive_dest_name("https://github.com/owner/repo.git")
        self.assertEqual(name, "github.com_owner_repo")

    def test_url_with_trailing_slash(self):
        name = clone_repo.derive_dest_name("https://github.com/owner/repo/")
        # Trailing slash becomes underscore; still deterministic.
        self.assertTrue(name.startswith("github.com_owner_repo"))

    def test_collides_only_on_host_and_path(self):
        a = clone_repo.derive_dest_name("https://github.com/a/b.git")
        b = clone_repo.derive_dest_name("https://gitlab.com/a/b.git")
        self.assertNotEqual(a, b)

    def test_output_is_filesystem_safe(self):
        name = clone_repo.derive_dest_name("https://example.com/a:b/c?d=e")
        # No character that breaks a path component.
        for ch in ":/?*<>|":
            self.assertNotIn(ch, name)


class RedactTests(unittest.TestCase):
    def test_token_in_url_is_redacted(self):
        url = "https://x-access-token:ghp_secret123@github.com/owner/repo.git"
        self.assertEqual(
            clone_repo.redact(url),
            "https://***@github.com/owner/repo.git",
        )

    def test_plain_url_unchanged(self):
        url = "https://github.com/owner/repo.git"
        self.assertEqual(clone_repo.redact(url), url)

    def test_ssh_url_unchanged(self):
        url = "git@github.com:owner/repo.git"
        self.assertEqual(clone_repo.redact(url), url)

    def test_github_token_redacted_in_arbitrary_stderr(self):
        orig = clone_repo.GITHUB_TOKEN
        try:
            clone_repo.GITHUB_TOKEN = "ghp_super_secret_token_value"
            msg = "fatal: auth failed using ghp_super_secret_token_value for repo"
            self.assertNotIn("ghp_super_secret_token_value", clone_repo.redact(msg))
        finally:
            clone_repo.GITHUB_TOKEN = orig


class DirSizeTests(unittest.TestCase):
    def test_empty_dir_is_zero(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(clone_repo.dir_size_mb(Path(td)), 0)

    def test_megabyte_rounding(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "big.bin"
            # ~2 MB of zeros
            p.write_bytes(b"\0" * (2 * 1024 * 1024))
            self.assertEqual(clone_repo.dir_size_mb(Path(td)), 2)


@unittest.skipUnless(shutil.which("git"), "git not on PATH")
class HandleLocalTests(unittest.TestCase):
    def test_plain_directory_without_git(self):
        with tempfile.TemporaryDirectory() as td:
            # No .git subdir — should still resolve, with a warning on stderr.
            result = clone_repo.handle_local(td)
            self.assertEqual(result, Path(td).resolve())

    def test_nonexistent_path_raises(self):
        with self.assertRaises(SystemExit) as cm:
            clone_repo.handle_local("/no/such/path/anywhere-xyz")
        self.assertNotEqual(cm.exception.code, 0)

    def test_file_not_directory_raises(self):
        with tempfile.NamedTemporaryFile() as f:
            with self.assertRaises(SystemExit) as cm:
                clone_repo.handle_local(f.name)
            self.assertNotEqual(cm.exception.code, 0)

    def test_git_repo_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            subprocess.run(["git", "init", "-q", td], check=True)
            result = clone_repo.handle_local(td)
            self.assertTrue((result / ".git").is_dir())


@unittest.skipUnless(shutil.which("git"), "git not on PATH")
class HandleRemoteTests(unittest.TestCase):
    """Uses file:// URLs so we don't depend on network access."""

    def setUp(self):
        self._src = tempfile.TemporaryDirectory()
        self._src_path = Path(self._src.name)
        subprocess.run(["git", "init", "-q", str(self._src_path)], check=True)
        (self._src_path / "README.md").write_text("# fixture\n")
        subprocess.run(["git", "-C", str(self._src_path), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self._src_path),
             "-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "init"],
            check=True,
        )
        self._work = tempfile.TemporaryDirectory()
        # Point the module's work root at our temp dir so tests don't collide.
        self._orig_work_root = clone_repo.WORK_ROOT
        clone_repo.WORK_ROOT = Path(self._work.name)

    def tearDown(self):
        clone_repo.WORK_ROOT = self._orig_work_root
        self._src.cleanup()
        self._work.cleanup()

    def test_clone_from_file_url(self):
        url = f"file://{self._src_path}"
        dest = clone_repo.handle_remote(url)
        self.assertTrue((dest / ".git").is_dir())
        self.assertTrue((dest / "README.md").is_file())

    def test_second_call_reuses_existing(self):
        url = f"file://{self._src_path}"
        first = clone_repo.handle_remote(url)
        second = clone_repo.handle_remote(url)
        self.assertEqual(first, second)
        self.assertTrue((second / ".git").is_dir())

    def test_run_git_raises_on_nonzero_exit(self):
        with self.assertRaises(subprocess.CalledProcessError):
            clone_repo.run_git(["rev-parse", "--verify", "nonexistent-ref-xyz"], cwd=self._src_path)

    def test_failed_clone_exits_with_git_error(self):
        bad_url = f"file://{self._src_path}-does-not-exist"
        with self.assertRaises(SystemExit) as cm:
            clone_repo.handle_remote(bad_url)
        self.assertNotEqual(cm.exception.code, 0)

    def test_clone_specific_branch_commit_and_subdir(self):
        # Record initial commit SHA, then create a feature branch with a monorepo subdir.
        first_sha = subprocess.run(
            ["git", "-C", str(self._src_path), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        subprocess.run(["git", "-C", str(self._src_path), "checkout", "-qb", "feature-api"], check=True)
        (self._src_path / "packages" / "api").mkdir(parents=True)
        (self._src_path / "packages" / "api" / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self._src_path), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self._src_path),
             "-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-qm", "add api package"],
            check=True,
        )

        url = f"file://{self._src_path}"
        # 1. Clone branch + subdir
        api_dir = clone_repo.handle_remote(url, ref="feature-api", subdir="packages/api")
        self.assertTrue((api_dir / "app.py").is_file())
        self.assertEqual(api_dir.name, "api")

        # 2. Refresh existing branch clone
        api_dir_again = clone_repo.handle_remote(url, ref="feature-api", subdir="packages/api")
        self.assertEqual(api_dir, api_dir_again)

        # 3. Clone exact commit SHA (before packages/api existed)
        sha_dir = clone_repo.handle_remote(url, ref=first_sha)
        self.assertTrue((sha_dir / "README.md").is_file())
        self.assertFalse((sha_dir / "packages").exists())


class StdoutContractTests(unittest.TestCase):
    """The script's stdout must be exactly one path on success."""

    @unittest.skipUnless(shutil.which("git"), "git not on PATH")
    def test_local_path_stdout_is_single_line(self):
        with tempfile.TemporaryDirectory() as td:
            proc = subprocess.run(
                [sys.executable, str(_SCRIPT), td],
                capture_output=True, text=True, check=True,
            )
            lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1, f"expected 1 stdout line, got: {proc.stdout!r}")
            self.assertTrue(Path(lines[0]).is_dir())

    def test_missing_arg_exits_nonzero(self):
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT)],
            capture_output=True, text=True,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("usage", proc.stderr)


if __name__ == "__main__":
    unittest.main()