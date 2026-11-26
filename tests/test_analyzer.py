"""Tests for upgraded scripts/analyzer.py, scripts/report.py, and scripts/analyze_repo.py."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.analyzer import analyze_repository, classify_path_scope  # noqa: E402
from scripts.report import write_reports  # noqa: E402


class ScopeClassificationTests(unittest.TestCase):
    def test_scopes(self):
        self.assertEqual(classify_path_scope("src/app.py"), "production")
        self.assertEqual(classify_path_scope("tests/test_app.py"), "test")
        self.assertEqual(classify_path_scope("pkg/foo_test.go"), "test")
        self.assertEqual(classify_path_scope("web/button.spec.ts"), "test")
        self.assertEqual(classify_path_scope("examples/demo.py"), "example")
        self.assertEqual(classify_path_scope("docs/guide.py"), "docs")


class PythonAstAndSecurityTests(unittest.TestCase):
    def test_python_ast_ignores_comments_docstrings_and_method_eval(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "clean.py").write_text(
                '"""Docstring mentioning eval(x) and exec(y) and yaml.load(z)."""\n'
                "# subprocess.run('ls', shell=True)\n"
                "import yaml\n"
                "def run(model, raw):\n"
                "    model.eval()\n"
                "    yaml.safe_load(raw)\n"
                "    yaml.load(raw, Loader=yaml.SafeLoader)\n"
                "    msg = 'eval(123)'\n"
                "    return msg\n",
                encoding="utf-8",
            )
            result = analyze_repository(repo)
            ids = [f["id"] for f in result["findings"]]
            self.assertEqual(ids, [])

    def test_python_ast_detects_real_sinks_including_aliases_and_multiline(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "risky.py").write_text(
                "import subprocess as sp\n"
                "import os\n"
                "import pickle\n"
                "import yaml\n"
                "def f(x, data):\n"
                "    a = eval(x)\n"
                "    exec(x)\n"
                "    sp.run(\n"
                "        x,\n"
                "        shell=True,\n"
                "    )\n"
                "    os.system(x)\n"
                "    pickle.loads(data)\n"
                "    yaml.load(data)\n"
                "    return a\n",
                encoding="utf-8",
            )
            result = analyze_repository(repo)
            ids = {f["id"] for f in result["findings"]}
            self.assertEqual(
                ids,
                {"PY_EVAL", "PY_EXEC", "PY_SHELL", "PY_OS_SYSTEM", "PY_PICKLE", "PY_YAML_LOAD"},
            )
            self.assertTrue(all(f["scope"] == "production" for f in result["findings"]))

    def test_js_and_go_extra_rules_and_comment_skipping(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "app.tsx").write_text(
                "// child_process.exec('ignored')\n"
                "import child_process from 'child_process';\n"
                "child_process.exec(cmd);\n"
                "const el = <div dangerouslySetInnerHTML={{ __html: html }} />;\n",
                encoding="utf-8",
            )
            (repo / "main.go").write_text(
                'package main\n'
                'import "os/exec"\n'
                'func run(cmd string) { exec.Command("sh", "-c", cmd) }\n',
                encoding="utf-8",
            )
            result = analyze_repository(repo)
            ids = {f["id"] for f in result["findings"]}
            self.assertIn("JS_CHILD_PROCESS", ids)
            self.assertIn("JS_DANGEROUS_HTML", ids)
            self.assertIn("GO_EXEC_SHELL", ids)
            # Comment line on line 1 must not trigger JS_CHILD_PROCESS
            cp_lines = [f["line"] for f in result["findings"] if f["id"] == "JS_CHILD_PROCESS"]
            self.assertEqual(cp_lines, [3])

    def test_js_child_process_ignores_regexp_exec_and_catches_real_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "parser.ts").write_text(
                "const re = /foo/g;\n"
                "const match = re.exec(input);\n"
                "const m2 = /bar/.exec(input);\n"
                "const res = db.exec('SELECT 1');\n",
                encoding="utf-8",
            )
            (repo / "runner.js").write_text(
                "const { exec } = require('node:child_process');\n"
                "const re = /abc/;\n"
                "re.exec(cmd);\n"
                "exec(cmd);\n"
                "execSync(cmd);\n",
                encoding="utf-8",
            )
            result = analyze_repository(repo)
            cp = [(f["path"], f["line"]) for f in result["findings"] if f["id"] == "JS_CHILD_PROCESS"]
            self.assertEqual(cp, [("runner.js", 4), ("runner.js", 5)])

    def test_sql_build_avoids_prose_false_positives_and_catches_dynamic_sql(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "safe.py").write_text(
                'label = "Please select an option " + name\n'
                'msg = f"Updated {count} items"\n'
                'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
                'cur.execute("DELETE FROM sessions WHERE id = ?", (sid,))\n',
                encoding="utf-8",
            )
            (repo / "risky.py").write_text(
                'q1 = "SELECT * FROM users WHERE id = " + uid\n'
                'q2 = f"SELECT * FROM notes WHERE title LIKE \'%{q}%\'"\n'
                'q3 = "UPDATE users SET name = \'{}\'".format(name)\n'
                'q4 = "DELETE FROM items WHERE id = %s" % item_id\n',
                encoding="utf-8",
            )
            (repo / "risky.ts").write_text(
                "const q = `DELETE FROM sessions WHERE id = ${sid}`;\n",
                encoding="utf-8",
            )
            result = analyze_repository(repo)
            sql_hits = [(f["path"], f["line"]) for f in result["findings"] if f["id"] == "SQL_BUILD"]
            self.assertEqual(
                sql_hits,
                [
                    ("risky.py", 1),
                    ("risky.py", 2),
                    ("risky.py", 3),
                    ("risky.py", 4),
                    ("risky.ts", 1),
                ],
            )

    def test_secret_detection_redacts_value_in_json_and_markdown(self):
        fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        fake_gh = "ghp_" + "A" * 36
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "config.py").write_text(
                f'AWS = "{fake_aws}"\nGH = "{fake_gh}"\n',
                encoding="utf-8",
            )
            (repo / ".env").write_text("SECRET=should_never_be_read\n", encoding="utf-8")
            result = analyze_repository(repo)
            ids = {f["id"] for f in result["findings"]}
            self.assertIn("SECRET_AWS_KEY", ids)
            self.assertIn("SECRET_GITHUB_TOKEN", ids)

            out_dir = Path(tmp) / "out"
            md_path, json_path = write_reports(result, out_dir)
            md_text = md_path.read_text(encoding="utf-8")
            json_text = json_path.read_text(encoding="utf-8")
            for secret in (fake_aws, fake_gh, "should_never_be_read"):
                self.assertNotIn(secret, md_text)
                self.assertNotIn(secret, json_text)
            self.assertIn("[REDACTED", md_text)

    def test_production_findings_sort_before_test_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / "tests").mkdir(parents=True)
            (repo / "src").mkdir(parents=True)
            # Alphabetically 'a_test.py' precedes 'z_prod.py', but production must sort first.
            (repo / "tests" / "test_a.py").write_text("eval('1')\n", encoding="utf-8")
            (repo / "src" / "z_prod.py").write_text("eval('2')\n", encoding="utf-8")
            result = analyze_repository(repo)
            self.assertEqual(len(result["findings"]), 2)
            self.assertEqual(result["findings"][0]["path"], "src/z_prod.py")
            self.assertEqual(result["findings"][0]["scope"], "production")
            self.assertEqual(result["findings"][1]["path"], "tests/test_a.py")
            self.assertEqual(result["findings"][1]["scope"], "test")
            self.assertEqual(result["summary"]["production_findings"], 1)
            self.assertEqual(result["summary"]["non_production_findings"], 1)


class RepoHealthAndCliTests(unittest.TestCase):
    def test_repo_health_and_test_presence_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / "tests").mkdir()
            (repo / "README.md").write_text("# Demo\n", encoding="utf-8")
            (repo / "LICENSE").write_text("MIT\n", encoding="utf-8")
            (repo / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
            (repo / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
            (repo / "pyproject.toml").write_text(
                "[project]\nname = 'demo'\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
                encoding="utf-8",
            )
            (repo / "app.py").write_text("x = 1\n" * 25, encoding="utf-8")
            (repo / "tests" / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

            out_dir = Path(tmp) / "report"
            proc = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "analyze_repo.py"), str(repo), "--out", str(out_dir)],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(Path(proc.stdout.strip()), out_dir.resolve())
            self.assertIn("health: tests=1 (pytest)", proc.stderr)

            data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            health = data["summary"]["repo_health"]
            self.assertTrue(health["has_readme"])
            self.assertTrue(health["has_license"])
            self.assertIn(".github/workflows/ci.yml", health["ci_configs"])
            self.assertIn("Dockerfile", health["container_files"])
            self.assertTrue(health["tests"]["detected"])
            self.assertEqual(health["tests"]["test_file_count"], 1)
            self.assertIn("pytest", health["tests"]["frameworks"])
            self.assertEqual(health["largest_files"][0]["path"], "app.py")

            md = (out_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Repository health & test presence", md)
            self.assertIn("pytest", md)

    def test_report_discloses_skipped_files_and_separates_todos(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
            (repo / "app.py").write_text(
                "# TODO: clean this up\n"
                "def f(x):\n"
                "    return eval(x)\n",
                encoding="utf-8",
            )
            result = analyze_repository(repo)
            self.assertEqual(result["product"], "github-repo-analyzer")
            self.assertEqual(result["summary"]["heuristic_findings"], 1)
            self.assertEqual(result["summary"]["todo_markers"], 1)
            self.assertEqual(result["summary"]["findings_by_severity"]["high"], 1)
            self.assertEqual(result["summary"]["findings_by_severity"]["low"], 0)
            self.assertEqual(result["summary"]["production_findings_by_severity"]["high"], 1)
            self.assertEqual(len(result["findings"]), 1)
            self.assertEqual(len(result["todos"]), 1)
            self.assertEqual(result["todos"][0]["id"], "TODO")

            out_dir = Path(tmp) / "out"
            md_path, _ = write_reports(result, out_dir)
            md = md_path.read_text(encoding="utf-8")
            self.assertIn("# GitHub Repository Analyzer Report", md)
            self.assertIn("## Scan coverage & truncation disclosures", md)
            self.assertIn("sensitive: 1", md)
            self.assertIn("## TODO / FIXME markers (1 total)", md)
            self.assertNotIn("[TODO] TODO/FIXME marker", md)

            # Compact summary.json is written alongside report.json and omits bulky arrays.
            summary_path = out_dir / "summary.json"
            self.assertTrue(summary_path.is_file())
            compact = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertNotIn("files", compact)
            self.assertNotIn("modules", compact["architecture"])
            self.assertNotIn("imports", compact["architecture"])
            self.assertEqual(compact["top_findings"]["production_code_findings_total"], 1)
            self.assertEqual(compact["top_findings"]["production"][0]["id"], "PY_EVAL")
            self.assertEqual(len(compact["top_findings"]["todo_sample"]), 1)
            self.assertEqual(compact["summary"]["skipped_counts"]["sensitive"], 1)

    def test_analyze_repo_subdir_keeps_git_metadata_and_writes_outside_git_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "monorepo"
            (repo / "packages" / "api").mkdir(parents=True)
            (repo / "packages" / "web").mkdir(parents=True)
            (repo / "packages" / "api" / "app.py").write_text("def run():\n    return 1\n", encoding="utf-8")
            (repo / "packages" / "web" / "index.js").write_text("console.log('web');\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
                check=True,
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "analyze_repo.py"),
                    str(repo),
                    "--subdir",
                    "packages/api",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            out_dir = Path(proc.stdout.strip())
            self.assertTrue(out_dir.is_dir())
            # Default output directory must be strictly outside the git repository root.
            with self.assertRaises(ValueError):
                out_dir.resolve().relative_to(repo.resolve())

            self.assertTrue((out_dir / "summary.json").is_file())
            compact = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
            # Only files in packages/api were analyzed.
            self.assertEqual(compact["summary"]["files_analyzed"], 1)
            git_meta = compact["summary"]["repo_health"]["git"]
            self.assertTrue(git_meta["is_git_repo"])
            self.assertEqual(git_meta["subdir"], "packages/api")
            self.assertIsNotNone(git_meta["head_commit"])

            md = (out_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("subdir: `packages/api`", md)

            # Path traversal via --subdir must fail cleanly.
            bad = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "analyze_repo.py"),
                    str(repo),
                    "--subdir",
                    "../outside",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, "")

    def test_new_security_rules_secrets_and_expanded_sensitive_skips(self):
        fake_anthropic = "sk-ant-" + "A" * 24
        fake_stripe = "sk_live_" + "B" * 24
        fake_npm = "npm_" + "C" * 36
        fake_pypi = "pypi-" + "D" * 52
        fake_db = "postgresql://admin:Sup3rS3cretPw@prod-db.internal:5432/app"
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "sec"
            repo.mkdir()
            (repo / "net.py").write_text(
                "import requests\n"
                "import tarfile\n"
                "requests.get('https://example.com', verify=False)\n"
                "with tarfile.open('a.tar') as tf:\n"
                "    tf.extractall('/tmp/out')\n",
                encoding="utf-8",
            )
            (repo / "client.ts").write_text(
                "const fn = new Function('return 1');\n"
                "const agent = { rejectUnauthorized: false };\n",
                encoding="utf-8",
            )
            (repo / "leaks.py").write_text(
                f'A = "{fake_anthropic}"\n'
                f'S = "{fake_stripe}"\n'
                f'N = "{fake_npm}"\n'
                f'P = "{fake_pypi}"\n'
                f'D = "{fake_db}"\n'
                'SAFE_DB = "postgresql://user:password@localhost:5432/dev"\n',
                encoding="utf-8",
            )
            # Expanded sensitive files must be skipped without reading.
            (repo / "server.pem").write_text("PRIVATE KEY MATERIAL\n", encoding="utf-8")
            (repo / "tls.key").write_text("KEY MATERIAL\n", encoding="utf-8")
            (repo / ".npmrc").write_text("//registry.npmjs.org/:_authToken=secret\n", encoding="utf-8")
            (repo / "gcp-service-account.json").write_text('{"private_key": "abc"}\n', encoding="utf-8")

            result = analyze_repository(repo)
            ids = {f["id"] for f in result["findings"]}
            for expected in (
                "PY_TLS_VERIFY_FALSE",
                "PY_TAR_EXTRACTALL",
                "JS_NEW_FUNCTION",
                "JS_TLS_REJECT_UNAUTH",
                "SECRET_ANTHROPIC_KEY",
                "SECRET_STRIPE_KEY",
                "SECRET_NPM_TOKEN",
                "SECRET_PYPI_TOKEN",
                "SECRET_DB_URL",
            ):
                self.assertIn(expected, ids)
            # Localhost/password placeholder DB URL should not fire SECRET_DB_URL.
            db_hits = [f for f in result["findings"] if f["id"] == "SECRET_DB_URL"]
            self.assertEqual(len(db_hits), 1)
            self.assertEqual(result["summary"]["skipped_counts"]["sensitive"], 4)

            out_dir = Path(tmp) / "out"
            md_path, json_path = write_reports(result, out_dir)
            combined = (
                md_path.read_text(encoding="utf-8")
                + json_path.read_text(encoding="utf-8")
                + (out_dir / "summary.json").read_text(encoding="utf-8")
            )
            for secret in (fake_anthropic, fake_stripe, fake_npm, fake_pypi, "Sup3rS3cretPw"):
                self.assertNotIn(secret, combined)

    def test_env_vars_commands_git_hotspots_and_reading_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "full"
            (repo / "src").mkdir(parents=True)
            (repo / ".github" / "workflows").mkdir(parents=True)
            (repo / "README.md").write_text("# Full App\n\nDemo project.\n", encoding="utf-8")
            (repo / ".env.example").write_text(
                "DATABASE_URL=super_secret_example_val_never_echo\nAPI_KEY=changeme\n",
                encoding="utf-8",
            )
            (repo / ".env").write_text("REAL_SECRET=do_not_read\n", encoding="utf-8")
            (repo / "justfile").write_text("test:\n  pytest\nlint:\n  ruff check .\n", encoding="utf-8")
            (repo / "Taskfile.yml").write_text("version: '3'\ntasks:\n  build:\n    cmds:\n      - echo hi\n", encoding="utf-8")
            (repo / "docker-compose.yml").write_text("services:\n  api:\n    image: python\n  db:\n    image: postgres\n", encoding="utf-8")
            (repo / ".github" / "workflows" / "ci.yml").write_text(
                "jobs:\n  test:\n    steps:\n      - run: pytest -q\n",
                encoding="utf-8",
            )
            (repo / "src" / "core.py").write_text(
                "import os\nDB = os.environ['DATABASE_URL']\nMODE = os.getenv('APP_MODE')\n",
                encoding="utf-8",
            )
            (repo / "src" / "worker.py").write_text("from src import core\n", encoding="utf-8")
            (repo / "src" / "main.py").write_text(
                "from src import core, worker\n"
                "if __name__ == '__main__':\n"
                "    print(core.DB)\n",
                encoding="utf-8",
            )

            # Initialize non-shallow git repo with 3 commits touching src/core.py
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c1"],
                check=True,
            )
            for i in range(2):
                (repo / "src" / "core.py").write_text(
                    f"import os\nDB = os.environ['DATABASE_URL']\nMODE = os.getenv('APP_MODE')\nV = {i}\n",
                    encoding="utf-8",
                )
                subprocess.run(["git", "-C", str(repo), "add", "src/core.py"], check=True)
                subprocess.run(
                    ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", f"c{i+2}"],
                    check=True,
                )

            result = analyze_repository(repo)
            health = result["summary"]["repo_health"]

            # Env vars: names discovered, values NEVER echoed, .env never read.
            env_map = {e["name"]: e for e in health["env_vars"]}
            self.assertIn("DATABASE_URL", env_map)
            self.assertTrue(env_map["DATABASE_URL"]["defined_in_example"])
            self.assertIn("API_KEY", env_map)
            self.assertIn("APP_MODE", env_map)
            self.assertNotIn("REAL_SECRET", env_map)

            # Expanded commands discovered from justfile, Taskfile, docker-compose, and GH Actions.
            cmd_sources = {c["source"] for c in health["commands"]}
            self.assertIn("justfile", cmd_sources)
            self.assertIn("Taskfile.yml", cmd_sources)
            self.assertIn("docker-compose.yml", cmd_sources)
            self.assertIn(".github/workflows/ci.yml", cmd_sources)

            # Git hotspots & hotspot_hubs (src/core.py has 3 commits and production_in_degree=2).
            self.assertEqual(health["git_hotspots"][0]["path"], "src/core.py")
            self.assertEqual(health["git_hotspots"][0]["commits"], 3)
            self.assertTrue(any(h["path"] == "src/core.py" for h in health["hotspot_hubs"]))

            # Reading order starts with README.md and includes main.py and core.py.
            order_paths = [item["path"] for item in result["summary"]["reading_order"]]
            self.assertEqual(order_paths[0], "README.md")
            self.assertIn("src/main.py", order_paths)
            self.assertIn("src/core.py", order_paths)

            out_dir = Path(tmp) / "out"
            md_path, json_path = write_reports(result, out_dir)
            md = md_path.read_text(encoding="utf-8")
            self.assertIn("## Where to start reading", md)
            self.assertIn("### Environment variables & configuration surface", md)
            self.assertIn("### Recent git change hotspots", md)
            self.assertNotIn("super_secret_example_val_never_echo", md)
            self.assertNotIn("super_secret_example_val_never_echo", json_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
