"""Tests for unified scripts/architecture.py.

Covers standalone scanning (`scan`, CLI `--json`/`--summary`, route extraction,
language gates, model extraction, entry points, manifests, skip/size rules) as
well as the library `analyze_architecture` API.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "architecture.py"
_spec = importlib.util.spec_from_file_location("architecture_standalone", _SCRIPT)
arch_mod = importlib.util.module_from_spec(_spec)
sys.modules["architecture_standalone"] = arch_mod
_spec.loader.exec_module(arch_mod)  # type: ignore[union-attr]


# ---- Fixtures ---------------------------------------------------------------
# Each entry: (filename, contents, expected_language, expected_routes)
FIXTURES = {
    "flask": (
        "app.py",
        'from flask import Flask\napp = Flask(__name__)\n'
        '@app.route("/users")\ndef u(): ...\n'
        '@app.get("/users/<int:id>")\ndef u2(id): ...\n',
        "Python",
        {"/users", "/users/<int:id>"},
    ),
    "fastapi": (
        "main.py",
        'from fastapi import FastAPI\nrouter = FastAPI()\n'
        '@router.get("/items")\ndef items(): ...\n'
        '@router.post("/items")\ndef create(): ...\n',
        "Python",
        {"/items"},
    ),
    "express": (
        "server.js",
        'const app = require("express")();\n'
        'app.get("/users", (req, res) => {});\n'
        'app.post("/users/:id", (req, res) => {});\n',
        "JavaScript",
        {"/users", "/users/:id"},
    ),
    "go_net_http": (
        "main.go",
        'package main\nimport "net/http"\n'
        'func main() {\n'
        '  http.HandleFunc("/ping", ping)\n'
        '  http.HandleFunc("/users", users)\n'
        '}\n',
        "Go",
        {"/ping", "/users"},
    ),
    "gin": (
        "main.go",
        'package main\nimport "github.com/gin-gonic/gin"\n'
        'func main() {\n  r := gin.Default()\n'
        '  r.GET("/ping", ping)\n  r.POST("/users", create)\n}\n',
        "Go",
        {"/ping", "/users"},
    ),
    "beego": (
        "routers/router.go",
        'package routers\nimport "github.com/astaxie/beego"\n'
        'func init() {\n'
        '  beego.Router("/users", &UserController{})\n'
        '  beego.NSNamespace("/api", func() {})\n'
        '}\n',
        "Go",
        {"/users", "/api"},
    ),
    "actix_web": (
        "src/main.rs",
        'use actix_web::{get, App};\n'
        '#[get("/hello")]\nasync fn hi() -> &\'static str { "hi" }\n'
        '#[route("/login", method = "POST")]\nasync fn login() {}\n',
        "Rust",
        {"/hello", "/login"},
    ),
    "rocket": (
        "src/main.rs",
        'use rocket::*;\n'
        '#[get("/hello")]\nfn hi() -> &\'static str { "hi" }\n',
        "Rust",
        {"/hello"},
    ),
    "axum": (
        "src/main.rs",
        'use axum::{Router, routing::get};\n'
        'fn main() {\n'
        '  let app = Router::new()\n'
        '    .route("/users", get(list))\n'
        '    .route("/users/:id", get(one));\n'
        '}\n',
        "Rust",
        {"/users", "/users/:id"},
    ),
    "spring": (
        "src/main/java/UserController.java",
        'package demo;\n'
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\npublic class UserController {\n'
        '  @GetMapping("/users")\n  public String list() { return ""; }\n'
        '  @PostMapping("/users")\n  public String create() { return ""; }\n'
        '}\n',
        "Java",
        {"/users"},
    ),
    "ktor": (
        "src/main/kotlin/App.kt",
        'import io.ktor.server.routing.*\n'
        'fun Application.module() {\n'
        '  routing {\n'
        '    get("/users") { call -> }\n'
        '    post("/users/{id}") { call -> }\n'
        '  }\n'
        '}\n',
        "Kotlin",
        {"/users", "/users/{id}"},
    ),
    "phoenix_router": (
        "lib/app_web/router.ex",
        'defmodule AppWeb.Router do\n'
        '  use AppWeb, :router\n'
        '  scope "/api" do\n'
        '    get "/users/:id", UserController, :show\n'
        '    post "/users", UserController, :create\n'
        '    resources "/posts", PostController\n'
        '  end\n'
        'end\n',
        "Elixir",
        {"/users/:id", "/users", "/posts"},
    ),
    "phoenix_non_router": (
        # Must NOT be reported — not in a router.ex file.
        "lib/app/tasks.ex",
        'defmodule App.Tasks do\n'
        '  def get "/x" do\n  end\n'
        'end\n',
        "Elixir",
        set(),
    ),
    "rails": (
        "config/routes.rb",
        'Rails.application.routes.draw do\n'
        '  get "/users", to: "users#index"\n'
        '  post "/users", to: "users#create"\n'
        'end\n',
        "Ruby",
        {"/users"},
    ),
    "laravel": (
        "routes/web.php",
        '<?php\nuse Illuminate\\Support\\Facades\\Route;\n'
        'Route::get("/users", [UserController::class, "index"]);\n'
        'Route::post("/users", [UserController::class, "store"]);\n',
        "PHP",
        {"/users"},
    ),
    "vapor": (
        "Sources/App/routes.swift",
        'import Vapor\n'
        'func routes(_ app: Application) throws {\n'
        '  app.get("users") { req in return "" }\n'
        '  app.get("users", ":id") { req in return "" }\n'
        '}\n',
        "Swift",
        {"/users", "/users/:id"},
    ),
    "aspnet": (
        "Controllers/UserController.cs",
        'using Microsoft.AspNetCore.Mvc;\n'
        '[ApiController]\npublic class UserController : ControllerBase {\n'
        '  [HttpGet("api/users")]\n  public IActionResult List() => Ok();\n'
        '  [HttpPost("api/users")]\n  public IActionResult Create() => Ok();\n'
        '}\n',
        "C#",
        {"api/users"},
    ),
}


def _write_fixture(root: Path, filename: str, contents: str) -> None:
    p = root / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(contents, encoding="utf-8")


class ScanFixtureTests(unittest.TestCase):
    def _scan(self, filename: str, contents: str):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(root, filename, contents)
            return arch_mod.scan(root.resolve())

    def test_each_fixture(self):
        for name, (fname, contents, expected_lang, expected_routes) in FIXTURES.items():
            with self.subTest(framework=name):
                am = self._scan(fname, contents)
                # Language gate: the file must be classified correctly.
                self.assertIn(
                    expected_lang,
                    am.languages,
                    f"{name}: language {expected_lang} not detected; found {am.languages}",
                )
                # Routes: every expected route must appear.
                found = {r["route"] for r in am.routes}
                for want in expected_routes:
                    self.assertIn(
                        want,
                        found,
                        f"{name}: expected route {want!r} not found. Got {sorted(found)}",
                    )

    def test_no_cross_language_leak(self):
        # The Elixir bare-get pattern must not fire on a Python file.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(
                root,
                "app.py",
                'def get(path):\n  return path\n'
                'x = get("/not/a/route")\n',
            )
            am = arch_mod.scan(root.resolve())
            routes = [r for r in am.routes if r["framework"].startswith("Phoenix")]
            self.assertEqual(routes, [], f"Phoenix pattern leaked into Python: {routes}")

    def test_phoenix_router_filter(self):
        # A file with a `get "/x"` inside a non-router .ex must be dropped.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(
                root,
                "lib/app/tasks.ex",
                'defmodule App.Tasks do\n'
                '  def get "/x" do\n  end\n'
                'end\n',
            )
            am = arch_mod.scan(root.resolve())
            self.assertEqual(am.routes, [])

    def test_rocket_vs_actix_disambiguation(self):
        # Same macro shape; only the import distinguishes them.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(
                root,
                "src/main.rs",
                'use rocket::get;\n#[get("/a")]\nfn a() {}\n',
            )
            am = arch_mod.scan(root.resolve())
            self.assertTrue(
                any(r["framework"] == "rocket" for r in am.routes),
                f"expected rocket family, got {am.routes}",
            )

    def test_rust_uncertain_when_no_imports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(root, "src/main.rs", '#[get("/a")]\nfn a() {}\n')
            am = arch_mod.scan(root.resolve())
            self.assertTrue(
                any(r.get("uncertain") for r in am.routes),
                f"expected uncertain flag, got {am.routes}",
            )

    def test_vapor_multitarg_join(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(
                root,
                "Sources/App/routes.swift",
                'app.get("users", ":id") { req in }\n',
            )
            am = arch_mod.scan(root.resolve())
            self.assertTrue(
                any(r["route"] == "/users/:id" for r in am.routes),
                f"Vapor join failed: {am.routes}",
            )


class ModelExtractionTests(unittest.TestCase):
    def test_python_dataclass_and_orm(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(
                root,
                "models.py",
                'from dataclasses import dataclass\n'
                'from sqlalchemy import Base\n'
                '@dataclass\nclass User:\n    id: int\n'
                'class Post(Base):\n    pass\n',
            )
            am = arch_mod.scan(root.resolve())
            names = {m["name"] for m in am.models}
            self.assertIn("User", names)
            self.assertIn("Post", names)

    def test_sql_create_table(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_fixture(
                root,
                "schema.sql",
                'CREATE TABLE users (id INT);\n'
                'CREATE TABLE IF NOT EXISTS posts (id INT);\n',
            )
            am = arch_mod.scan(root.resolve())
            names = {m["name"] for m in am.models}
            self.assertEqual(names, {"users", "posts"})


class EntryPointTests(unittest.TestCase):
    def test_common_entry_points(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "main.py").write_text("print('hi')\n")
            (root / "Dockerfile").write_text("FROM python:3\n")
            (root / "Makefile").write_text("all:\n\techo hi\n")
            am = arch_mod.scan(root.resolve())
            self.assertIn("main.py", am.entry_points)
            self.assertIn("Dockerfile", am.entry_points)
            self.assertIn("Makefile", am.entry_points)

    def test_go_cmd_layout(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "cmd" / "server").mkdir(parents=True)
            (root / "cmd" / "server" / "main.go").write_text("package main\n")
            am = arch_mod.scan(root.resolve())
            self.assertTrue(
                any(e.endswith("cmd/server/main.go") for e in am.entry_points),
                f"cmd/*/main.go entry not found: {am.entry_points}",
            )


class ManifestTests(unittest.TestCase):
    def test_root_and_one_level(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "package.json").write_text("{}")
            (root / "api").mkdir()
            (root / "api" / "requirements.txt").write_text("")
            am = arch_mod.scan(root.resolve())
            self.assertIn("package.json", am.manifests)
            self.assertIn("api/requirements.txt", am.manifests)


class SkipAndSizeTests(unittest.TestCase):
    def test_node_modules_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            nm = root / "node_modules" / "lodash"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text("module.exports = {};\n")
            (root / "app.py").write_text("print('hi')\n")
            am = arch_mod.scan(root.resolve())
            self.assertEqual(am.total_files, 1)

    def test_binary_extensions_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "logo.png").write_bytes(b"\x89PNG")
            (root / "app.py").write_text("print('hi')\n")
            am = arch_mod.scan(root.resolve())
            self.assertEqual(am.total_files, 1)

    def test_large_file_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "big.py").write_text("x = 1\n" * 600)
            am = arch_mod.scan(root.resolve())
            paths = {f["path"] for f in am.large_files}
            self.assertIn("big.py", paths)


class UnifiedApiTests(unittest.TestCase):
    def test_analyze_architecture_available_from_unified_module(self):
        result = arch_mod.analyze_architecture({
            "app.py": (
                "from pkg.core import run\n"
                "@app.get('/health')\n"
                "def health(): return run()\n"
                "if __name__ == '__main__':\n"
                "    run()\n"
            ),
            "pkg/__init__.py": "",
            "pkg/core.py": "def run():\n    return 'ok'\n",
        })
        self.assertEqual(result["summary"]["modules"], 3)
        self.assertEqual(result["summary"]["internal_imports"], 1)
        self.assertEqual(result["summary"]["routes"], 1)
        self.assertEqual(result["routes"][0]["route"], "/health")


class StdoutContractTests(unittest.TestCase):
    def test_json_stdout_is_parseable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("@app.route('/x')\ndef x(): ...\n")
            proc = subprocess.run(
                [sys.executable, str(_SCRIPT), str(root)],
                capture_output=True, text=True, check=True,
            )
            data = json.loads(proc.stdout)
            self.assertIn("routes", data)
            self.assertIn("languages", data)

    def test_summary_flag_produces_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "app.py").write_text("x = 1\n")
            proc = subprocess.run(
                [sys.executable, str(_SCRIPT), str(root), "--summary"],
                capture_output=True, text=True, check=True,
            )
            self.assertIn("# Architecture", proc.stdout)


if __name__ == "__main__":
    unittest.main()
