"""Tests for architecture & onboarding upgrades:
- Integrated HTTP route & data-model extraction
- Nested monorepo manifests, entry points, and test framework detection
- tsconfig.json / jsconfig.json JSONC path alias & baseUrl import resolution
- Priority-based Mermaid node selection & package-level Mermaid overview
- License type detection, README summary, discovered commands, and directory overview
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.analyzer import analyze_repository  # noqa: E402
from scripts.dependency_graph import render_mermaid, render_package_mermaid  # noqa: E402
from scripts.report import write_reports  # noqa: E402


class RouteAndModelIntegrationTests(unittest.TestCase):
    def test_routes_and_models_extracted_into_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "webapp"
            (repo / "src").mkdir(parents=True)
            (repo / "prisma").mkdir()
            (repo / "db").mkdir()
            (repo / "tests").mkdir()

            (repo / "src" / "api.py").write_text(
                "from dataclasses import dataclass\n"
                "from pathlib import Path\n"
                "from fastapi import APIRouter\n"
                "ROOT = Path('.')\n"
                "router = APIRouter()\n"
                "@dataclass\n"
                "class UserDTO:\n"
                "    id: int\n"
                "@router.get('/users')\n"
                "def list_users():\n"
                "    return []\n"
                "@router.post('/users')\n"
                "def create_user():\n"
                "    return {}\n",
                encoding="utf-8",
            )
            (repo / "prisma" / "schema.prisma").write_text(
                "model Account {\n"
                "  id Int @id\n"
                "}\n",
                encoding="utf-8",
            )
            (repo / "db" / "init.sql").write_text(
                "CREATE TABLE IF NOT EXISTS audit_logs (id INT PRIMARY KEY);\n",
                encoding="utf-8",
            )
            (repo / "tests" / "test_api.py").write_text(
                "@app.route('/test-only')\n"
                "def dummy(): pass\n",
                encoding="utf-8",
            )

            result = analyze_repository(repo)
            arch = result["architecture"]
            self.assertGreaterEqual(arch["summary"]["routes"], 2)
            self.assertGreaterEqual(arch["summary"]["models"], 3)

            # Production routes sort before test routes, and Path('.') is not mistaken for a Django URL.
            self.assertEqual(arch["routes"][0]["scope"], "production")
            route_paths = {r["route"] for r in arch["routes"]}
            self.assertIn("/users", route_paths)
            self.assertIn("/test-only", route_paths)
            self.assertNotIn(".", route_paths)

            model_names = {m["name"] for m in arch["models"]}
            self.assertTrue({"UserDTO", "Account", "audit_logs"}.issubset(model_names))

            out_dir = Path(tmp) / "out"
            md_path, json_path = write_reports(result, out_dir)
            md = md_path.read_text(encoding="utf-8")
            self.assertIn("### Detected API routes", md)
            self.assertIn("`/users`", md)
            self.assertIn("### Detected data models & schemas", md)
            self.assertIn("`Account`", md)
            self.assertIn("`audit_logs`", md)

            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["architecture"]["summary"]["models"], arch["summary"]["models"])


class MonorepoAndTsconfigAliasTests(unittest.TestCase):
    def test_nested_manifests_dependencies_entries_and_go_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "monorepo"
            (repo / "apps" / "web" / "src").mkdir(parents=True)
            (repo / "services" / "api" / "pkg").mkdir(parents=True)
            (repo / "services" / "worker" / "internal" / "jobs").mkdir(parents=True)

            (repo / "apps" / "web" / "package.json").write_text(
                json.dumps({
                    "name": "web",
                    "main": "src/boot.ts",
                    "dependencies": {"react": "^18.2.0"},
                    "devDependencies": {"vitest": "^1.0.0"},
                    "scripts": {"dev": "vite", "test": "vitest run"},
                }),
                encoding="utf-8",
            )
            (repo / "apps" / "web" / "src" / "boot.ts").write_text(
                "import React from 'react';\nexport const x = 1;\n",
                encoding="utf-8",
            )

            (repo / "services" / "api" / "pyproject.toml").write_text(
                "[project]\n"
                "name = 'api'\n"
                "dependencies = ['fastapi>=0.110']\n"
                "[project.scripts]\n"
                "api-serve = 'pkg.runner:main'\n"
                "[tool.pytest.ini_options]\n"
                "testpaths = ['tests']\n",
                encoding="utf-8",
            )
            (repo / "services" / "api" / "pkg" / "runner.py").write_text(
                "def main():\n    return 0\n",
                encoding="utf-8",
            )

            (repo / "services" / "worker" / "go.mod").write_text(
                "module example.com/worker\n\n"
                "require github.com/stretchr/testify v1.9.0\n",
                encoding="utf-8",
            )
            (repo / "services" / "worker" / "main.go").write_text(
                'package main\n'
                'import "example.com/worker/internal/jobs"\n'
                'func main() { _ = jobs.Run }\n',
                encoding="utf-8",
            )
            (repo / "services" / "worker" / "internal" / "jobs" / "jobs.go").write_text(
                "package jobs\nfunc Run() {}\n",
                encoding="utf-8",
            )

            result = analyze_repository(repo)
            arch = result["architecture"]
            deps = {(d["name"], d["source"]) for d in arch["dependencies"]}
            self.assertIn(("react", "apps/web/package.json"), deps)
            self.assertIn(("fastapi", "services/api/pyproject.toml"), deps)
            self.assertIn(("github.com/stretchr/testify", "services/worker/go.mod"), deps)

            entries = {e["path"] for e in arch["entry_points"]}
            self.assertIn("apps/web/src/boot.ts", entries)
            self.assertIn("services/api/pkg/runner.py", entries)
            self.assertIn("services/worker/main.go", entries)

            # Nested Go module internal import resolves cleanly.
            go_internal = [
                e for e in arch["imports"]
                if e["source"] == "services/worker/main.go" and e["classification"] == "internal"
            ]
            self.assertEqual(len(go_internal), 1)
            self.assertEqual(go_internal[0]["target"], "services/worker/internal/jobs/jobs.go")

            # Nested test frameworks detected in repo health.
            frameworks = result["summary"]["repo_health"]["tests"]["frameworks"]
            self.assertIn("vitest", frameworks)
            self.assertIn("pytest", frameworks)

    def test_tsconfig_jsonc_paths_and_baseurl_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "tsapp"
            (repo / "src" / "utils").mkdir(parents=True)
            (repo / "src" / "shared").mkdir(parents=True)
            (repo / "tsconfig.json").write_text(
                "{\n"
                "  // JSONC comment in tsconfig\n"
                "  /* Block comment */\n"
                "  \"compilerOptions\": {\n"
                "    \"baseUrl\": \".\",\n"
                "    \"paths\": {\n"
                "      \"@/*\": [\"src/*\"],\n"
                "    },\n"
                "  },\n"
                "}\n",
                encoding="utf-8",
            )
            (repo / "src" / "utils" / "math.ts").write_text("export const add = (a: number, b: number) => a + b;\n", encoding="utf-8")
            (repo / "src" / "shared" / "index.ts").write_text("export const ok = true;\n", encoding="utf-8")
            (repo / "src" / "index.ts").write_text(
                "import React from 'react';\n"
                "import { add } from '@/utils/math';\n"
                "import { ok } from 'src/shared';\n"
                "import { missing } from '@/does-not-exist';\n"
                "import { add as add2 } from './utils/math.js';\n",
                encoding="utf-8",
            )

            result = analyze_repository(repo)
            arch = result["architecture"]
            self.assertEqual(arch["summary"]["js_alias_configs"], 1)

            by_spec = {e["specifier"]: e for e in arch["imports"] if e["source"] == "src/index.ts"}
            self.assertEqual(by_spec["react"]["classification"], "external_or_stdlib")
            self.assertEqual(by_spec["@/utils/math"]["classification"], "internal")
            self.assertEqual(by_spec["@/utils/math"]["target"], "src/utils/math.ts")
            self.assertEqual(by_spec["src/shared"]["classification"], "internal")
            self.assertEqual(by_spec["src/shared"]["target"], "src/shared/index.ts")
            self.assertEqual(by_spec["./utils/math.js"]["classification"], "internal")
            self.assertEqual(by_spec["./utils/math.js"]["target"], "src/utils/math.ts")
            self.assertEqual(by_spec["@/does-not-exist"]["classification"], "unresolved_local")


class MermaidPriorityAndPackageOverviewTests(unittest.TestCase):
    def test_mermaid_prioritizes_production_entries_and_hubs_over_alphabetical_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "large"
            (repo / "a_tests").mkdir(parents=True)
            (repo / "z_core").mkdir(parents=True)
            for i in range(10):
                (repo / "a_tests" / f"test_{i:02d}.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "z_core" / "hub.py").write_text("VALUE = 1\n", encoding="utf-8")
            (repo / "z_core" / "main.py").write_text("from z_core import hub\n", encoding="utf-8")

            result = analyze_repository(repo)
            diagram = render_mermaid(result["architecture"], max_nodes=4)
            self.assertIn("z_core/main.py", diagram)
            self.assertIn("z_core/hub.py", diagram)
            self.assertIn("prioritized by production scope", diagram)

    def test_package_level_mermaid_embedded_for_large_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "bigpkg"
            (repo / "src" / "api").mkdir(parents=True)
            (repo / "src" / "core").mkdir(parents=True)
            (repo / "src" / "extra").mkdir(parents=True)
            (repo / "src" / "core" / "db.py").write_text("DB = 1\n", encoding="utf-8")
            (repo / "src" / "api" / "a.py").write_text("from src.core import db\n", encoding="utf-8")
            (repo / "src" / "api" / "b.py").write_text("from src.core import db\n", encoding="utf-8")
            # Create >40 modules so report.md triggers the inline package-level overview.
            for i in range(40):
                (repo / "src" / "extra" / f"m{i:02d}.py").write_text("v = 1\n", encoding="utf-8")

            result = analyze_repository(repo)
            pkg_mmd = render_package_mermaid(result["architecture"])
            self.assertIsNotNone(pkg_mmd)
            self.assertIn("src/api", pkg_mmd)
            self.assertIn("src/core", pkg_mmd)
            self.assertIn("-->|2|", pkg_mmd)

            out_dir = Path(tmp) / "out"
            md_path, _ = write_reports(result, out_dir)
            md = md_path.read_text(encoding="utf-8")
            self.assertIn("#### Package-level dependency overview", md)
            self.assertIn("architecture.mmd", md)


class OnboardingHealthAndDirectoryOverviewTests(unittest.TestCase):
    def test_license_type_readme_summary_commands_and_directory_overview(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "proj"
            (repo / "src").mkdir(parents=True)
            (repo / "tests").mkdir(parents=True)

            (repo / "README.md").write_text(
                "[![CI](https://img.shields.io/badge/ci-pass-green)]\n\n"
                "# Acme Service\n\n"
                "Fast read-only [inventory](https://example.com) service for teams.\n\n"
                "## Install\n",
                encoding="utf-8",
            )
            (repo / "LICENSE").write_text(
                "Apache License\nVersion 2.0, January 2004\n",
                encoding="utf-8",
            )
            (repo / "Makefile").write_text(
                ".PHONY: test lint\n"
                "test:\n\tpytest\n"
                "lint:\n\truff check .\n",
                encoding="utf-8",
            )
            (repo / "package.json").write_text(
                json.dumps({"name": "acme", "scripts": {"dev": "vite", "build": "vite build"}}),
                encoding="utf-8",
            )
            (repo / "src" / "app.py").write_text("x = 1\n" * 20, encoding="utf-8")
            (repo / "tests" / "test_app.py").write_text("def test_ok(): assert True\n", encoding="utf-8")

            result = analyze_repository(repo)
            health = result["summary"]["repo_health"]
            self.assertEqual(health["license_type"], "Apache-2.0")
            self.assertIn("Acme Service", health["readme_summary"])
            self.assertIn("Fast read-only inventory service for teams.", health["readme_summary"])

            cmd_names = {(c["source"], c["name"]) for c in health["commands"]}
            self.assertIn(("package.json", "dev"), cmd_names)
            self.assertIn(("package.json", "build"), cmd_names)
            self.assertIn(("Makefile", "test"), cmd_names)
            self.assertIn(("Makefile", "lint"), cmd_names)

            overview = result["summary"]["directory_overview"]
            dirs = {row["directory"]: row for row in overview}
            self.assertEqual(dirs["src"]["files"], 1)
            self.assertEqual(dirs["src"]["lines"], 20)
            self.assertEqual(dirs["src"]["primary_language"], "Python")
            self.assertEqual(dirs["tests"]["test_files"], 1)

            out_dir = Path(tmp) / "out"
            md_path, _ = write_reports(result, out_dir)
            md = md_path.read_text(encoding="utf-8")
            self.assertIn("LICENSE=yes (Apache-2.0)", md)
            self.assertIn("**README summary:** Acme Service", md)
            self.assertIn("### Discovered commands (read-only, not executed)", md)
            self.assertIn("## Directory overview", md)


class ProductionSubgraphAndExpandedSpecsTests(unittest.TestCase):
    def test_production_subgraph_separates_test_fan_in_and_reachability(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "prodgraph"
            (repo / "src").mkdir(parents=True)
            (repo / "tests").mkdir(parents=True)
            (repo / "src" / "helper.py").write_text("X = 1\n", encoding="utf-8")
            (repo / "src" / "main.py").write_text(
                "from src import helper\n"
                "if __name__ == '__main__':\n"
                "    print(helper.X)\n",
                encoding="utf-8",
            )
            for i in range(4):
                (repo / "tests" / f"test_{i}.py").write_text("from src import helper\n", encoding="utf-8")

            result = analyze_repository(repo)
            metrics = result["architecture"]["dependency_graph"]["metrics"]
            # Full repo: 4 tests + 1 main import helper => in_degree 5, 4 unreachable test modules.
            self.assertEqual(metrics["top_fan_in_modules"][0]["path"], "src/helper.py")
            self.assertEqual(metrics["top_fan_in_modules"][0]["degree"], 5)
            self.assertEqual(metrics["not_reachable_from_entry_points"], 4)

            # Production subgraph: only main imports helper => degree 1, 0 unreachable production modules!
            prod = metrics["production"]
            self.assertEqual(prod["modules"], 2)
            self.assertEqual(prod["not_reachable_from_entry_points"], 0)
            self.assertEqual(prod["top_fan_in_modules"][0]["path"], "src/helper.py")
            self.assertEqual(prod["top_fan_in_modules"][0]["degree"], 1)

            unreachable_ins = [
                ins for ins in result["architecture"]["dependency_graph"]["insights"]
                if ins["category"] == "not_reachable_from_entry_points"
            ]
            self.assertEqual(len(unreachable_ins), 1)
            self.assertEqual(unreachable_ins[0]["production_count"], 0)

    def test_multi_ecosystem_manifests_api_specs_and_nextjs_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "polyglot"
            (repo / "app" / "api" / "users").mkdir(parents=True)
            (repo / "pages" / "api").mkdir(parents=True)
            (repo / "proto").mkdir()
            (repo / "graphql").mkdir()

            (repo / "pom.xml").write_text(
                "<project><dependencies>"
                "<dependency><groupId>org.springframework.boot</groupId>"
                "<artifactId>spring-boot-starter-web</artifactId><version>3.2.0</version></dependency>"
                "</dependencies></project>\n",
                encoding="utf-8",
            )
            (repo / "build.gradle.kts").write_text(
                'dependencies { implementation("io.ktor:ktor-server-core:2.3.7") }\n',
                encoding="utf-8",
            )
            (repo / "Gemfile").write_text("gem 'rails', '~> 7.1'\n", encoding="utf-8")
            (repo / "composer.json").write_text(
                json.dumps({"require": {"php": "^8.2", "laravel/framework": "^11.0"}}),
                encoding="utf-8",
            )
            (repo / "pubspec.yaml").write_text(
                "name: demo\ndependencies:\n  http: ^1.2.0\ndev_dependencies:\n  test: ^1.25.0\n",
                encoding="utf-8",
            )
            (repo / "App.csproj").write_text(
                '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>\n',
                encoding="utf-8",
            )
            (repo / "openapi.yaml").write_text("openapi: 3.1.0\ninfo:\n  title: Demo\n", encoding="utf-8")
            (repo / "graphql" / "schema.graphql").write_text(
                "type Customer { id: ID! }\ninput CreateCustomerInput { name: String! }\n",
                encoding="utf-8",
            )
            (repo / "proto" / "orders.proto").write_text(
                "syntax = \"proto3\";\nmessage Order { string id = 1; }\n"
                "service OrderService { rpc GetOrder(Order) returns (Order); }\n",
                encoding="utf-8",
            )
            (repo / "app" / "api" / "users" / "route.ts").write_text(
                "export async function GET() { return new Response('ok'); }\n"
                "export async function POST() { return new Response('ok'); }\n",
                encoding="utf-8",
            )
            (repo / "pages" / "api" / "health.ts").write_text(
                "export default function handler(req, res) { res.status(200).end(); }\n",
                encoding="utf-8",
            )

            result = analyze_repository(repo)
            arch = result["architecture"]
            dep_names = {d["name"] for d in arch["dependencies"]}
            for expected in (
                "org.springframework.boot:spring-boot-starter-web",
                "io.ktor:ktor-server-core",
                "rails",
                "laravel/framework",
                "http",
                "Newtonsoft.Json",
            ):
                self.assertIn(expected, dep_names)

            spec_kinds = {(s["path"], s["kind"]) for s in arch["api_specs"]}
            self.assertIn(("openapi.yaml", "OpenAPI/Swagger"), spec_kinds)
            self.assertIn(("graphql/schema.graphql", "GraphQL"), spec_kinds)
            self.assertIn(("proto/orders.proto", "Protobuf"), spec_kinds)

            route_pairs = {(r["framework"], r["route"]) for r in arch["routes"]}
            self.assertIn(("Next.js-AppRouter", "GET,POST /api/users"), route_pairs)
            self.assertIn(("Next.js-PagesAPI", "/api/health"), route_pairs)
            self.assertIn(("gRPC/Protobuf", "GetOrder"), route_pairs)

            model_pairs = {(m["kind"], m["name"]) for m in arch["models"]}
            self.assertIn(("GraphQL-type", "Customer"), model_pairs)
            self.assertIn(("Proto-message", "Order"), model_pairs)
            self.assertIn(("Proto-service", "OrderService"), model_pairs)


if __name__ == "__main__":
    unittest.main()
