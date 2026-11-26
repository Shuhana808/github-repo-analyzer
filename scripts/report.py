import json
from pathlib import Path
from .dependency_graph import render_mermaid, render_package_mermaid


def _architecture_section(result):
    architecture = result.get("architecture", {})
    if not architecture:
        return []
    summary = architecture.get("summary", {})
    lines = [
        "", "## Architecture analysis", "",
        f"- **Source files / modules:** {summary.get('modules', 0)}",
        f"- **Detected entry points:** {summary.get('entry_points', 0)}",
        f"- **Import edges:** {summary.get('import_edges', 0)} "
        f"(internal: {summary.get('internal_imports', 0)}, "
        f"external/stdlib: {summary.get('external_or_stdlib_imports', 0)}, "
        f"unresolved local: {summary.get('unresolved_local_imports', 0)})",
        f"- **Direct dependencies:** {summary.get('direct_dependencies', 0)}",
        f"- **Detected API routes:** {summary.get('routes', 0)}",
        f"- **Detected data models:** {summary.get('models', 0)}",
        f"- **Detected API specs (OpenAPI/GraphQL/Protobuf):** {summary.get('api_specs', 0)}",
        f"- **Files skipped by architecture budget:** {summary.get('skipped_files_due_to_budget', 0)}",
        "", "### Detected entry points", "",
    ]
    entries = architecture.get("entry_points", [])
    lines += [f"- `{item['path']}` — {item['reason']}" for item in entries] or ["No entry points detected by current heuristics."]

    api_specs = architecture.get("api_specs", [])
    if api_specs:
        lines += ["", f"### Detected API contract specs ({len(api_specs)} total)", ""]
        for spec in api_specs[:30]:
            lines.append(f"- `{spec['kind']}` — `{spec['path']}`")

    routes = architecture.get("routes", [])
    if routes:
        lines += ["", f"### Detected API routes ({summary.get('routes', len(routes))} total)", ""]
        for r in routes[:40]:
            uncertain = " *(uncertain framework)*" if r.get("uncertain") else ""
            scope_tag = f" [{r['scope']}]" if r.get("scope") and r["scope"] != "production" else ""
            lines.append(f"- `{r['framework']}` `{r['route']}` — `{r['path']}:{r['line']}`{scope_tag}{uncertain}")
        if summary.get("routes", len(routes)) > 40:
            lines.append(f"\n_Only the first 40 of {summary.get('routes', len(routes))} routes are shown here; see `report.json` for all._")

    models = architecture.get("models", [])
    if models:
        lines += ["", f"### Detected data models & schemas ({summary.get('models', len(models))} total)", ""]
        for m in models[:40]:
            scope_tag = f" [{m['scope']}]" if m.get("scope") and m["scope"] != "production" else ""
            lines.append(f"- `{m['kind']}` `{m['name']}` — `{m['path']}:{m['line']}`{scope_tag}")
        if summary.get("models", len(models)) > 40:
            lines.append(f"\n_Only the first 40 of {summary.get('models', len(models))} models are shown here; see `report.json` for all._")

    lines += ["", "### Direct dependencies", ""]
    dependencies = architecture.get("dependencies", [])
    lines += [
        f"- `{dep['name']}` — `{dep['version']}` ({dep['type']}; `{dep['source']}`)"
        for dep in dependencies
    ] or ["No direct dependencies detected in the supported manifests."]

    modules = architecture.get("modules", [])
    lines += ["", "### Module map", "", "| Module | Language | Import statements | Importers | Dependencies | Dependents | Reachable | Role |", "|---|---|---:|---:|---:|---:|---|---|"]
    for module in modules[:100]:
        role = "entry point" if module.get("is_entry_point") else "module"
        reachability = ("yes" if module.get("reachable_from_entry_point") is True else
                        "no" if module.get("reachable_from_entry_point") is False else "unknown")
        lines.append(
            f"| `{module['path']}` | {module['language']} | {module['internal_imports']} | "
            f"{module['imported_by']} | {module.get('out_degree', 0)} | "
            f"{module.get('in_degree', 0)} | {reachability} | {role} |"
        )
    if len(modules) > 100:
        lines.append(f"\n_Only the first 100 of {len(modules)} modules are shown here; see `report.json` for the full map._")

    edges = [e for e in architecture.get("imports", []) if e.get("classification") == "internal" and e.get("target")]
    lines += ["", "### Resolved internal import statements", ""]
    if edges:
        lines += [
            f"- `{edge['source']}:{edge['line']}` → `{edge['target']}` "
            f"(import `{edge['specifier']}`)"
            for edge in edges[:120]
        ]
        if len(edges) > 120:
            lines.append(f"\n_Only the first 120 of {len(edges)} internal import statements are shown here; see `report.json` for all._")
    else:
        lines.append("No internal import edges were resolved.")

    unresolved = [e for e in architecture.get("imports", []) if e.get("classification") == "unresolved_local"]
    if unresolved:
        lines += ["", "### Unresolved local imports", ""]
        lines += [f"- `{e['source']}:{e['line']}` — `{e['specifier']}`" for e in unresolved[:80]]
        if len(unresolved) > 80:
            lines.append(f"\n_Only the first 80 of {len(unresolved)} unresolved references are shown._")

    graph = architecture.get("dependency_graph", {})
    metrics = graph.get("metrics", {})
    lines += ["", "### Dependency graph visualization", ""]
    lines.append("The diagram highlights detected entry points, cycle participants, and highly depended-on modules.")
    if len(modules) <= 40 and len(graph.get("unique_edges", [])) <= 60:
        lines += ["", "```mermaid"]
        lines += render_mermaid(architecture).rstrip("\n").splitlines()
        lines += ["```"]
    else:
        lines += ["", "The full module graph is larger than the inline display limit. See [`architecture.mmd`](architecture.mmd) for the bounded module-level visualization."]
        pkg_diagram = render_package_mermaid(architecture)
        if pkg_diagram:
            lines += ["", "#### Package-level dependency overview", "", "```mermaid"]
            lines += pkg_diagram.rstrip("\n").splitlines()
            lines += ["```"]

    lines += ["", "### Dependency insights", ""]
    if metrics:
        lines += [
            f"- **Unique module dependencies:** {metrics.get('unique_dependency_edges', 0)}",
            f"- **Connected components:** {metrics.get('weakly_connected_components', 0)} "
            f"(largest: {metrics.get('largest_weak_component_size', 0)} modules)",
            f"- **Circular dependency groups:** {metrics.get('cyclic_components', 0)} "
            f"({metrics.get('modules_in_cycles', 0)} modules involved)",
            f"- **Isolated modules:** {metrics.get('isolated_modules', 0)}",
            f"- **Graph density:** {metrics.get('density', 0)}",
        ]
        reachable = metrics.get("reachable_from_entry_points")
        if reachable is not None:
            lines.append(f"- **Reachable from detected entry points:** {reachable}/{metrics.get('modules', 0)} modules")
        prod_metrics = metrics.get("production") or {}
        if prod_metrics:
            prod_reach = prod_metrics.get("reachable_from_entry_points")
            prod_reach_str = (
                f", reachable: {prod_reach}/{prod_metrics.get('modules', 0)}"
                if prod_reach is not None
                else ""
            )
            lines.append(
                f"- **Production subgraph only:** {prod_metrics.get('modules', 0)} modules, "
                f"{prod_metrics.get('unique_dependency_edges', 0)} edges, "
                f"{prod_metrics.get('cyclic_components', 0)} cycle groups, "
                f"{prod_metrics.get('isolated_modules', 0)} isolated{prod_reach_str}"
            )
        lines += ["", "**Most depended-on modules (production)**", ""]
        top_prod_in = prod_metrics.get("top_fan_in_modules", [])[:5]
        if top_prod_in:
            lines += [f"- `{item['path']}` — imported by {item['degree']} distinct production modules" for item in top_prod_in]
        else:
            top_in = metrics.get("top_fan_in_modules", [])[:5]
            lines += [f"- `{item['path']}` — imported by {item['degree']} distinct modules" for item in top_in] or ["- No module dependencies were resolved."]
        lines += ["", "**Modules with the most dependencies (production)**", ""]
        top_prod_out = prod_metrics.get("top_fan_out_modules", [])[:5]
        if top_prod_out:
            lines += [f"- `{item['path']}` — imports {item['degree']} distinct production modules" for item in top_prod_out]
        else:
            top_out = metrics.get("top_fan_out_modules", [])[:5]
            lines += [f"- `{item['path']}` — imports {item['degree']} distinct internal modules" for item in top_out] or ["- No module dependencies were resolved."]

    insights = graph.get("insights", [])
    if insights:
        lines += ["", "**Review recommendations**", ""]
        for insight in insights[:40]:
            subject = ", ".join(insight.get("modules") or insight.get("packages", []))
            lines.append(f"- **{insight['title']}** ({insight['severity']}): {insight['summary']}")
            if subject:
                lines.append(f"  - Affected: `{subject}`")
            if insight.get("evidence"):
                lines.append(f"  - Evidence: " + "; ".join(f"`{value}`" for value in insight["evidence"][:5]))
            lines.append(f"  - Suggested review: {insight['recommendation']}")
        if len(insights) > 40:
            lines.append(f"- _Only the first 40 of {len(insights)} insights are shown; see `report.json` for all._")
    else:
        lines.append("No graph-structure review flags were identified by the current heuristics.")

    lines += ["", "_Dependency insights are static heuristics based only on resolved imports. Unreachable or isolated modules may be tests, plugins, framework-discovered modules, or dynamic entry points._"]
    limits = architecture.get("limitations", [])
    if limits:
        lines += ["", "### Architecture-analysis limitations", ""] + [f"- {item}" for item in limits]
    return lines


def _health_section(summary):
    health = summary.get("repo_health")
    if not health:
        return []
    git = health.get("git", {})
    tests = health.get("tests", {})
    lines = ["", "## Repository health & test presence", ""]
    if git.get("is_git_repo"):
        commit = git.get("head_commit") or "unknown"
        branch = git.get("branch") or "unknown"
        date = git.get("last_commit_date") or "unknown"
        subdir_note = f"; subdir: `{git['subdir']}`" if git.get("subdir") else ""
        lines.append(f"- **Git HEAD:** `{branch}` @ `{commit}` (last commit: {date}{subdir_note})")
    else:
        lines.append("- **Git:** not a git repository")
    lic_type = health.get("license_type")
    lic_desc = f"yes ({lic_type})" if health.get("has_license") and lic_type else (
        f"no (manifest: {lic_type})" if lic_type else ("yes" if health.get("has_license") else "no")
    )
    lines.append(f"- **README / LICENSE:** README={'yes' if health.get('has_readme') else 'no'}, LICENSE={lic_desc}")
    if health.get("readme_summary"):
        clean_readme = health["readme_summary"].replace("`", "'")
        lines.append(f"- **README summary:** {clean_readme}")
    ci = health.get("ci_configs") or []
    lines.append(f"- **CI configs:** {', '.join(f'`{c}`' for c in ci) if ci else 'none detected'}")
    containers = health.get("container_files") or []
    lines.append(f"- **Container files:** {', '.join(f'`{c}`' for c in containers) if containers else 'none detected'}")
    frameworks = tests.get("frameworks") or []
    test_dirs = tests.get("test_directories") or []
    lines.append(
        f"- **Tests (read-only detection, not executed):** {tests.get('test_file_count', 0)} test file(s); "
        f"frameworks: {', '.join(f'`{fw}`' for fw in frameworks) if frameworks else 'none detected'}"
        + (f"; dirs: {', '.join(f'`{d}`' for d in test_dirs[:5])}" if test_dirs else "")
    )
    commands = health.get("commands") or []
    if commands:
        lines += ["", "### Discovered commands (read-only, not executed)", ""]
        for cmd in commands[:20]:
            cmd_text = cmd["command"].replace("`", "'")
            lines.append(f"- `{cmd['name']}` (`{cmd['source']}`): `{cmd_text}`")
        if len(commands) > 20:
            lines.append(f"\n_Showing first 20 of {len(commands)} discovered commands; see `report.json` for all._")
    env_vars = health.get("env_vars") or []
    if env_vars:
        lines += ["", f"### Environment variables & configuration surface ({len(env_vars)} detected; names only)", ""]
        for ev in env_vars[:25]:
            tpl_tag = " *(in .env template)*" if ev.get("defined_in_example") else ""
            srcs = ", ".join(f"`{s}`" for s in (ev.get("sources") or [])[:4])
            lines.append(f"- `{ev['name']}`{tpl_tag} — {srcs}")
        if len(env_vars) > 25:
            lines.append(f"\n_Showing first 25 of {len(env_vars)} detected environment variable names; see `report.json` for all._")
    hotspots = health.get("git_hotspots") or []
    hotspot_hubs = health.get("hotspot_hubs") or []
    if hotspots:
        lines += ["", "### Recent git change hotspots (last 180 days, up to 200 commits)", ""]
        for h in hotspots[:10]:
            lines.append(f"- `{h['path']}` — {h['commits']} commit(s) ({h['scope']})")
        if hotspot_hubs:
            lines += ["", "**High-churn production hubs (high fan-in + recent churn):**", ""]
            for hh in hotspot_hubs[:5]:
                lines.append(
                    f"- `{hh['path']}` — {hh['commits']} recent commit(s), imported by {hh['production_in_degree']} production module(s)"
                )
    elif health.get("git_hotspots_note") and health.get("git", {}).get("is_git_repo"):
        lines.append(f"- **Git change hotspots:** {health['git_hotspots_note']}")
    largest = health.get("largest_files") or []
    if largest:
        lines += ["", "### Largest files", ""]
        lines += [
            f"- `{item['path']}` — {item['lines']} lines ({item['language']}, {item['scope']})"
            for item in largest[:10]
        ]
    return lines


def _reading_order_section(summary):
    order = summary.get("reading_order") or []
    if not order:
        return []
    lines = ["", "## Where to start reading", ""]
    for idx, item in enumerate(order, 1):
        lines.append(f"{idx}. `{item['path']}` — {item['reason']}")
    return lines


def _directory_overview_section(summary):
    overview = summary.get("directory_overview") or []
    if not overview:
        return []
    lines = [
        "", "## Directory overview", "",
        "| Directory | Files | Lines | Primary language | Test files |",
        "|---|---:|---:|---|---:|",
    ]
    for item in overview[:20]:
        lines.append(
            f"| `{item['directory']}` | {item['files']} | {item['lines']} | "
            f"{item['primary_language']} | {item['test_files']} |"
        )
    if len(overview) > 20:
        lines.append(f"\n_Showing top 20 of {len(overview)} top-level directories by line count; see `report.json` for all._")
    return lines


def _truncation_and_skip_lines(result):
    s = result.get("summary", {})
    arch = result.get("architecture", {}).get("summary", {})
    skipped = s.get("skipped_counts") or {}
    notes = []
    if s.get("findings_truncated"):
        notes.append(
            f"**Findings truncated:** showing {s.get('findings_in_report', 0)} of "
            f"{s.get('heuristic_findings', 0)} total matches (cap: 2,000)."
        )
    if skipped.get("file_budget", 0) > 0:
        notes.append(
            f"**File budget reached:** {skipped['file_budget']} supported file(s) skipped after the file limit."
        )
    if arch.get("skipped_files_due_to_budget", 0) > 0:
        notes.append(
            f"**Architecture content budget reached:** {arch['skipped_files_due_to_budget']} file(s) excluded from import/graph mapping."
        )
    if s.get("python_ast_parse_errors", 0) > 0:
        notes.append(
            f"**Python AST parse errors:** {s['python_ast_parse_errors']} `.py` file(s) could not be parsed (e.g. Python 2 syntax or template files)."
        )
    nonzero_skips = {k: v for k, v in skipped.items() if v > 0}
    if nonzero_skips:
        breakdown = ", ".join(f"{k}: {v}" for k, v in nonzero_skips.items())
        notes.append(f"**Skipped files:** {breakdown}.")
    return notes


def build_compact_summary(result: dict) -> dict:
    """Build a bounded, context-safe summary JSON payload for AI agents and quick triage.

    Excludes bulky per-file, per-module, and per-import arrays while preserving all
    high-signal metrics, top prioritized findings, routes, models, dependencies,
    dependency-graph metrics/insights, and mandatory limitation disclosures.
    """
    summary = dict(result.get("summary") or {})
    # Trim top-level lists inside summary so huge repos stay compact.
    if isinstance(summary.get("directories"), list):
        summary["directories"] = summary["directories"][:40]
    if isinstance(summary.get("manifests"), list):
        summary["manifests"] = summary["manifests"][:60]
    if isinstance(summary.get("top_level_entries"), list):
        summary["top_level_entries"] = summary["top_level_entries"][:50]

    findings = result.get("findings") or []
    code_findings = [f for f in findings if f.get("id") != "TODO"]
    todo_findings = result.get("todos")
    if todo_findings is None:
        todo_findings = [f for f in findings if f.get("id") == "TODO"]
    prod_code = [f for f in code_findings if f.get("scope") == "production"]
    nonprod_code = [f for f in code_findings if f.get("scope") != "production"]

    arch = result.get("architecture") or {}
    dep_graph = arch.get("dependency_graph") or {}
    raw_metrics = dict(dep_graph.get("metrics") or {})
    # Replace potentially huge largest_components node lists with compact sizes + sample.
    largest_components = raw_metrics.pop("largest_components", None)
    if isinstance(largest_components, list):
        raw_metrics["largest_component_sizes"] = [len(c) for c in largest_components[:10]]
        raw_metrics["largest_component_sample"] = largest_components[0][:15] if largest_components else []

    compact_insights = []
    for ins in (dep_graph.get("insights") or [])[:30]:
        item = dict(ins)
        if isinstance(item.get("modules"), list) and len(item["modules"]) > 15:
            item["modules_total"] = len(item["modules"])
            item["modules"] = item["modules"][:15]
        if isinstance(item.get("evidence"), list) and len(item["evidence"]) > 10:
            item["evidence"] = item["evidence"][:10]
        compact_insights.append(item)

    return {
        "product": result.get("product"),
        "version": result.get("version"),
        "repository": result.get("repository"),
        "read_only": result.get("read_only", True),
        "artifacts": {
            "report_md": "report.md",
            "report_json": "report.json",
            "summary_json": "summary.json",
            "architecture_mmd": "architecture.mmd",
        },
        "summary": summary,
        "top_findings": {
            "total_in_report": len(findings),
            "code_findings_total": len(code_findings),
            "production_code_findings_total": len(prod_code),
            "non_production_code_findings_total": len(nonprod_code),
            "production": prod_code[:30],
            "non_production_sample": nonprod_code[:10],
            "todo_sample": todo_findings[:10],
        },
        "architecture": {
            "summary": arch.get("summary") or {},
            "entry_points": (arch.get("entry_points") or [])[:30],
            "routes": (arch.get("routes") or [])[:40],
            "models": (arch.get("models") or [])[:40],
            "api_specs": (arch.get("api_specs") or [])[:30],
            "dependencies": (arch.get("dependencies") or [])[:60],
            "dependency_graph": {
                "metrics": raw_metrics,
                "insights": compact_insights,
            },
            "limitations": arch.get("limitations") or [],
        },
    }


def write_reports(result, out_dir):
    out = Path(out_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    jp, mp = out / "report.json", out / "report.md"
    sp = out / "summary.json"
    graph_path = out / "architecture.mmd"
    jp.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    sp.write_text(json.dumps(build_compact_summary(result), indent=2, ensure_ascii=False), encoding="utf-8")
    s = result["summary"]
    prod_n = s.get("production_findings", s["heuristic_findings"])
    nonprod_n = s.get("non_production_findings", 0)
    sev = s.get("findings_by_severity") or {}
    sev_str = (
        f" — high: {sev.get('high', 0)}, medium: {sev.get('medium', 0)}, low: {sev.get('low', 0)}"
        if sev
        else ""
    )
    lines = ["# GitHub Repository Analyzer Report", "",
      f"- **Repository:** `{result['repository']}`", f"- **Read-only:** {result['read_only']}",
      f"- **Files analyzed:** {s['files_analyzed']}", f"- **Lines counted:** {s['total_lines']}",
      f"- **Heuristic findings:** {s['heuristic_findings']} (production: {prod_n}, test/example/docs: {nonprod_n}{sev_str})",
      f"- **TODO/FIXME markers:** {s['todo_markers']}", "",
      "> Findings are heuristic review targets, not confirmed vulnerabilities. Verify each item in context.", ""]
    coverage_notes = _truncation_and_skip_lines(result)
    if coverage_notes:
        lines += ["## Scan coverage & truncation disclosures", ""] + [f"- {n}" for n in coverage_notes] + [""]
    lines += ["## Language inventory", ""]
    lines += [f"- **{k}:** {v} file(s)" for k,v in s["languages"].items()] or ["No supported text files detected."]
    lines += _reading_order_section(s)
    lines += _directory_overview_section(s)
    lines += ["", "## Project manifests", ""] + [f"- `{x}`" for x in s["manifests"]]
    lines += _health_section(s)
    lines += _architecture_section(result)
    graph_path.write_text(render_mermaid(result.get("architecture", {})), encoding="utf-8")

    code_findings = [f for f in result["findings"] if f.get("id") != "TODO"]
    todo_findings = result.get("todos")
    if todo_findings is None:
        todo_findings = [f for f in result["findings"] if f.get("id") == "TODO"]

    lines += ["", "## Findings", ""]
    if code_findings:
        for i, f in enumerate(code_findings, 1):
            evidence = f["evidence"].replace("`", "'")
            scope = f.get("scope", "production")
            lines += [f"### {i}. [{f['id']}] {f['title']} — {f['severity'].upper()} ({scope})",
              f"- **Confidence:** {f['confidence']}", f"- **Scope:** {scope}",
              f"- **Location:** `{f['path']}:{f['line']}`",
              f"- **Status:** {f['status']}", f"- **Evidence:** `{evidence}`",
              f"- **Recommended review:** {f['recommendation']}", ""]
    else:
        lines.append("No configured code or secret patterns matched. This does not establish that the repository is bug-free.")
        lines.append("")

    if todo_findings:
        lines += [f"## TODO / FIXME markers ({s['todo_markers']} total)", ""]
        for f in todo_findings[:25]:
            evidence = f["evidence"].replace("`", "'")
            scope = f.get("scope", "production")
            lines.append(f"- `{f['path']}:{f['line']}` ({scope}) — `{evidence}`")
        if s["todo_markers"] > 25:
            lines.append(f"\n_Showing first 25 of {s['todo_markers']} TODO/FIXME markers; see `report.json` for full list._")
        lines.append("")

    lines += ["## Top-level entries", ""] + [f"- `{x}`" for x in s["top_level_entries"]]
    lines += ["", "## Limitations", ""] + [f"- {x}" for x in s["limitations"]]
    lines += ["", "## Suggested next steps", "",
      "1. Review high-severity findings in context.",
      "2. Run trusted tests and linters in an appropriate environment.",
      "3. Add language-specific static analysis for the detected stack.",
      "4. Verify authorization, input validation, error handling, and dependency practices.", ""]
    mp.write_text("\n".join(lines), encoding="utf-8")
    return mp, jp
