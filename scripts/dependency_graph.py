"""Graph metrics, dependency insights, and Mermaid rendering.

This module consumes already-resolved static import edges. It does not execute
repository code and does not infer dependencies that the import mapper missed.
"""
from __future__ import annotations

from collections import defaultdict, deque
from html import escape
import math
from pathlib import PurePosixPath
from typing import Iterable


def _strongly_connected_components(
    nodes: Iterable[str], adjacency: dict[str, set[str]]
) -> list[list[str]]:
    """Return deterministic SCCs using iterative Kosaraju (safe for deep graphs)."""
    ordered_nodes = sorted(set(nodes))
    visited: set[str] = set()
    finish_order: list[str] = []

    for start in ordered_nodes:
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, object]] = [(start, iter(sorted(adjacency.get(start, set()))))]
        while stack:
            node, children = stack[-1]
            try:
                child = next(children)  # type: ignore[arg-type]
            except StopIteration:
                finish_order.append(node)
                stack.pop()
                continue
            if child not in visited:
                visited.add(child)
                stack.append((child, iter(sorted(adjacency.get(child, set())))))

    reverse: dict[str, set[str]] = {node: set() for node in ordered_nodes}
    for source in ordered_nodes:
        for target in adjacency.get(source, set()):
            reverse.setdefault(target, set()).add(source)

    assigned: set[str] = set()
    components: list[list[str]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: list[str] = []
        stack = [start]
        assigned.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for child in sorted(reverse.get(node, set()), reverse=True):
                if child not in assigned:
                    assigned.add(child)
                    stack.append(child)
        components.append(sorted(component))
    return sorted(components, key=lambda group: (group[0], len(group)))


def _weak_components(nodes: Iterable[str], adjacency: dict[str, set[str]]) -> list[list[str]]:
    reverse: dict[str, set[str]] = defaultdict(set)
    for source, targets in adjacency.items():
        for target in targets:
            reverse[target].add(source)
    undirected: dict[str, set[str]] = {node: set(adjacency.get(node, set())) for node in nodes}
    for node, parents in reverse.items():
        undirected.setdefault(node, set()).update(parents)
    remaining = set(undirected)
    result: list[list[str]] = []
    while remaining:
        start = min(remaining)
        remaining.remove(start)
        queue = deque([start])
        component = []
        while queue:
            node = queue.popleft()
            component.append(node)
            for child in sorted(undirected.get(node, set())):
                if child in remaining:
                    remaining.remove(child)
                    queue.append(child)
        result.append(sorted(component))
    return sorted(result, key=lambda group: (-len(group), group[0]))


def _package_name(path: str) -> str:
    parts = PurePosixPath(path).parts
    return parts[0] if len(parts) > 1 else "(root)"


_CONTAINER_ROOTS = {"src", "lib", "pkg", "packages", "apps", "services", "internal", "cmd", "modules"}


def _diagram_package_name(path: str) -> str:
    """Group path into a readable package label for high-level Mermaid diagrams."""
    parts = PurePosixPath(path).parts
    if len(parts) <= 1:
        return "(root)"
    if parts[0].lower() in _CONTAINER_ROOTS and len(parts) > 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


_TEST_SCOPE_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testing", "fixtures", "testdata"}
_NONPROD_SCOPE_DIRS = _TEST_SCOPE_DIRS | {
    "example", "examples", "sample", "samples", "demo", "demos", "benchmark", "benchmarks",
    "doc", "docs", "documentation",
}


def _module_scope(path: str) -> str:
    p = PurePosixPath(path)
    dir_parts = {part.lower() for part in p.parts[:-1]}
    name = p.name.lower()
    stem = p.stem.lower()
    if (
        dir_parts & _TEST_SCOPE_DIRS
        or name == "conftest.py"
        or name.startswith("test_")
        or stem.endswith("_test")
        or ".test." in name
        or ".spec." in name
    ):
        return "test"
    if dir_parts & {"example", "examples", "sample", "samples", "demo", "demos", "benchmark", "benchmarks"}:
        return "example"
    if dir_parts & {"doc", "docs", "documentation"}:
        return "docs"
    return "production"


def _is_nonprod_path(path: str) -> bool:
    return _module_scope(path) != "production"


def analyze_dependency_graph(
    modules: list[dict], imports: list[dict], entry_points: list[dict]
) -> dict:
    """Compute dependency graph metrics and cautious architecture review insights."""
    nodes = sorted({module["path"] for module in modules})
    node_set = set(nodes)
    adjacency: dict[str, set[str]] = {node: set() for node in nodes}
    reverse: dict[str, set[str]] = {node: set() for node in nodes}
    import_occurrences: dict[tuple[str, str], int] = defaultdict(int)
    for edge in imports:
        source, target = edge.get("source"), edge.get("target")
        if edge.get("classification") != "internal" or source not in node_set or target not in node_set:
            continue
        adjacency[source].add(target)
        reverse[target].add(source)
        import_occurrences[(source, target)] += 1

    unique_edges = sorted((source, target) for source in nodes for target in adjacency[source])
    sccs = _strongly_connected_components(nodes, adjacency)
    cyclic_components = [component for component in sccs
                         if len(component) > 1 or component[0] in adjacency.get(component[0], set())]
    weak = _weak_components(nodes, adjacency) if nodes else []

    entry_nodes = sorted({entry.get("path") for entry in entry_points} & node_set)
    reachable: set[str] = set()
    queue = deque(entry_nodes)
    while queue:
        node = queue.popleft()
        if node in reachable:
            continue
        reachable.add(node)
        queue.extend(sorted(adjacency[node] - reachable))

    # Compute production-only subgraph metrics so test/example imports don't skew coupling or reachability.
    prod_nodes = sorted(path for path in nodes if _module_scope(path) == "production")
    prod_node_set = set(prod_nodes)
    prod_adjacency: dict[str, set[str]] = {
        node: (adjacency[node] & prod_node_set) for node in prod_nodes
    }
    prod_reverse: dict[str, set[str]] = {
        node: (reverse[node] & prod_node_set) for node in prod_nodes
    }
    prod_unique_edges = sorted(
        (source, target) for source in prod_nodes for target in prod_adjacency[source]
    )
    prod_sccs = _strongly_connected_components(prod_nodes, prod_adjacency)
    prod_cyclic = [
        comp for comp in prod_sccs
        if len(comp) > 1 or comp[0] in prod_adjacency.get(comp[0], set())
    ]
    prod_entry_nodes = sorted(set(entry_nodes) & prod_node_set)
    prod_reachable: set[str] = set()
    prod_queue = deque(prod_entry_nodes)
    while prod_queue:
        node = prod_queue.popleft()
        if node in prod_reachable:
            continue
        prod_reachable.add(node)
        prod_queue.extend(sorted(prod_adjacency[node] - prod_reachable))
    prod_isolated = sorted(
        path for path in prod_nodes if not prod_adjacency[path] and not prod_reverse[path]
    )

    module_records = []
    for module in modules:
        path = module["path"]
        indegree = len(reverse[path])
        outdegree = len(adjacency[path])
        scope = _module_scope(path)
        record = dict(module)
        record.update({
            "scope": scope,
            "in_degree": indegree,
            "out_degree": outdegree,
            "production_in_degree": len(prod_reverse[path]) if path in prod_node_set else 0,
            "production_out_degree": len(prod_adjacency[path]) if path in prod_node_set else 0,
            "is_isolated": indegree == 0 and outdegree == 0,
            "reachable_from_entry_point": path in reachable if entry_nodes else None,
        })
        module_records.append(record)

    n = len(nodes)
    m = len(unique_edges)
    in_threshold = max(3, math.ceil(math.sqrt(max(1, n))))
    out_threshold = max(3, math.ceil(math.sqrt(max(1, n))))
    insights: list[dict] = []

    for index, component in enumerate(cyclic_components, 1):
        self_loop = len(component) == 1
        evidence = [f"{source} -> {target}" for source, target in unique_edges
                    if source in component and target in component]
        insights.append({
            "id": f"CYCLE-{index:03d}", "category": "circular_dependency",
            "severity": "medium", "title": "Circular module dependency",
            "summary": (f"{component[0]} imports itself." if self_loop else
                        f"{len(component)} modules form a mutually reachable dependency group."),
            "modules": component, "evidence": evidence[:30],
            "recommendation": "Review whether the modules can depend on a lower-level shared module or use an interface to break the cycle.",
        })

    for package_group in _strongly_connected_components(
        sorted({_package_name(node) for node in nodes}),
        _package_adjacency(nodes, unique_edges),
    ):
        if len(package_group) > 1:
            package_edges = [f"{a} -> {b}" for a, b in _package_edges(nodes, unique_edges)
                             if a in package_group and b in package_group]
            insights.append({
                "id": f"PACKAGE-CYCLE-{len(insights) + 1:03d}",
                "category": "package_dependency_cycle", "severity": "medium",
                "title": "Cross-package dependency cycle",
                "summary": "Top-level packages depend on one another in a cycle: " + ", ".join(package_group),
                "modules": [], "packages": package_group, "evidence": package_edges[:30],
                "recommendation": "Review package boundaries and consider moving shared contracts or utilities into a lower-level package.",
            })

    for module in sorted(module_records, key=lambda item: (-item["in_degree"], item["path"])):
        if module["in_degree"] >= in_threshold:
            insights.append({
                "id": f"FAN-IN-{len(insights) + 1:03d}", "category": "high_fan_in",
                "severity": "info", "title": "Highly depended-on module",
                "summary": f"{module['path']} is imported by {module['in_degree']} distinct modules.",
                "modules": [module["path"]], "evidence": sorted(reverse[module["path"]])[:30],
                "recommendation": "Treat this module as a high-impact change point; keep its public interfaces stable and test dependent modules.",
            })

    for module in sorted(module_records, key=lambda item: (-item["out_degree"], item["path"])):
        if module["out_degree"] >= out_threshold:
            insights.append({
                "id": f"FAN-OUT-{len(insights) + 1:03d}", "category": "high_fan_out",
                "severity": "low", "title": "High-dependency module",
                "summary": f"{module['path']} depends on {module['out_degree']} distinct internal modules.",
                "modules": [module["path"]], "evidence": sorted(adjacency[module["path"]])[:30],
                "recommendation": "Review whether this module has too many responsibilities or could depend on narrower interfaces.",
            })

    isolated = sorted(path for path in nodes if not adjacency[path] and not reverse[path])
    if isolated:
        isolated_prioritized = sorted(isolated, key=lambda p: (0 if p in prod_node_set else 1, p))
        isolated_prod_count = sum(1 for p in isolated if p in prod_node_set)
        insights.append({
            "id": f"ISOLATED-{len(insights) + 1:03d}", "category": "isolated_modules",
            "severity": "info", "title": "Modules with no resolved internal imports",
            "summary": (
                f"{len(isolated)} modules ({isolated_prod_count} production, "
                f"{len(isolated) - isolated_prod_count} non-production) have no incoming or outgoing "
                f"resolved internal dependency edges."
            ),
            "production_count": isolated_prod_count,
            "modules": isolated_prioritized[:100], "evidence": [],
            "recommendation": "Check whether these are independent entry points, tests, plugins, dynamically loaded modules, or files missed by the import resolver; isolation alone does not mean dead code.",
        })

    if entry_nodes:
        unreachable = sorted(node_set - reachable)
        if unreachable:
            unreachable_prioritized = sorted(unreachable, key=lambda p: (0 if p in prod_node_set else 1, p))
            unreachable_prod_count = sum(1 for p in unreachable if p in prod_node_set)
            insights.append({
                "id": f"UNREACHABLE-{len(insights) + 1:03d}", "category": "not_reachable_from_entry_points",
                "severity": "low", "title": "Modules not reached from detected entry points",
                "summary": (
                    f"{len(unreachable)} modules ({unreachable_prod_count} production, "
                    f"{len(unreachable) - unreachable_prod_count} non-production) are not reachable by "
                    f"following resolved imports from detected entry points."
                ),
                "production_count": unreachable_prod_count,
                "modules": unreachable_prioritized[:100], "evidence": [],
                "recommendation": "Check whether these modules are tests, plugins, framework-discovered modules, library APIs, or possible unused code; entry-point detection and import resolution are heuristic.",
            })

    # Show the most central modules even when they do not cross the alert threshold.
    top_in = sorted(module_records, key=lambda item: (-item["in_degree"], item["path"]))[:10]
    top_out = sorted(module_records, key=lambda item: (-item["out_degree"], item["path"]))[:10]
    prod_records = [item for item in module_records if item["scope"] == "production"]
    top_prod_in = sorted(prod_records, key=lambda item: (-item["production_in_degree"], item["path"]))[:10]
    top_prod_out = sorted(prod_records, key=lambda item: (-item["production_out_degree"], item["path"]))[:10]
    package_edges = _package_edges(nodes, unique_edges)
    package_adjacency = _package_adjacency(nodes, unique_edges)
    package_nodes = sorted({_package_name(node) for node in nodes})
    package_components = _strongly_connected_components(package_nodes, package_adjacency) if package_nodes else []

    density = (m / (n * (n - 1))) if n > 1 else 0.0
    metrics = {
        "modules": n,
        "unique_dependency_edges": m,
        "import_statements_resolved": sum(import_occurrences.values()),
        "weakly_connected_components": len(weak),
        "largest_weak_component_size": len(weak[0]) if weak else 0,
        "strongly_connected_components": len(sccs),
        "cyclic_components": len(cyclic_components),
        "modules_in_cycles": len({node for group in cyclic_components for node in group}),
        "isolated_modules": len(isolated),
        "detected_entry_points": len(entry_nodes),
        "reachable_from_entry_points": len(reachable) if entry_nodes else None,
        "not_reachable_from_entry_points": (n - len(reachable)) if entry_nodes else None,
        "average_in_degree": round(sum(len(reverse[node]) for node in nodes) / n, 3) if n else 0.0,
        "average_out_degree": round(sum(len(adjacency[node]) for node in nodes) / n, 3) if n else 0.0,
        "density": round(density, 5),
        "package_count": len(package_nodes),
        "package_dependency_edges": len(package_edges),
        "package_dependency_cycles": sum(1 for group in package_components if len(group) > 1),
        "fan_in_alert_threshold": in_threshold,
        "fan_out_alert_threshold": out_threshold,
        "top_fan_in_modules": [{"path": item["path"], "degree": item["in_degree"]} for item in top_in],
        "top_fan_out_modules": [{"path": item["path"], "degree": item["out_degree"]} for item in top_out],
        "largest_components": [group for group in weak[:10]],
        "production": {
            "modules": len(prod_nodes),
            "unique_dependency_edges": len(prod_unique_edges),
            "cyclic_components": len(prod_cyclic),
            "modules_in_cycles": len({node for group in prod_cyclic for node in group}),
            "isolated_modules": len(prod_isolated),
            "detected_entry_points": len(prod_entry_nodes),
            "reachable_from_entry_points": len(prod_reachable) if prod_entry_nodes else None,
            "not_reachable_from_entry_points": (len(prod_nodes) - len(prod_reachable)) if prod_entry_nodes else None,
            "top_fan_in_modules": [
                {"path": item["path"], "degree": item["production_in_degree"]} for item in top_prod_in
            ],
            "top_fan_out_modules": [
                {"path": item["path"], "degree": item["production_out_degree"]} for item in top_prod_out
            ],
        },
    }
    return {
        "modules": sorted(module_records, key=lambda item: item["path"]),
        "metrics": metrics,
        "insights": insights,
        "unique_edges": [{"source": source, "target": target,
                          "import_occurrences": import_occurrences[(source, target)]}
                         for source, target in unique_edges],
    }


def _package_edges(nodes: list[str], edges: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return sorted({(_package_name(source), _package_name(target))
                   for source, target in edges if _package_name(source) != _package_name(target)})


def _package_adjacency(nodes: list[str], edges: list[tuple[str, str]]) -> dict[str, set[str]]:
    packages = {_package_name(node) for node in nodes}
    adjacency = {package: set() for package in packages}
    for source, target in _package_edges(nodes, edges):
        adjacency[source].add(target)
    return adjacency


def _mermaid_label(text: str) -> str:
    # HTML escaping avoids Mermaid token injection from unusual repository paths.
    return (escape(text, quote=True).replace("&#x27;", "&#39;").replace("&quot;", "'")
            .replace("[", "&#91;").replace("]", "&#93;").replace("|", "&#124;")
            .replace("\n", " ").replace("\r", " "))


def render_mermaid(architecture: dict, max_nodes: int = 200, max_edges: int = 400) -> str:
    """Render a safe, bounded Mermaid dependency graph.

    When a repository exceeds max_nodes, prioritizes production entry points,
    cycle participants, and high-centrality modules over alphabetical truncation.
    """
    modules = architecture.get("modules", [])
    edges = architecture.get("dependency_graph", {}).get("unique_edges", [])
    entry_paths = {entry.get("path") for entry in architecture.get("entry_points", [])}
    cyclic_paths = {path for insight in architecture.get("dependency_graph", {}).get("insights", [])
                    if insight.get("category") == "circular_dependency"
                    for path in insight.get("modules", [])}
    graph_metrics = architecture.get("dependency_graph", {}).get("metrics", {})
    hub_paths = {item.get("path") for item in graph_metrics.get("top_fan_in_modules", [])
                 if item.get("degree", 0) >= graph_metrics.get("fan_in_alert_threshold", 3)}
    fanout_paths = {item.get("path") for item in graph_metrics.get("top_fan_out_modules", [])
                    if item.get("degree", 0) >= graph_metrics.get("fan_out_alert_threshold", 3)}
    isolated_paths = {module.get("path") for module in modules
                      if module.get("is_isolated") is True}

    prioritized = len(modules) > max_nodes
    if prioritized:
        def _priority_key(mod: dict) -> tuple:
            path = mod.get("path", "")
            nonprod = 1 if _is_nonprod_path(path) else 0
            in_deg = int(mod.get("in_degree", 0) or 0)
            out_deg = int(mod.get("out_degree", 0) or 0)
            important = 0 if (path in entry_paths or path in cyclic_paths or path in hub_paths or path in fanout_paths) else 1
            isolated = 1 if (in_deg == 0 and out_deg == 0) else 0
            return (nonprod, important, isolated, -(in_deg + out_deg), -in_deg, path)

        selected = sorted(sorted(modules, key=_priority_key)[:max_nodes], key=lambda m: m.get("path", ""))
    else:
        selected = sorted(modules, key=lambda module: module.get("path", ""))

    selected_paths = {module["path"] for module in selected}
    matching_edges = [edge for edge in edges
                      if edge.get("source") in selected_paths and edge.get("target") in selected_paths]
    visible_edges = matching_edges[:max_edges]
    ids = {module["path"]: f"m{index:04d}" for index, module in enumerate(selected)}

    lines = ["%% GitHub Repository Analyzer module dependency graph", "flowchart LR"]
    for module in selected:
        path = module["path"]
        lines.append(f'  {ids[path]}["{_mermaid_label(path)}"]')
    for edge in visible_edges:
        lines.append(f"  {ids[edge['source']]} --> {ids[edge['target']]}")
    lines.extend([
        "  classDef entry fill:#dbeafe,stroke:#2563eb,stroke-width:2px",
        "  classDef cycle fill:#fee2e2,stroke:#dc2626,stroke-width:2px",
        "  classDef hub fill:#fef3c7,stroke:#d97706,stroke-width:2px",
        "  classDef fanout fill:#ede9fe,stroke:#7c3aed,stroke-width:2px",
        "  classDef isolated fill:#f3f4f6,stroke:#6b7280,stroke-dasharray: 4 3",
    ])
    for paths, class_name in ((entry_paths, "entry"), (cyclic_paths, "cycle"),
                              (hub_paths, "hub"), (fanout_paths, "fanout"),
                              (isolated_paths, "isolated")):
        matching = [ids[path] for path in sorted(paths) if path in ids]
        if matching:
            lines.append(f"  class {','.join(matching)} {class_name}")
    if prioritized:
        lines.insert(
            1,
            f"%% Truncated: showing {len(selected)} of {len(modules)} modules "
            f"(prioritized by production scope, entry points, cycles, and centrality)",
        )
    if len(visible_edges) < len(matching_edges):
        lines.insert(1, f"%% Truncated: showing {len(visible_edges)} of {len(matching_edges)} dependency edges")
    if not visible_edges:
        lines.append("  %% No resolved internal dependency edges")
    return "\n".join(lines) + "\n"


def render_package_mermaid(
    architecture: dict, max_packages: int = 35, max_edges: int = 80
) -> str | None:
    """Render a high-level package/directory Mermaid diagram for large repositories.

    Returns None if there are no inter-package dependency edges to visualize.
    """
    modules = architecture.get("modules", [])
    edges = architecture.get("dependency_graph", {}).get("unique_edges", [])
    entry_paths = {entry.get("path") for entry in architecture.get("entry_points", [])}

    pkg_counts: dict[str, int] = defaultdict(int)
    entry_pkgs: set[str] = set()
    for mod in modules:
        path = mod.get("path", "")
        pkg = _diagram_package_name(path)
        pkg_counts[pkg] += 1
        if path in entry_paths:
            entry_pkgs.add(pkg)

    pkg_edge_weights: dict[tuple[str, str], int] = defaultdict(int)
    for edge in edges:
        src = _diagram_package_name(edge.get("source", ""))
        dst = _diagram_package_name(edge.get("target", ""))
        if src and dst and src != dst:
            pkg_edge_weights[(src, dst)] += 1

    if not pkg_edge_weights:
        return None

    connected_pkgs: set[str] = set()
    pkg_degree: dict[str, int] = defaultdict(int)
    for (src, dst), weight in pkg_edge_weights.items():
        connected_pkgs.add(src)
        connected_pkgs.add(dst)
        pkg_degree[src] += weight
        pkg_degree[dst] += weight

    ordered_pkgs = sorted(
        connected_pkgs,
        key=lambda p: (1 if _is_nonprod_path(f"{p}/x.py") else 0, -pkg_degree[p], -pkg_counts[p], p),
    )
    selected_pkgs = sorted(ordered_pkgs[:max_packages])
    selected_set = set(selected_pkgs)

    visible_edges = sorted(
        (
            (src, dst, weight)
            for (src, dst), weight in pkg_edge_weights.items()
            if src in selected_set and dst in selected_set
        ),
        key=lambda item: (-item[2], item[0], item[1]),
    )[:max_edges]

    pkg_adj: dict[str, set[str]] = {pkg: set() for pkg in selected_pkgs}
    for src, dst, _w in visible_edges:
        pkg_adj[src].add(dst)
    cyclic_pkgs = {
        pkg
        for group in _strongly_connected_components(selected_pkgs, pkg_adj)
        if len(group) > 1
        for pkg in group
    }

    ids = {pkg: f"p{idx:03d}" for idx, pkg in enumerate(selected_pkgs)}
    lines = ["%% Package-level dependency overview", "flowchart LR"]
    if len(connected_pkgs) > len(selected_pkgs):
        lines.append(f"%% Truncated: showing {len(selected_pkgs)} of {len(connected_pkgs)} connected packages")
    for pkg in selected_pkgs:
        count = pkg_counts.get(pkg, 0)
        lines.append(f'  {ids[pkg]}["{_mermaid_label(pkg)} ({count})"]')
    for src, dst, weight in sorted(visible_edges, key=lambda item: (item[0], item[1])):
        if weight > 1:
            lines.append(f"  {ids[src]} -->|{weight}| {ids[dst]}")
        else:
            lines.append(f"  {ids[src]} --> {ids[dst]}")
    lines.extend([
        "  classDef entry fill:#dbeafe,stroke:#2563eb,stroke-width:2px",
        "  classDef cycle fill:#fee2e2,stroke:#dc2626,stroke-width:2px",
    ])
    for pkgs, cls in ((entry_pkgs, "entry"), (cyclic_pkgs, "cycle")):
        matching = [ids[p] for p in sorted(pkgs) if p in ids]
        if matching:
            lines.append(f"  class {','.join(matching)} {cls}")
    return "\n".join(lines) + "\n"
