"""
Step 1: Dependency Tree Resolution
Extract top-level imports via AST, resolve full transitive graph via pipdeptree.
"""

import ast
import json
import subprocess
import sys
from pathlib import Path
from typing import Set, Dict, List, Any


def extract_imports_from_file(filepath: Path) -> Set[str]:
    """
    Parse Python file via AST and extract top-level import names.
    Returns package names (not module paths).
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(filepath))
    except SyntaxError as e:
        print(f"❌ Syntax error in {filepath}: {e}")
        return set()

    imports = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # import foo, bar.baz → extract 'foo', 'bar'
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                imports.add(top_level)

        elif isinstance(node, ast.ImportFrom):
            # from foo import bar → extract 'foo'
            if node.module:
                top_level = node.module.split(".")[0]
                imports.add(top_level)

    return imports


def get_pipdeptree_json() -> Dict[str, Any]:
    """
    Run pipdeptree --json and return parsed output.
    Installs pipdeptree if not present.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pipdeptree", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("⚠️  pipdeptree not found. Installing...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pipdeptree"],
            check=True,
        )
        # Retry
        result = subprocess.run(
            [sys.executable, "-m", "pipdeptree", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"❌ pipdeptree error: {e.stderr}")
        raise


def normalize_package_name(name: str) -> str:
    """Normalize package name for matching (underscores vs hyphens)."""
    return name.lower().replace("_", "-").replace(".", "-")


def build_dependency_tree(
    top_level_imports: Set[str], pipdeptree_json: List[Dict]
) -> Dict[str, Any]:
    """
    Build comprehensive dependency tree JSON.
    Maps AST-inferred imports to resolved packages and their transitive deps.
    """
    # Build lookup: normalized package name → full package info
    pkg_lookup = {}
    for pkg_info in pipdeptree_json:
        normalized = normalize_package_name(pkg_info["package"]["key"])
        pkg_lookup[normalized] = pkg_info

    # Identify which top-level imports are in the resolved tree
    resolved_top_level = {}
    for imp in top_level_imports:
        normalized = normalize_package_name(imp)
        if normalized in pkg_lookup:
            resolved_top_level[imp] = pkg_lookup[normalized]
        else:
            # Check if it's a builtin or standard library
            print(f"⚠️  Top-level import '{imp}' not found in installed packages (likely builtin or stdlib)")

    # Build tree structure
    tree = {
        "metadata": {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "total_packages": len(pipdeptree_json),
            "top_level_imports_detected": len(top_level_imports),
            "top_level_imports_resolved": len(resolved_top_level),
        },
        "top_level_imports": list(top_level_imports),
        "resolved_packages": {},
        "full_dependency_graph": pipdeptree_json,
    }

    # Build resolved packages section
    for imp_name, pkg_info in resolved_top_level.items():
        tree["resolved_packages"][imp_name] = {
            "package_name": pkg_info["package"]["package_name"],
            "key": pkg_info["package"]["key"],
            "version": pkg_info["package"]["installed_version"],
            "dependencies": [
                {
                    "name": dep["package_name"],
                    "key": dep["key"],
                    "installed_version": dep["installed_version"],
                }
                for dep in pkg_info["dependencies"]
            ],
            "dependency_count": len(pkg_info["dependencies"]),
        }

    return tree


def main():
    script_path = Path("image_recognition_basic.py")
    output_dir = Path("artifacts")

    print("=" * 70)
    print("Step 1: Dependency Tree Resolution")
    print("=" * 70)

    # Step 1a: AST parsing
    print(f"\n📍 Step 1a: Parsing imports from {script_path}...")
    if not script_path.exists():
        print(f"❌ Script not found: {script_path}")
        sys.exit(1)

    top_level = extract_imports_from_file(script_path)
    print(f"✅ Found {len(top_level)} top-level imports: {sorted(top_level)}")

    # Step 1b: pipdeptree resolution
    print(f"\n📍 Step 1b: Resolving full dependency tree via pipdeptree...")
    pipdeptree_data = get_pipdeptree_json()
    print(f"✅ Resolved {len(pipdeptree_data)} installed packages")

    # Step 1c: Build machine-readable graph
    print(f"\n📍 Step 1c: Building machine-readable dependency tree...")
    dep_tree = build_dependency_tree(top_level, pipdeptree_data)

    # Output: JSON
    output_dir.mkdir(exist_ok=True)
    json_output = output_dir / "dep_tree.json"
    with open(json_output, "w", encoding="utf-8") as f:
        json.dump(dep_tree, f, indent=2)
    print(f"✅ Saved JSON: {json_output}")

    # Output: Text summary
    txt_output = output_dir / "dep_tree.txt"
    with open(txt_output, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write("Dependency Tree Summary\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Python Version: {dep_tree['metadata']['python_version']}\n")
        f.write(f"Total Installed Packages: {dep_tree['metadata']['total_packages']}\n")
        f.write(f"Top-Level Imports (AST): {dep_tree['metadata']['top_level_imports_detected']}\n")
        f.write(f"Resolved to Packages: {dep_tree['metadata']['top_level_imports_resolved']}\n\n")

        f.write("Top-Level Imports:\n")
        for imp in sorted(top_level):
            f.write(f"  • {imp}\n")

        f.write("\nResolved Packages (with transitive deps):\n")
        for imp_name in sorted(dep_tree["resolved_packages"].keys()):
            pkg = dep_tree["resolved_packages"][imp_name]
            f.write(
                f"\n  {imp_name}\n"
                f"    Package: {pkg['package_name']} ({pkg['version']})\n"
                f"    Dependencies: {pkg['dependency_count']}\n"
            )
            for dep in pkg["dependencies"][:5]:  # Show first 5
                f.write(f"      → {dep['name']} ({dep['installed_version']})\n")
            if pkg["dependency_count"] > 5:
                f.write(f"      ... +{pkg['dependency_count'] - 5} more\n")

    print(f"✅ Saved text summary: {txt_output}")

    print(f"\n{'=' * 70}")
    print("Step 1 Complete ✅")
    print(f"{'=' * 70}\n")
    print(f"Artifacts:")
    print(f"  • {json_output}")
    print(f"  • {txt_output}")


if __name__ == "__main__":
    main()
