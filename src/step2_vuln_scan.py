"""
Step 2: Vulnerability scanning
Option A: pip-audit
Option B: OSV scan (use osv-scanner if available; fallback to OSV API queries)

Outputs:
- artifacts/vulns_pip_audit.json
- artifacts/vulns_osv.json
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / "requirements-lock.txt"
ARTIFACTS = ROOT / "artifacts"
PIP_AUDIT_OUT = ARTIFACTS / "vulns_pip_audit.json"
OSV_OUT = ARTIFACTS / "vulns_osv.json"


def parse_pinned_requirements(lockfile: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []

    for line in lockfile.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "==" not in s:
            continue

        name, version = s.split("==", 1)
        name = name.strip()
        version = version.strip()

        if not name or not version:
            continue

        packages.append({"name": name, "version": version})

    return packages


def run_pip_audit(lockfile: Path, output_file: Path) -> dict[str, Any]:
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Install pip-audit if missing
    try:
        subprocess.run(
            [sys.executable, "-m", "pip_audit", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pip-audit"],
            check=True,
        )

    # pip-audit exits non-zero when vulns are found, so don't fail on return code.
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            str(lockfile),
            "-f",
            "json",
            "-o",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    status = "completed"
    if result.returncode not in (0, 1):
        status = "error"

    report: dict[str, Any] = {
        "status": status,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_file": str(output_file),
    }

    return report


def run_osv_scanner_if_available(lockfile: Path, output_file: Path) -> dict[str, Any] | None:
    if shutil.which("osv-scanner") is None:
        return None

    result = subprocess.run(
        [
            "osv-scanner",
            "--lockfile",
            str(lockfile),
            "--format",
            "json",
            "--output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    status = "completed" if result.returncode == 0 else "error"
    return {
        "method": "osv-scanner-cli",
        "status": status,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_file": str(output_file),
    }


def run_osv_api_scan(packages: list[dict[str, str]], output_file: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for pkg in packages:
        payload = {
            "package": {
                "name": pkg["name"],
                "ecosystem": "PyPI",
            },
            "version": pkg["version"],
        }

        try:
            resp = requests.post(
                "https://api.osv.dev/v1/query",
                json=payload,
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            errors.append(
                {
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "error": str(exc),
                }
            )
            continue

        vulns = data.get("vulns", [])
        if vulns:
            findings.append(
                {
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "vulnerabilities": vulns,
                    "count": len(vulns),
                }
            )

    report = {
        "method": "osv-api",
        "scanned_packages": len(packages),
        "packages_with_findings": len(findings),
        "findings": findings,
        "errors": errors,
    }

    output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def summarize_counts(pip_audit_file: Path, osv_file: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "pip_audit_packages_with_vulns": None,
        "osv_packages_with_vulns": None,
        "osv_total_vuln_records": None,
    }

    try:
        pip_data = json.loads(pip_audit_file.read_text(encoding="utf-8"))
        deps = pip_data.get("dependencies", [])
        vuln_packages = 0
        for dep in deps:
            if dep.get("vulns"):
                vuln_packages += 1
        summary["pip_audit_packages_with_vulns"] = vuln_packages
    except Exception:
        pass

    try:
        osv_data = json.loads(osv_file.read_text(encoding="utf-8"))
        findings = osv_data.get("findings", [])
        summary["osv_packages_with_vulns"] = len(findings)
        total_records = 0
        for f in findings:
            total_records += int(f.get("count", 0))
        summary["osv_total_vuln_records"] = total_records
    except Exception:
        pass

    return summary


def main() -> None:
    if not LOCKFILE.exists():
        raise SystemExit(f"Lockfile missing: {LOCKFILE}")

    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("Step 2: Vulnerability Scanning")
    print("=" * 70)
    print(f"Using lockfile: {LOCKFILE}")

    # Option A: pip-audit
    print("\n[Option A] Running pip-audit against pinned lockfile...")
    pip_result = run_pip_audit(LOCKFILE, PIP_AUDIT_OUT)
    print(f"pip-audit status: {pip_result['status']} (rc={pip_result['return_code']})")
    print(f"pip-audit output: {PIP_AUDIT_OUT}")

    # Option B: OSV
    print("\n[Option B] Running OSV scan against pinned versions...")
    osv_cli_result = run_osv_scanner_if_available(LOCKFILE, OSV_OUT)

    if osv_cli_result is not None:
        print(f"osv-scanner status: {osv_cli_result['status']} (rc={osv_cli_result['return_code']})")
        print(f"osv-scanner output: {OSV_OUT}")
        osv_method = "osv-scanner-cli"
    else:
        packages = parse_pinned_requirements(LOCKFILE)
        osv_api_result = run_osv_api_scan(packages, OSV_OUT)
        print(
            "OSV CLI not found; used OSV API fallback. "
            f"Packages scanned: {osv_api_result['scanned_packages']}"
        )
        print(f"OSV output: {OSV_OUT}")
        osv_method = "osv-api"

    summary = summarize_counts(PIP_AUDIT_OUT, OSV_OUT)

    combined = {
        "lockfile": str(LOCKFILE),
        "pip_audit": pip_result,
        "osv_method": osv_method,
        "summary": summary,
    }

    combined_file = ARTIFACTS / "vuln_scan_summary.json"
    combined_file.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    print("\n" + "=" * 70)
    print("Step 2 Complete")
    print("=" * 70)
    print("Artifacts:")
    print(f"- {PIP_AUDIT_OUT}")
    print(f"- {OSV_OUT}")
    print(f"- {combined_file}")


if __name__ == "__main__":
    main()
