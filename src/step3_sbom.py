"""
Step 3: SBOM generation
- Primary output: CycloneDX JSON (sbom.cdx.json)
- Optional output: SPDX JSON (sbom.spdx.json) when a converter is available

Artifacts:
- artifacts/sbom.cdx.json
- artifacts/sbom.spdx.json (optional)
- artifacts/sbom_summary.json
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / "requirements-lock.txt"
ARTIFACTS = ROOT / "artifacts"
CDX_FILE = ARTIFACTS / "sbom.cdx.json"
SPDX_FILE = ARTIFACTS / "sbom.spdx.json"
SUMMARY_FILE = ARTIFACTS / "sbom_summary.json"


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_pip_audit() -> None:
    check = run_cmd([sys.executable, "-m", "pip_audit", "--version"])
    if check.returncode == 0:
        return

    install = run_cmd([sys.executable, "-m", "pip", "install", "pip-audit"])
    if install.returncode != 0:
        raise RuntimeError(f"Failed to install pip-audit: {install.stderr}")


def generate_cyclonedx(lockfile: Path, output_file: Path) -> dict[str, Any]:
    # Preferred path: pip-audit native CycloneDX output
    ensure_pip_audit()

    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(lockfile),
        "-f",
        "cyclonedx-json",
        "-o",
        str(output_file),
    ]
    res = run_cmd(cmd)

    if res.returncode != 0:
        return {
            "status": "error",
            "method": "pip-audit-cyclonedx",
            "return_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }

    return {
        "status": "completed",
        "method": "pip-audit-cyclonedx",
        "return_code": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "output_file": str(output_file),
    }


def try_convert_cdx_to_spdx(cdx_file: Path, spdx_file: Path) -> dict[str, Any]:
    # Optional path only. If no converter exists, report skipped.
    if shutil.which("cyclonedx") is None:
        return {
            "status": "skipped",
            "reason": "cyclonedx converter CLI not found",
        }

    cmd = [
        "cyclonedx",
        "convert",
        "--input-file",
        str(cdx_file),
        "--output-file",
        str(spdx_file),
        "--output-format",
        "spdxjson",
    ]
    res = run_cmd(cmd)

    if res.returncode != 0:
        return {
            "status": "error",
            "return_code": res.returncode,
            "stdout": res.stdout,
            "stderr": res.stderr,
        }

    return {
        "status": "completed",
        "output_file": str(spdx_file),
        "return_code": res.returncode,
    }


def count_components_in_cdx(cdx_file: Path) -> int | None:
    try:
        data = json.loads(cdx_file.read_text(encoding="utf-8"))
        components = data.get("components", [])
        return len(components)
    except Exception:
        return None


def main() -> None:
    if not LOCKFILE.exists():
        raise SystemExit(f"Lockfile missing: {LOCKFILE}")

    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("Step 3: SBOM Generation")
    print("=" * 70)
    print(f"Using lockfile: {LOCKFILE}")

    print("\nGenerating CycloneDX SBOM...")
    cdx_result = generate_cyclonedx(LOCKFILE, CDX_FILE)
    if cdx_result["status"] != "completed":
        raise SystemExit(
            "CycloneDX generation failed.\n"
            f"stderr: {cdx_result.get('stderr', '')}\n"
            f"stdout: {cdx_result.get('stdout', '')}"
        )

    print(f"CycloneDX SBOM written: {CDX_FILE}")

    print("\nAttempting optional SPDX conversion...")
    spdx_result = try_convert_cdx_to_spdx(CDX_FILE, SPDX_FILE)
    if spdx_result["status"] == "completed":
        print(f"SPDX SBOM written: {SPDX_FILE}")
    else:
        print(f"SPDX generation: {spdx_result['status']}")
        if "reason" in spdx_result:
            print(f"Reason: {spdx_result['reason']}")

    component_count = count_components_in_cdx(CDX_FILE)

    summary = {
        "lockfile": str(LOCKFILE),
        "cyclonedx": cdx_result,
        "spdx": spdx_result,
        "cyclonedx_component_count": component_count,
        "artifacts": {
            "cyclonedx": str(CDX_FILE),
            "spdx": str(SPDX_FILE) if SPDX_FILE.exists() else None,
        },
    }

    SUMMARY_FILE.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 70)
    print("Step 3 Complete")
    print("=" * 70)
    print(f"Artifacts:\n- {CDX_FILE}\n- {SUMMARY_FILE}")
    if SPDX_FILE.exists():
        print(f"- {SPDX_FILE}")


if __name__ == "__main__":
    main()
