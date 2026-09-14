# ML/DL Program Security Pipeline

A comprehensive security analysis pipeline for Python-based Machine Learning and Deep Learning programs.

## Project Overview

This research project implements a repeatable "ML program security pipeline" that provides:

1. **Dependency Tree Analysis** — Full transitive dependency graph resolution
2. **Vulnerability Scanning** — CVE/OSV database checks for known vulnerabilities  
3. **SBOM Generation** — CycloneDX + optional SPDX output
4. **Integrity & Provenance Verification** — Hashes, index URLs, wheel signatures
5. **Static Code Analysis** — Bandit/Ruff/Semgrep checks + runtime containment policies
6. **Binary Component Extraction** — Native libraries from TensorFlow/Keras/NumPy for deeper analysis

## Project Structure

```
InventoryDependencyTree/
├── src/                          # Main package source
│   └── security_scanner/         # Core library (to be developed)
├── configs/                      # Tool configuration files
│   ├── bandit.yaml              # Static security scanning rules
│   ├── pip-audit.toml           # Vulnerability scanner config
│   └── ...                       # Additional tool configs
├── artifacts/                    # Output directory (gitignored)
│   ├── dep_tree.json            # Full dependency graph
│   ├── vulns_pip_audit.json     # Vulnerability findings
│   ├── sbom.cdx.json            # CycloneDX SBOM
│   ├── integrity_report.json    # Hashes & provenance
│   ├── static_report.json       # Code analysis findings
│   └── wheelhouse/              # Extracted binaries
├── tests/                        # Test suite
├── image_recognition_basic.py   # Example ML program (test target)
├── requirements.in               # Auditable, direct dependency inputs
├── requirements-lock.txt         # Hash-verified, resolved dependency closure
├── requirements.txt              # Compatibility alias for the lockfile
├── pyproject.toml               # Project metadata + tool config
└── README.md                     # This file
```

## Environment Setup

### Prerequisites
- CPython 3.12.10 on Windows x86_64
- A new virtual environment; do not reuse an unrelated environment

### Install Dependencies

```bash
# Create and activate the recorded baseline (Windows PowerShell)
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install only the hash-verified dependency closure
python -m pip install --require-hashes -r requirements-lock.txt

# Confirm dependency metadata is internally consistent
python -m pip check
```

## Step 0: Deterministic Resolution Foundation

The foundation is a **fully resolved, hash-verified environment** for one declared platform baseline:

- **`requirements.in`** — the auditable list of direct application and pipeline dependencies
- **`requirements-lock.txt`** — the complete transitive closure, pinned to exact versions and protected by SHA-256 hashes
- **CPython 3.12.10 / Windows x86_64** — the exact, tested interpreter and platform baseline
- **`--require-hashes` installation** — `pip` rejects artifacts that do not match a lockfile hash
- **`pip check` validation** — confirms installed package metadata has no unsatisfied requirements

This gives the vulnerability, SBOM, integrity, static-analysis, and binary-extraction stages the same dependency identities on every clean installation of this baseline. The lock is intentionally a Windows/CPython 3.12.10 baseline; a separate lock must be generated and validated for each additional platform or Python version.

### Updating the Baseline

Dependency updates are deliberate changes to `requirements.in`. Regenerate the lock with CPython 3.12.10 and `pip-tools`, review the resulting diff, then validate it before committing:

```powershell
.\.venv\Scripts\python.exe -m pip install pip-tools==7.5.3
.\.venv\Scripts\pip-compile.exe --generate-hashes --allow-unsafe --strip-extras --output-file requirements-lock.txt requirements.in
.\.venv\Scripts\python.exe -m pip install --dry-run --require-hashes -r requirements-lock.txt
```

## Next Steps

1. **Step 1** — Dependency tree resolution (dep_tree.json)
2. **Step 2** — Vulnerability scanning (pip-audit + OSV)
3. **Step 3** — SBOM generation (CycloneDX)
4. **Step 4** — Integrity & provenance checks
5. **Step 5** — Static code analysis + runtime policy
6. **Step 6** — Binary extraction (TF/Keras/NumPy native libs)

## Configuration Files

- **`pyproject.toml`** — Project metadata, dependencies, tool settings
- **`configs/bandit.yaml`** — Bandit (SAST) configuration
- **`configs/pip-audit.toml`** — pip-audit (vulnerability scanner) config
- **`.gitignore`** — Excludes `.venv/`, `artifacts/`, `__pycache__/`, etc.

## Example: Running Against a Test Program

```bash
# Test with the included example
python image_recognition_basic.py

# (Future) Run full security pipeline on it
python -m security_scanner image_recognition_basic.py --output-dir artifacts/
```

## License

MIT (Assumed for research project)

## References

- [CycloneDX](https://cyclonedx.org/)
- [SPDX](https://spdx.dev/)
- [pip-audit](https://github.com/pypa/pip-audit)
- [Bandit](https://bandit.readthedocs.io/)
- [OSV](https://osv.dev/)
