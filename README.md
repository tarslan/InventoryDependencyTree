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
├── requirements-lock.txt         # Fully resolved dependencies (platform-specific)
├── requirements.txt              # Main dependencies (generated from freeze)
├── pyproject.toml               # Project metadata + tool config
└── README.md                     # This file
```

## Environment Setup

### Prerequisites
- Python 3.12+ 
- Virtual environment (included: `.venv/`)

### Install Dependencies

```bash
# Activate virtual environment (Windows)
.\.venv\Scripts\Activate.ps1

# Or (Unix/macOS)
source .venv/bin/activate

# Install from lock file (reproducible)
pip install -r requirements-lock.txt
```

## Step 0: Deterministic Resolution

The foundation of the pipeline is a **fully resolved, pinned environment**:

- **`requirements-lock.txt`** — All 165 transitive dependencies pinned to exact versions
- **Python 3.12.10** — Isolated virtual environment
- **Platform-aware** — Windows wheels (win_amd64); use `pip-compile` or `uv` for cross-platform locks

This ensures vulnerability scanners (OSV, pip-audit) have complete version information.

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
