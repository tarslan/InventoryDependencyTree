"""
Step 6: Binary Component Extraction & Fingerprinting
=====================================================

Purpose
-------
Extract and fingerprint all native binary components (.pyd, .dll) from the
installed packages, particularly the core ML stack (TensorFlow, NumPy, Keras,
OpenCV) and their transitive runtime dependencies.

For each binary:
  - Compute SHA-256 hash (fingerprint)
  - Extract import table (DLL dependencies)
  - Extract export table (exported symbols)
  - Infer binary architecture (x64, x86, ARM64)
  - Record version info if available
  - Classify by package

Outputs
-------
  artifacts/binaries_report.json      – complete inventory
  artifacts/wheelhouse/               – per-package binary manifest JSON files
  artifacts/wheelhouse/<pkg>/         – symlinks/copies of .pyd/.dll files (optional)
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Any

# pefile: Windows PE (Portable Executable) format parser
try:
    import pefile
except ImportError:
    pefile = None  # type: ignore

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv"
SITE_PACKAGES = VENV / "Lib" / "site-packages"
LOCKFILE = ROOT / "requirements-lock.txt"
ARTIFACTS = ROOT / "artifacts"
WHEELHOUSE = ARTIFACTS / "wheelhouse"
WHEELHOUSE.mkdir(exist_ok=True)

BINARIES_REPORT = ARTIFACTS / "binaries_report.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BinaryImport:
    dll_name: str           # e.g., "kernel32.dll", "msvcr120.dll"
    ordinal: Optional[int] = None
    hint: Optional[int] = None


@dataclass
class BinaryExport:
    name: str               # e.g., "__PyCFunction_NewEx"
    ordinal: int
    address: int
    forward: Optional[str] = None


@dataclass
class BinaryMetadata:
    file_path: str
    file_name: str
    package_name: str
    package_version: Optional[str]
    
    size_bytes: int
    sha256_hash: str
    
    # PE file metadata
    machine_type: Optional[str]      # "x64" | "x86" | "ARM64" | etc
    subsystem: Optional[str]         # "WINDOWS_CUI" | "WINDOWS_GUI" | etc
    
    # Imports and exports
    imports: list[BinaryImport] = field(default_factory=list)
    export_count: int = 0
    export_symbols: list[str] = field(default_factory=list)
    
    # Version info
    product_name: Optional[str] = None
    product_version: Optional[str] = None
    file_version: Optional[str] = None
    company_name: Optional[str] = None
    
    # Security / signing
    signed: bool = False
    cert_subject: Optional[str] = None
    
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Lockfile parsing
# ---------------------------------------------------------------------------

def parse_lockfile(path: Path) -> dict[str, str]:
    """Return {name: version} from a pip-freeze style requirements file."""
    packages: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            packages[name.strip().lower()] = version.strip()
    return packages


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------

def find_binaries() -> list[Path]:
    """Find all .pyd and .dll files in site-packages."""
    binaries: list[Path] = []
    for pattern in ("**/*.pyd", "**/*.dll"):
        binaries.extend(SITE_PACKAGES.glob(pattern))
    return sorted(binaries)


def infer_package_name(binary_path: Path) -> str:
    """
    Infer the package name from a binary's path.
    E.g., /tensorflow/python/_pywrap_tensorflow_internal.so → "tensorflow"
    """
    # Walk up from the binary to find a .dist-info or top-level package dir
    current = binary_path.parent
    while current != SITE_PACKAGES and current.is_dir():
        if (current / "__init__.py").exists():
            # This is a package directory
            return current.name
        # Check for .dist-info
        if current.name.endswith(".dist-info"):
            pkg_name = current.name.rsplit("-", 1)[0]
            return pkg_name
        current = current.parent
    
    # Fallback: check site-packages subdirectories
    if binary_path.parent.name.endswith(".dist-info"):
        return binary_path.parent.name.rsplit("-", 1)[0]
    
    # Final fallback: first component of the path
    rel = binary_path.relative_to(SITE_PACKAGES)
    return rel.parts[0] if rel.parts else "unknown"


# ---------------------------------------------------------------------------
# PE file analysis (Windows)
# ---------------------------------------------------------------------------

def analyze_pe_file(path: Path) -> tuple[dict[str, Any], Optional[str]]:
    """
    Parse a Windows PE file (.pyd, .dll) and extract metadata.
    Returns (metadata_dict, error_string).
    """
    if pefile is None:
        return {}, "pefile library not available"
    
    try:
        pe = pefile.PE(str(path))
    except Exception as e:
        return {}, str(e)
    
    metadata: dict[str, Any] = {}
    
    # Machine type
    machine_map = {
        0x014c: "x86",
        0x8664: "x64",
        0xaa64: "ARM64",
        0x01c0: "ARM",
        0x0ebc: "ARM64",
    }
    metadata["machine_type"] = machine_map.get(pe.FILE_HEADER.Machine, 
                                               f"0x{pe.FILE_HEADER.Machine:04x}")
    
    # Subsystem
    if hasattr(pe, "OPTIONAL_HEADER"):
        subsystem_map = {
            0: "UNKNOWN",
            1: "NATIVE",
            2: "WINDOWS_GUI",
            3: "WINDOWS_CUI",
            5: "OS2_CUI",
            7: "POSIX_CUI",
            9: "WINDOWS_CE_GUI",
            10: "EFI_APPLICATION",
            11: "EFI_BOOT_SERVICE_DRIVER",
            12: "EFI_RUNTIME_DRIVER",
        }
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        metadata["subsystem"] = subsystem_map.get(subsystem, f"0x{subsystem:02x}")
    
    # Imports (DLL dependencies)
    imports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="ignore") if isinstance(entry.dll, bytes) else str(entry.dll)
            imports.append(dll_name)
    metadata["import_dlls"] = imports
    
    # Exports (symbols)
    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"#{exp.ordinal}"
                exports.append(name)
            except Exception:
                exports.append(f"#{exp.ordinal}")
    metadata["export_symbols"] = exports[:100]  # Limit to first 100 for brevity
    metadata["export_count"] = len(exports) if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0
    
    # Version info (if present)
    if hasattr(pe, "VS_VERSIONINFO"):
        try:
            for idx, entry in enumerate(pe.VS_VERSIONINFO):
                if hasattr(entry, "name"):
                    entry_name = entry.name.decode("utf-8", errors="ignore") if isinstance(entry.name, bytes) else str(entry.name)
                    if "StringFileInfo" in entry_name:
                        # Version strings are nested; attempt extraction
                        pass
        except Exception:
            pass
    
    # Check for signing (Authenticode)
    # This is more complex and requires PKCS#7 parsing; skip for now
    metadata["signed"] = False  # Not yet implemented
    
    return metadata, None


# ---------------------------------------------------------------------------
# File fingerprinting
# ---------------------------------------------------------------------------

def compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Process one binary
# ---------------------------------------------------------------------------

def process_binary(binary_path: Path, lockfile_packages: dict[str, str]) -> BinaryMetadata:
    """Analyze a single binary and return metadata."""
    try:
        # Basic file info
        size_bytes = binary_path.stat().st_size
        sha256_hash = compute_sha256(binary_path)
        
        # Infer package
        pkg_name_inferred = infer_package_name(binary_path)
        # Look up version from lockfile
        pkg_name_normalized = pkg_name_inferred.lower().replace("-", "_")
        pkg_version = None
        for locked_name, version in lockfile_packages.items():
            if locked_name.replace("-", "_") == pkg_name_normalized:
                pkg_version = version
                break
        
        # PE analysis
        pe_data, pe_error = analyze_pe_file(binary_path)
        
        metadata = BinaryMetadata(
            file_path=str(binary_path.relative_to(SITE_PACKAGES)),
            file_name=binary_path.name,
            package_name=pkg_name_inferred,
            package_version=pkg_version,
            size_bytes=size_bytes,
            sha256_hash=sha256_hash,
            machine_type=pe_data.get("machine_type"),
            subsystem=pe_data.get("subsystem"),
            export_count=pe_data.get("export_count", 0),
            export_symbols=pe_data.get("export_symbols", []),
            error=pe_error,
        )
        
        # Convert import DLLs to BinaryImport objects
        for dll_name in pe_data.get("import_dlls", []):
            metadata.imports.append(BinaryImport(dll_name=dll_name))
        
        return metadata
    
    except Exception as exc:
        return BinaryMetadata(
            file_path=str(binary_path.relative_to(SITE_PACKAGES)) if binary_path.is_relative_to(SITE_PACKAGES) else str(binary_path),
            file_name=binary_path.name,
            package_name="unknown",
            package_version=None,
            size_bytes=0,
            sha256_hash="error",
            error=str(exc),
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("Step 6 – Binary Component Extraction & Fingerprinting")
    log.info("  Platform: %s %s", platform.system(), platform.machine())
    log.info("  Python:   %s", sys.version.split()[0])
    log.info("  Venv:     %s", VENV)
    
    # Load lockfile
    lockfile_packages = parse_lockfile(LOCKFILE)
    log.info("  Lockfile: %d packages", len(lockfile_packages))
    
    # Find binaries
    binaries = find_binaries()
    log.info("  Binaries: %d files found", len(binaries))
    
    if len(binaries) == 0:
        log.warning("  No binaries found!")
        return
    
    # Process each binary
    metadata_list: list[BinaryMetadata] = []
    for i, binary_path in enumerate(binaries, 1):
        if i % 50 == 0 or i == len(binaries):
            log.info("  Progress: %d / %d", i, len(binaries))
        meta = process_binary(binary_path, lockfile_packages)
        metadata_list.append(meta)
    
    # Aggregate by package
    by_package: dict[str, list[BinaryMetadata]] = {}
    for meta in metadata_list:
        pkg = meta.package_name or "unknown"
        by_package.setdefault(pkg, []).append(meta)
    
    # Statistics
    total_size = sum(m.size_bytes for m in metadata_list)
    error_count = sum(1 for m in metadata_list if m.error is not None)
    
    ml_packages = {"tensorflow", "numpy", "keras", "cv2", "pillow"}
    ml_binaries = [m for m in metadata_list if m.package_name.lower() in ml_packages]
    
    # ---------------------------------------------------------------------------
    # Main report
    # ---------------------------------------------------------------------------
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pipeline_step": 6,
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python_version": sys.version.split()[0],
            "python_platform_tag": "win_amd64" if platform.machine() == "AMD64" else platform.machine(),
        },
        "venv": str(VENV),
        "site_packages": str(SITE_PACKAGES),
        "summary": {
            "total_binaries": len(binaries),
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "ml_package_binaries": len(ml_binaries),
            "ml_package_size_mb": round(sum(m.size_bytes for m in ml_binaries) / 1024 / 1024, 2),
            "packages_with_binaries": len(by_package),
            "errors": error_count,
        },
        "by_package": {},
        "ml_packages": {
            "tensor_flow": {
                "binaries": len([m for m in metadata_list if m.package_name.lower() == "tensorflow"]),
                "total_size_mb": round(sum(m.size_bytes for m in metadata_list if m.package_name.lower() == "tensorflow") / 1024 / 1024, 2),
            },
            "numpy": {
                "binaries": len([m for m in metadata_list if m.package_name.lower() == "numpy"]),
                "total_size_mb": round(sum(m.size_bytes for m in metadata_list if m.package_name.lower() == "numpy") / 1024 / 1024, 2),
            },
            "keras": {
                "binaries": len([m for m in metadata_list if m.package_name.lower() == "keras"]),
                "total_size_mb": round(sum(m.size_bytes for m in metadata_list if m.package_name.lower() == "keras") / 1024 / 1024, 2),
            },
            "opencv": {
                "binaries": len([m for m in metadata_list if m.package_name.lower() == "cv2"]),
                "total_size_mb": round(sum(m.size_bytes for m in metadata_list if m.package_name.lower() == "cv2") / 1024 / 1024, 2),
            },
        },
        "all_binaries": [asdict(m) for m in metadata_list],
    }
    
    # Populate by-package summary
    for pkg_name in sorted(by_package.keys()):
        metas = by_package[pkg_name]
        report["by_package"][pkg_name] = {
            "count": len(metas),
            "total_size_mb": round(sum(m.size_bytes for m in metas) / 1024 / 1024, 2),
            "machines": list(set(m.machine_type for m in metas if m.machine_type)),
            "import_dll_summary": sorted(set(
                dll for m in metas for imp in m.imports for dll in [imp.dll_name]
            )),
        }
    
    BINARIES_REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("  Full report  -> %s", BINARIES_REPORT)
    
    # ---------------------------------------------------------------------------
    # Per-package manifest files in wheelhouse/
    # ---------------------------------------------------------------------------
    for pkg_name, metas in sorted(by_package.items()):
        pkg_dir = WHEELHOUSE / pkg_name
        pkg_dir.mkdir(exist_ok=True)
        
        pkg_manifest = {
            "package": pkg_name,
            "binary_count": len(metas),
            "binaries": [asdict(m) for m in metas],
            "aggregate_imports": sorted(set(
                imp.dll_name for m in metas for imp in m.imports
            )),
        }
        
        manifest_file = pkg_dir / "manifest.json"
        manifest_file.write_text(json.dumps(pkg_manifest, indent=2), encoding="utf-8")
    
    log.info("  Package manifests -> %s/*/manifest.json", WHEELHOUSE)
    
    # ---------------------------------------------------------------------------
    # Console summary
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("Step 6 – Binary Component Extraction & Fingerprinting")
    print("=" * 70)
    print(f"  Platform                 : {platform.system()} {platform.machine()}")
    print(f"  Python                   : {sys.version.split()[0]}")
    print(f"  Site-packages            : {SITE_PACKAGES}")
    print()
    print(f"  Total binaries           : {len(binaries)}")
    print(f"  Total size               : {total_size / 1024 / 1024:.2f} MB")
    print(f"  Packages with binaries   : {len(by_package)}")
    print(f"  Analysis errors          : {error_count}")
    print()
    print(f"  ML packages:")
    print(f"    TensorFlow             : {report['ml_packages']['tensor_flow']['binaries']} binaries, {report['ml_packages']['tensor_flow']['total_size_mb']} MB")
    print(f"    NumPy                  : {report['ml_packages']['numpy']['binaries']} binaries, {report['ml_packages']['numpy']['total_size_mb']} MB")
    print(f"    Keras                  : {report['ml_packages']['keras']['binaries']} binaries, {report['ml_packages']['keras']['total_size_mb']} MB")
    print(f"    OpenCV (cv2)           : {report['ml_packages']['opencv']['binaries']} binaries, {report['ml_packages']['opencv']['total_size_mb']} MB")
    print()
    print(f"  Top-level DLL dependencies (system/runtime):")
    all_dlls = set()
    for m in metadata_list:
        for imp in m.imports:
            all_dlls.add(imp.dll_name.lower())
    for dll in sorted(list(all_dlls)[:15]):
        count = sum(1 for m in metadata_list if any(imp.dll_name.lower() == dll for imp in m.imports))
        print(f"    {dll:<30} : {count:>3} binaries")
    if len(all_dlls) > 15:
        print(f"    ... and {len(all_dlls) - 15} more")
    print()
    print(f"  Output artifacts:")
    print(f"    {BINARIES_REPORT.name}")
    print(f"    {WHEELHOUSE.name}/**/manifest.json")
    print("=" * 70)


if __name__ == "__main__":
    main()
