"""
Step 5: Static Code Analysis + Runtime Containment Policy
==========================================================

Sub-steps
---------
  5A  Bandit  – Python SAST (CWE-mapped security rules)
  5B  Ruff    – Linter with security-relevant rules (E, W, S series)
  5C  Semgrep – Custom rule set from configs/.semgrep.yml (if CLI available)
  5D  ML-AST  – Custom AST checks targeting ML-specific risks
                (non-determinism, unsafe model I/O, unbounded data loading,
                 GPU/CPU resource limits, random seed hygiene)
  5E  Runtime – Derive a runtime containment policy from the static findings
                (filesystem, network, process, resource constraints)

Target file : image_recognition_basic.py

Outputs
-------
  artifacts/static_report.json    – findings from 5A–5D, structured by tool
  artifacts/runtime_policy.json   – 5E containment controls derived from findings
"""

from __future__ import annotations

import ast
import json
import logging
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "image_recognition_basic.py"
BANDIT_CFG = ROOT / "configs" / "bandit.yaml"
SEMGREP_CFG = ROOT / "configs" / ".semgrep.yml"
ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)

STATIC_REPORT = ARTIFACTS / "static_report.json"
RUNTIME_POLICY = ARTIFACTS / "runtime_policy.json"

PYTHON = Path(sys.executable)

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 5A  Bandit
# ---------------------------------------------------------------------------

def run_bandit() -> dict:
    """Run bandit -f json against the target file using our config."""
    log.info("  [5A] Running Bandit …")
    cmd = [
        str(PYTHON), "-m", "bandit",
        "-f", "json",
        "-c", str(BANDIT_CFG),
        str(TARGET),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # bandit exits 1 when findings exist – that is expected
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "tool": "bandit",
            "status": "error",
            "error": result.stderr[:500] or result.stdout[:500],
            "findings": [],
        }

    findings = []
    for issue in data.get("results", []):
        findings.append({
            "tool": "bandit",
            "rule_id": issue.get("test_id"),
            "rule_name": issue.get("test_name"),
            "severity": issue.get("issue_severity", "").upper(),
            "confidence": issue.get("issue_confidence", "").upper(),
            "cwe": issue.get("issue_cwe", {}).get("id"),
            "message": issue.get("issue_text"),
            "file": Path(issue.get("filename", "")).name,
            "line": issue.get("line_number"),
            "code_snippet": issue.get("code", "").strip(),
        })

    metrics = data.get("metrics", {}).get(str(TARGET), {})
    return {
        "tool": "bandit",
        "status": "completed",
        "target": str(TARGET.name),
        "config": str(BANDIT_CFG.name),
        "findings_count": len(findings),
        "severity_counts": {
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "metrics": {
            "loc": metrics.get("loc", 0),
            "nosec": metrics.get("nosec", 0),
            "skipped_tests": metrics.get("skipped_tests", 0),
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# 5B  Ruff
# ---------------------------------------------------------------------------

# Ruff rule prefixes with security relevance
RUFF_SECURITY_PREFIXES = ("S", "B", "E711", "E712", "T20", "PTH", "ANN")

def run_ruff() -> dict:
    """Run ruff check with security-relevant rule sets."""
    log.info("  [5B] Running Ruff …")
    cmd = [
        str(PYTHON), "-m", "ruff", "check",
        "--select", "S,B,E,W,T20",  # S=flake8-bandit, B=flake8-bugbear, E/W=pycodestyle
        "--output-format", "json",
        str(TARGET),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return {
            "tool": "ruff",
            "status": "error",
            "error": result.stderr[:500],
            "findings": [],
        }

    findings = []
    for item in data:
        code = item.get("code", "")
        message = item.get("message", "")
        loc = item.get("location", {})
        findings.append({
            "tool": "ruff",
            "rule_id": code,
            "severity": _ruff_severity(code),
            "message": message,
            "file": Path(item.get("filename", "")).name,
            "line": loc.get("row"),
            "col": loc.get("column"),
        })

    return {
        "tool": "ruff",
        "status": "completed",
        "target": str(TARGET.name),
        "findings_count": len(findings),
        "severity_counts": {
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
            "INFO": sum(1 for f in findings if f["severity"] == "INFO"),
        },
        "findings": findings,
    }


def _ruff_severity(code: str) -> str:
    if code.startswith("S"):
        # flake8-bandit codes – map high-risk ones
        high = {"S301", "S302", "S307", "S102", "S506"}
        if code in high:
            return "HIGH"
        return "MEDIUM"
    if code.startswith("B"):
        return "MEDIUM"
    return "INFO"


# ---------------------------------------------------------------------------
# 5C  Semgrep
# ---------------------------------------------------------------------------

def run_semgrep() -> dict:
    """Run semgrep with the custom ML rule set if CLI is available."""
    log.info("  [5C] Checking for Semgrep CLI …")
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin is None:
        log.info("        Semgrep CLI not found – skipping (install: pip install semgrep)")
        return {
            "tool": "semgrep",
            "status": "skipped",
            "reason": "semgrep CLI not found in PATH",
            "findings": [],
        }

    log.info("  [5C] Running Semgrep …")
    cmd = [
        semgrep_bin,
        "--config", str(SEMGREP_CFG),
        "--json",
        str(TARGET),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "tool": "semgrep",
            "status": "error",
            "error": result.stderr[:500],
            "findings": [],
        }

    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append({
            "tool": "semgrep",
            "rule_id": r.get("check_id"),
            "severity": extra.get("severity", "WARNING").upper(),
            "message": extra.get("message", ""),
            "file": Path(r.get("path", "")).name,
            "line": r.get("start", {}).get("line"),
            "code_snippet": extra.get("lines", "").strip(),
        })

    return {
        "tool": "semgrep",
        "status": "completed",
        "target": str(TARGET.name),
        "config": str(SEMGREP_CFG.name),
        "findings_count": len(findings),
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# 5D  ML-AST custom checks
# ---------------------------------------------------------------------------

@dataclass
class MLFinding:
    check_id: str
    severity: str       # HIGH | MEDIUM | LOW | INFO
    category: str       # determinism | model_io | data_loading | resource | dependency
    message: str
    line: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""


def run_ml_ast_checks() -> dict:
    """
    Custom AST-based checks for ML-specific security and reproducibility risks.

    Checks performed:
      ML-001  Missing random seed (non-deterministic model training)
      ML-002  np.random.choice / shuffle without seed (non-determinism)
      ML-003  model.save() path is hardcoded (no integrity hash stored)
      ML-004  model.load_model() / load_weights() without hash verification
      ML-005  keras.datasets / tf.data without explicit shuffle buffer size cap
      ML-006  TF/Keras mixed precision or XLA flags not set (reproducibility)
      ML-007  Unbounded model.fit() epochs (resource exhaustion)
      ML-008  model.predict() on unsanitized external input shape
      ML-009  No input validation / clipping before predict (adversarial risk)
      ML-010  os.environ GPU memory growth not configured (OOM risk)
    """
    log.info("  [5D] Running ML-AST custom checks …")
    source = TARGET.read_text(encoding="utf-8")
    lines = source.splitlines()

    try:
        tree = ast.parse(source, filename=str(TARGET))
    except SyntaxError as exc:
        return {
            "tool": "ml_ast",
            "status": "error",
            "error": str(exc),
            "findings": [],
        }

    findings: list[MLFinding] = []

    # ---- helper: collect all call nodes ----
    all_calls: list[ast.Call] = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]

    def get_line(node: ast.AST) -> Optional[int]:
        return getattr(node, "lineno", None)

    def snippet(lineno: Optional[int]) -> Optional[str]:
        if lineno and 1 <= lineno <= len(lines):
            return lines[lineno - 1].strip()
        return None

    def call_name(node: ast.Call) -> str:
        """Return dotted name string for a Call node."""
        func = node.func
        if isinstance(func, ast.Attribute):
            parts = []
            cur: ast.expr = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        if isinstance(func, ast.Name):
            return func.id
        return ""

    # ---- ML-001: Missing random seed ----
    seed_calls = {
        "tf.random.set_seed", "np.random.seed", "random.seed",
        "keras.utils.set_random_seed", "tensorflow.random.set_seed",
    }
    found_seed = any(call_name(c) in seed_calls for c in all_calls)
    if not found_seed:
        findings.append(MLFinding(
            check_id="ML-001",
            severity="MEDIUM",
            category="determinism",
            message=(
                "No global random seed detected. Model training is non-deterministic "
                "across runs, making reproducibility and audit trails unreliable."
            ),
            recommendation=(
                "Add `tf.random.set_seed(42)` and `np.random.seed(42)` "
                "near the top of main() before any data loading."
            ),
        ))

    # ---- ML-002: np.random.choice / shuffle without seed ----
    rand_ops = {"np.random.choice", "np.random.shuffle", "np.random.permutation"}
    for call in all_calls:
        name = call_name(call)
        if name in rand_ops:
            findings.append(MLFinding(
                check_id="ML-002",
                severity="LOW",
                category="determinism",
                message=f"`{name}` called without a seeded RandomGenerator.",
                line=get_line(call),
                code_snippet=snippet(get_line(call)),
                recommendation=(
                    "Pass a `np.random.default_rng(seed)` generator or call "
                    "`np.random.seed()` before this line."
                ),
            ))

    # ---- ML-003: model.save() without hash record ----
    save_calls = {"model.save", "keras.Model.save"}
    for call in all_calls:
        name = call_name(call)
        if name.endswith(".save"):
            # Check if save path arg is followed by any hash computation
            lineno = get_line(call)
            # Heuristic: look for hashlib in entire file
            if "hashlib" not in source and "sha256" not in source.lower():
                findings.append(MLFinding(
                    check_id="ML-003",
                    severity="MEDIUM",
                    category="model_io",
                    message=(
                        f"`{name}()` saves the model but no SHA-256 hash of the "
                        "output file is computed or stored. An attacker or corrupt "
                        "filesystem could silently replace the saved model."
                    ),
                    line=lineno,
                    code_snippet=snippet(lineno),
                    recommendation=(
                        "After saving, compute `hashlib.sha256(open(path,'rb').read()).hexdigest()` "
                        "and record it alongside the model file."
                    ),
                ))

    # ---- ML-004: model load without hash verification ----
    load_patterns = {"load_model", "load_weights", "from_pretrained",
                     "tf.saved_model.load", "keras.models.load_model"}
    for call in all_calls:
        name = call_name(call)
        if any(name.endswith(p) or p in name for p in load_patterns):
            if "hashlib" not in source and "sha256" not in source.lower():
                findings.append(MLFinding(
                    check_id="ML-004",
                    severity="HIGH",
                    category="model_io",
                    message=(
                        f"`{name}()` loads a model/weights without verifying a "
                        "cryptographic hash first. A supply-chain or filesystem "
                        "attacker could inject a backdoored model."
                    ),
                    line=get_line(call),
                    code_snippet=snippet(get_line(call)),
                    recommendation=(
                        "Store the expected SHA-256 hash of the model file in a "
                        "config or environment variable and verify it with "
                        "hashlib before loading."
                    ),
                ))

    # ---- ML-005: keras.datasets load without size cap ----
    dataset_loads = {"keras.datasets", "tf.data", "load_data"}
    dataset_found = False
    for call in all_calls:
        name = call_name(call)
        if "load_data" in name or "keras.datasets" in name:
            dataset_found = True
            # Check for slicing / take() near the call
            lineno = get_line(call)
            if lineno:
                context = "\n".join(lines[max(0, lineno - 2):lineno + 5])
                if ".take(" not in context and "[:," not in context and "[:" not in context:
                    findings.append(MLFinding(
                        check_id="ML-005",
                        severity="LOW",
                        category="data_loading",
                        message=(
                            f"`{name}()` loads the full dataset into memory. "
                            "In production, uncapped dataset sizes can cause OOM "
                            "denial-of-service."
                        ),
                        line=lineno,
                        code_snippet=snippet(lineno),
                        recommendation=(
                            "Add a size cap: `x_train = x_train[:MAX_SAMPLES]` or "
                            "use `tf.data.Dataset.take(n)` to limit memory usage."
                        ),
                    ))

    # ---- ML-006: No GPU memory growth configuration ----
    if "memory_growth" not in source and "set_memory_growth" not in source:
        findings.append(MLFinding(
            check_id="ML-006",
            severity="LOW",
            category="resource",
            message=(
                "GPU memory growth is not configured. TensorFlow allocates all "
                "available GPU memory by default, which can starve co-located "
                "processes or cause OOM on shared hardware."
            ),
            recommendation=(
                "Add near the top of main():\n"
                "  for gpu in tf.config.list_physical_devices('GPU'):\n"
                "      tf.config.experimental.set_memory_growth(gpu, True)"
            ),
        ))

    # ---- ML-007: Unbounded epochs ----
    for call in all_calls:
        name = call_name(call)
        if name.endswith(".fit") or name == "fit":
            for kw in call.keywords:
                if kw.arg == "epochs":
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                        if kw.value.value > 100:
                            findings.append(MLFinding(
                                check_id="ML-007",
                                severity="LOW",
                                category="resource",
                                message=(
                                    f"model.fit(epochs={kw.value.value}) – very high epoch "
                                    "count can cause prolonged compute consumption."
                                ),
                                line=get_line(call),
                                code_snippet=snippet(get_line(call)),
                                recommendation=(
                                    "Use EarlyStopping callback and cap epochs ≤ 50 "
                                    "for research / pipeline runs."
                                ),
                            ))

    # ---- ML-008: No input validation before predict ----
    for call in all_calls:
        name = call_name(call)
        if name.endswith(".predict") or name == "predict":
            lineno = get_line(call)
            if lineno:
                context = "\n".join(lines[max(0, lineno - 8):lineno])
                if "clip" not in context and "assert" not in context and "shape" not in context:
                    findings.append(MLFinding(
                        check_id="ML-008",
                        severity="MEDIUM",
                        category="model_io",
                        message=(
                            "No input shape assertion or value clipping detected before "
                            "`model.predict()`. Adversarial or malformed inputs can "
                            "trigger unexpected behavior or resource exhaustion."
                        ),
                        line=lineno,
                        code_snippet=snippet(lineno),
                        recommendation=(
                            "Before calling predict(), validate: "
                            "`assert input.shape[1:] == (32, 32, 3)` and clip: "
                            "`input = np.clip(input, 0.0, 1.0)`"
                        ),
                    ))

    # ---- ML-009: Model saved to CWD (no absolute path / no separate artifact dir) ----
    for call in all_calls:
        name = call_name(call)
        if name.endswith(".save"):
            args = call.args
            if args and isinstance(args[0], ast.Constant):
                path_val = str(args[0].value)
                if not Path(path_val).is_absolute() and "/" not in path_val and "\\" not in path_val:
                    findings.append(MLFinding(
                        check_id="ML-009",
                        severity="LOW",
                        category="model_io",
                        message=(
                            f"Model saved to relative path `{path_val}` (current "
                            "working directory). Unpredictable save location across "
                            "environments; also no subdirectory separation."
                        ),
                        line=get_line(call),
                        code_snippet=snippet(get_line(call)),
                        recommendation=(
                            "Use an explicit artifacts directory: "
                            "`Path('artifacts/models') / 'basic_cifar10_cnn.keras'` "
                            "and ensure the directory exists."
                        ),
                    ))

    # ---- ML-010: No EarlyStopping callback ----
    callback_names_in_source = re.findall(r"EarlyStopping|ReduceLROnPlateau|ModelCheckpoint", source)
    if not callback_names_in_source:
        findings.append(MLFinding(
            check_id="ML-010",
            severity="INFO",
            category="resource",
            message=(
                "No Keras training callbacks detected (EarlyStopping, ModelCheckpoint, etc.). "
                "Without EarlyStopping, overfitting may not be caught and compute "
                "may be wasted on non-improving epochs."
            ),
            recommendation=(
                "Add: `callbacks=[tf.keras.callbacks.EarlyStopping("
                "monitor='val_loss', patience=3, restore_best_weights=True)]` "
                "to model.fit()."
            ),
        ))

    tool_result = {
        "tool": "ml_ast",
        "status": "completed",
        "target": str(TARGET.name),
        "checks_performed": 10,
        "findings_count": len(findings),
        "severity_counts": {
            "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
            "LOW": sum(1 for f in findings if f.severity == "LOW"),
            "INFO": sum(1 for f in findings if f.severity == "INFO"),
        },
        "findings": [asdict(f) for f in findings],
    }
    return tool_result


# ---------------------------------------------------------------------------
# 5E  Runtime containment policy
# ---------------------------------------------------------------------------

def build_runtime_policy(
    bandit_result: dict,
    ruff_result: dict,
    semgrep_result: dict,
    ml_ast_result: dict,
) -> dict:
    """
    Derive a runtime containment policy from the aggregated static findings.

    ML programs have distinct runtime risk categories:
      - Network access  (model hub downloads, dataset CDN calls, telemetry)
      - Filesystem      (model save/load paths, checkpoint dirs)
      - Process/exec    (subprocesses, shell commands)
      - GPU/CPU         (unbounded memory, compute starvation)
      - IPC / serialization (pickle, shared memory, gRPC between workers)
    """
    log.info("  [5E] Building runtime containment policy …")

    all_findings: list[dict] = (
        bandit_result.get("findings", [])
        + ruff_result.get("findings", [])
        + semgrep_result.get("findings", [])
        + ml_ast_result.get("findings", [])
    )
    total = len(all_findings)
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")

    # ---- Source-level observed behaviours ----
    source = TARGET.read_text(encoding="utf-8")
    uses_network = any(kw in source for kw in
                       ["urllib", "requests", "http.client", "socket",
                        "keras.datasets", "tf.keras.datasets", "load_data"])
    uses_subprocess = any(kw in source for kw in
                          ["subprocess", "os.system", "os.popen", "Popen"])
    uses_pickle = "pickle" in source
    uses_model_save = ".save(" in source
    uses_model_load = any(kw in source for kw in
                          ["load_model", "load_weights", "saved_model.load"])
    uses_gpu = "GPU" in source or "gpu" in source or "memory_growth" in source
    has_fit = ".fit(" in source

    # ---- Policy construction ----
    policy: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pipeline_step": "5E",
        "target": TARGET.name,
        "total_static_findings": total,
        "high_severity_findings": high_count,
        "risk_level": "HIGH" if high_count > 0 else ("MEDIUM" if total > 5 else "LOW"),
        "observed_behaviours": {
            "network_access": uses_network,
            "subprocess_usage": uses_subprocess,
            "pickle_usage": uses_pickle,
            "model_save": uses_model_save,
            "model_load": uses_model_load,
            "gpu_usage": uses_gpu,
            "training_loop": has_fit,
        },
        "controls": [],
        "sandbox_recommendations": {},
        "ml_specific_controls": [],
    }

    controls: list[dict] = []

    # --- Network ---
    if uses_network:
        controls.append({
            "domain": "network",
            "control": "allowlist_outbound",
            "justification": (
                "keras.datasets.cifar10.load_data() downloads from "
                "storage.googleapis.com on first run. Subsequent runs are cached. "
                "Block all other outbound connections."
            ),
            "allowed_hosts": [
                "storage.googleapis.com",
                "files.pythonhosted.org",
                "pypi.org",
            ],
            "enforcement_options": [
                "iptables OUTPUT -d storage.googleapis.com -j ACCEPT; "
                "iptables OUTPUT -j DROP",
                "Python: use socket.setdefaulttimeout(30) and a network proxy allowlist",
                "Container: --network=none after initial dataset cache warms",
            ],
        })
    else:
        controls.append({
            "domain": "network",
            "control": "block_all_outbound",
            "justification": "No network calls detected in static analysis.",
            "enforcement_options": ["--network=none (Docker)", "nftables drop all outbound"],
        })

    # --- Filesystem ---
    fs_paths: list[str] = []
    if uses_model_save:
        fs_paths.append("artifacts/models/ (write – model save)")
    if uses_model_load:
        fs_paths.append("artifacts/models/ (read – model load)")
    fs_paths.append("~/.keras/ (read/write – Keras dataset cache)")
    fs_paths.append("/tmp/ or %TEMP% (read/write – TF scratch)")

    controls.append({
        "domain": "filesystem",
        "control": "path_allowlist",
        "justification": (
            "Model is saved to CWD (ML-009). Explicit path restriction prevents "
            "writes outside the project artifact directory."
        ),
        "allowed_paths": fs_paths,
        "enforcement_options": [
            "Docker: --volume ./artifacts:/app/artifacts:rw (everything else :ro)",
            "Linux: seccomp profile restricting open(2) paths",
            "Python: override builtins.open with an allowlist wrapper in testing",
        ],
    })

    # --- Process / exec ---
    if uses_subprocess:
        controls.append({
            "domain": "process",
            "control": "no_shell_exec",
            "justification": "subprocess usage detected. Restrict to no-shell mode.",
            "enforcement_options": [
                "Ensure shell=False in all subprocess calls",
                "seccomp: block execve syscall",
                "AppArmor/SELinux deny exec profile",
            ],
        })
    else:
        controls.append({
            "domain": "process",
            "control": "block_exec",
            "justification": "No subprocess usage detected. Block exec-family syscalls.",
            "enforcement_options": [
                "seccomp: deny execve, execveat",
                "Docker --security-opt seccomp=seccomp-no-exec.json",
            ],
        })

    # --- GPU / CPU resource limits ---
    controls.append({
        "domain": "resource",
        "control": "gpu_memory_growth",
        "justification": (
            "ML-006: GPU memory growth not configured. Without limits TF can "
            "allocate all VRAM, starving co-located workloads."
        ),
        "remediation_code": (
            "for gpu in tf.config.list_physical_devices('GPU'):\n"
            "    tf.config.experimental.set_memory_growth(gpu, True)"
        ),
        "enforcement_options": [
            "CUDA_VISIBLE_DEVICES='' (CPU-only for pipeline runs)",
            "nvidia-docker --gpus device=0 --memory 4g",
            "Kubernetes: resources.limits.nvidia.com/gpu: 1",
        ],
    })

    controls.append({
        "domain": "resource",
        "control": "cpu_thread_cap",
        "justification": (
            "TF defaults to using all available CPU threads. "
            "Cap inter/intra-op parallelism for reproducibility and fairness."
        ),
        "remediation_code": (
            "tf.config.threading.set_inter_op_parallelism_threads(4)\n"
            "tf.config.threading.set_intra_op_parallelism_threads(4)"
        ),
        "enforcement_options": [
            "Docker: --cpus=4",
            "cgroups v2: cpu.max 400000 100000",
            "TF_NUM_INTEROP_THREADS=4 TF_NUM_INTRAOP_THREADS=4 (env vars)",
        ],
    })

    # --- Pickle / serialization ---
    if uses_pickle:
        controls.append({
            "domain": "serialization",
            "control": "block_unsafe_deserialization",
            "justification": "pickle usage detected – arbitrary code execution risk.",
            "enforcement_options": [
                "Replace pickle with json or safetensors for model weights",
                "Verify SHA-256 of any pickle file before load",
                "Restrict read paths to known-good directories",
            ],
        })

    # --- Model integrity ---
    if uses_model_save or uses_model_load:
        controls.append({
            "domain": "model_integrity",
            "control": "hash_and_sign_model_artifacts",
            "justification": (
                "ML-003 / ML-004: Model saved/loaded without hash verification. "
                "A backdoored model replacement is undetectable without a digest check."
            ),
            "remediation_code": (
                "import hashlib, pathlib\n"
                "def sha256_file(path):\n"
                "    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()\n\n"
                "# After save:\n"
                "digest = sha256_file('artifacts/models/basic_cifar10_cnn.keras')\n"
                "pathlib.Path('artifacts/models/basic_cifar10_cnn.keras.sha256').write_text(digest)\n\n"
                "# Before load:\n"
                "stored = pathlib.Path('artifacts/models/basic_cifar10_cnn.keras.sha256').read_text()\n"
                "assert sha256_file(model_path) == stored, 'Model hash mismatch!'"
            ),
        })

    # --- Input validation ---
    controls.append({
        "domain": "input_validation",
        "control": "validate_and_clip_inputs",
        "justification": (
            "ML-008: No input validation before model.predict(). "
            "Required to guard against adversarial / malformed inputs."
        ),
        "remediation_code": (
            "def safe_predict(model, inputs, expected_shape=(32, 32, 3)):\n"
            "    assert inputs.ndim == 4, f'Expected batch, got {inputs.ndim}D'\n"
            "    assert inputs.shape[1:] == expected_shape, f'Shape mismatch: {inputs.shape}'\n"
            "    inputs = np.clip(inputs, 0.0, 1.0).astype('float32')\n"
            "    return model.predict(inputs, verbose=0)"
        ),
    })

    policy["controls"] = controls

    # ---- Sandbox / container recommendations ----
    policy["sandbox_recommendations"] = {
        "docker": {
            "base_image": "tensorflow/tensorflow:2.21.0 (official, regularly patched)",
            "flags": [
                "--read-only",
                "--volume ./artifacts:/app/artifacts:rw",
                "--volume ~/.keras:/root/.keras:rw",
                "--network=none  # after dataset cache warm-up",
                "--security-opt no-new-privileges",
                "--security-opt seccomp=seccomp-no-exec.json",
                "--memory=8g",
                "--cpus=4",
                "--user=1000:1000  # non-root",
            ],
        },
        "python_sandbox": {
            "tool": "RestrictedPython or PyPy sandbox",
            "note": (
                "For serving model.predict() via an API, wrap in a subprocess "
                "with resource.setrlimit() CPU/memory caps and no network access."
            ),
        },
        "linux_syscall_filter": {
            "tool": "seccomp-bpf",
            "deny_list": [
                "execve", "execveat", "fork", "vfork", "clone",
                "ptrace", "perf_event_open", "kexec_load",
            ],
        },
    }

    # ---- ML-specific controls summary ----
    policy["ml_specific_controls"] = [
        {
            "id": "ML-SEC-01",
            "name": "Reproducibility lock",
            "action": "Set tf.random.set_seed() + np.random.seed() at entry point",
            "severity": "MEDIUM",
        },
        {
            "id": "ML-SEC-02",
            "name": "Model artifact integrity",
            "action": "Compute & verify SHA-256 of .keras file on every save/load",
            "severity": "HIGH",
        },
        {
            "id": "ML-SEC-03",
            "name": "GPU memory cap",
            "action": "Enable memory_growth or set explicit GPU memory limit",
            "severity": "MEDIUM",
        },
        {
            "id": "ML-SEC-04",
            "name": "Input sanitisation at inference",
            "action": "Assert shape + clip values before every model.predict() call",
            "severity": "MEDIUM",
        },
        {
            "id": "ML-SEC-05",
            "name": "Training resource governor",
            "action": "Use EarlyStopping + CPU/GPU thread caps in model.fit()",
            "severity": "LOW",
        },
        {
            "id": "ML-SEC-06",
            "name": "Network allowlist",
            "action": (
                "Only storage.googleapis.com needed (CIFAR-10 download). "
                "Block all other outbound after dataset cache warm."
            ),
            "severity": "MEDIUM",
        },
    ]

    return policy


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("Step 5 – Static Analysis + Runtime Containment")
    log.info("  Target: %s", TARGET)

    bandit_result  = run_bandit()
    ruff_result    = run_ruff()
    semgrep_result = run_semgrep()
    ml_ast_result  = run_ml_ast_checks()
    policy         = build_runtime_policy(bandit_result, ruff_result,
                                          semgrep_result, ml_ast_result)

    # ---------------------------------------------------------------------------
    # Static report
    # ---------------------------------------------------------------------------
    all_counts = {
        "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for tool_result in [bandit_result, ruff_result, semgrep_result, ml_ast_result]:
        sc = tool_result.get("severity_counts", {})
        for sev in all_counts:
            all_counts[sev] += sc.get(sev, 0)

    total_findings = sum(all_counts.values())

    static_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pipeline_step": 5,
        "target": str(TARGET.name),
        "tools_run": ["bandit", "ruff", "semgrep", "ml_ast"],
        "total_findings": total_findings,
        "severity_totals": all_counts,
        "overall_verdict": (
            "FAIL" if all_counts["HIGH"] > 0
            else "WARN" if total_findings > 0
            else "PASS"
        ),
        "tools": {
            "bandit":  bandit_result,
            "ruff":    ruff_result,
            "semgrep": semgrep_result,
            "ml_ast":  ml_ast_result,
        },
    }

    STATIC_REPORT.write_text(json.dumps(static_report, indent=2), encoding="utf-8")
    log.info("  Static report -> %s", STATIC_REPORT)

    RUNTIME_POLICY.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    log.info("  Runtime policy -> %s", RUNTIME_POLICY)

    # ---------------------------------------------------------------------------
    # Console summary
    # ---------------------------------------------------------------------------
    print("\n" + "=" * 64)
    print("Step 5 – Static Analysis & Runtime Containment")
    print("=" * 64)
    print(f"  Target              : {TARGET.name}")
    print(f"  Overall verdict     : {static_report['overall_verdict']}")
    print(f"  Total findings      : {total_findings}")
    print()
    print(f"  Severity breakdown")
    print(f"    HIGH              : {all_counts['HIGH']:>4}")
    print(f"    MEDIUM            : {all_counts['MEDIUM']:>4}")
    print(f"    LOW               : {all_counts['LOW']:>4}")
    print(f"    INFO              : {all_counts['INFO']:>4}")
    print()
    print(f"  Per-tool breakdown")
    for key, r in static_report["tools"].items():
        status  = r.get("status", "?")
        count   = r.get("findings_count", 0)
        print(f"    {key:<10} : {status:<10}  findings: {count}")
    print()
    print(f"  Runtime policy risk : {policy['risk_level']}")
    print(f"  Containment controls: {len(policy['controls'])}")
    print(f"  ML-specific controls: {len(policy['ml_specific_controls'])}")
    print("=" * 64)

    # Print each finding with severity prefix
    any_findings = any(r.get("findings") for r in static_report["tools"].values())
    if any_findings:
        print("\n  Findings detail:")
        for tool_key, r in static_report["tools"].items():
            for f in r.get("findings", []):
                sev  = f.get("severity", "INFO")
                cid  = f.get("rule_id") or f.get("check_id", "")
                msg  = f.get("message", "")[:100]
                line = f.get("line")
                loc  = f" (line {line})" if line else ""
                print(f"    [{sev:<6}] [{tool_key}] {cid}{loc}: {msg}")


if __name__ == "__main__":
    main()
