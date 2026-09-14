# UMSAF Dissertation Research Execution To-Do List

**Refreshed:** 2026-09-14

This document converts the dissertation objectives, methodology, hypotheses, and current repository state into a sequential execution plan. Complete one task at a time. Do not mark a task complete until its evidence has been saved and its validation check has passed.

## How to Use This Plan

- Record the experiment ID, date, environment, tool versions, input hashes, and output paths for every task.
- Preserve raw outputs as well as summarized results. Do not overwrite an earlier run; use a dated run directory or an immutable archive.
- Treat a claim as **observed** only when supported by direct output or a reproducible test. Label inferred relationships as correlated, potential, or unconfirmed.
- Use the seven UMSAF layers consistently: Application; Dependency/Supply Chain; ML/DL Framework; Serialization/Computational Graph; Native Binary; Runtime/Hardware; Operating System/Infrastructure.
- Treat the Windows baseline as the authoritative primary configuration. Any future Linux/ELF run is comparative only and must have its own environment manifest, lockfile, and results.

## Current State and Blocking Issues

The repository contains a completed preliminary Windows pipeline run, not a completed UMSAF evaluation. Existing evidence includes:

- 129 packages in [artifacts/dep_tree.json](artifacts/dep_tree.json), from [src/step1_dep_tree.py](src/step1_dep_tree.py).
- 0 findings from the recorded pip-audit and OSV run in [artifacts/vuln_scan_summary.json](artifacts/vuln_scan_summary.json).
- A 124-component CycloneDX SBOM in [artifacts/sbom.cdx.json](artifacts/sbom.cdx.json); SPDX was skipped.
- 127/127 RECORD and PyPI checks passing in [artifacts/integrity_summary.json](artifacts/integrity_summary.json); PEP 740 attestations were not found and Sigstore verification was not performed.
- Static findings and a runtime policy in [artifacts/static_report.json](artifacts/static_report.json) and [artifacts/runtime_policy.json](artifacts/runtime_policy.json); Semgrep was skipped.
- 409 Windows PE binaries fingerprinted in [artifacts/binaries_report.json](artifacts/binaries_report.json), from [src/step6_binary_extraction.py](src/step6_binary_extraction.py).
- No files in [tests](tests), and no implemented model-inspection, runtime-tracing, cross-layer-correlation, propagation-analysis, or risk-classification modules.

Documentation status also requires attention before final results are reported: [README.md](README.md), [WHAT_WE_BUILT.md](WHAT_WE_BUILT.md), and [PIPELINE_SESSION_SUMMARY.md](PIPELINE_SESSION_SUMMARY.md) describe the six-step prototype as complete or production-ready, but they do not constitute evidence that the full UMSAF artifact in Dissertation Sections 10-12 has been implemented or evaluated. Treat those documents as preliminary-pipeline records until they are reconciled.

The dissertation methodology has been standardized on the Windows primary configuration: Windows x86_64, CPython 3.12.10, TensorFlow 2.21.0, and PE analysis. Ubuntu/Linux and ELF analysis are retained only as possible future comparative work. The current artifacts therefore represent the primary platform rather than a provisional substitute.

## Phase 0: Establish the Research Contract

### Task 1 - Freeze the research scope and claims

- **Do:** Confirm that the primary contribution is UMSAF for software-ecosystem security, not model accuracy, adversarial robustness, privacy, or formal neural-network verification. Confirm the seven layers, RQ1-RQ7, H1-H7, and the CIFAR-10 CNN as the primary workload.
- **Use:** [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md), especially Sections 3-6, 10, and 11; [Dissertation_Research_Updated_20260831.md](Dissertation/writing/Dissertation_Research_Updated_20260831.md); [proposal.md](Dissertation/proposal.md).
- **Prerequisite:** None.
- **Expected evidence:** A one-page scope and claims register mapping each objective, research question, hypothesis, and expected contribution to at least one planned experiment and one metric.
- **Validate:** Every dissertation objective has an experiment or is explicitly classified as out of scope. Remove unsupported claims such as "production-ready" from research conclusions unless separately demonstrated.

### Task 2 - Resolve the experimental platform and version baseline

- **Do:** Freeze the primary experiment as Windows x86_64, CPython 3.12.10, TensorFlow 2.21.0, Keras 3.x, NumPy 2.x, and PE-format `.pyd`/`.dll` analysis. Treat Ubuntu/Linux/ELF as future comparative work rather than a required dissertation environment. Record OS, architecture, CUDA/GPU status, tool versions, lockfile hash, and vulnerability-data sources.
- **Use:** [pyproject.toml](pyproject.toml), [requirements.in](requirements.in), [requirements-lock.txt](requirements-lock.txt), [README.md](README.md), Section 9.2.1 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Task 1.
- **Expected evidence:** `environment_manifest_<id>.json` containing interpreter path/version, Windows version, platform tag, package versions, lockfile hash, tool versions, hardware, environment variables, and data-source timestamps; a short scope note stating that results are Windows/PE-specific.
- **Validate:** Create a fresh Windows environment from the selected lockfile with `--require-hashes`; run `python -m pip check`; confirm that the recorded interpreter, platform, TensorFlow version, and PE tooling match the manifest.

### Task 3 - Define data management, experiment IDs, and evidence rules

- **Do:** Define immutable run directories, naming conventions, raw versus derived artifacts, retention, model-artifact handling, and the evidence-strength labels `directly_observed`, `strongly_correlated`, `potential`, and `unconfirmed`.
- **Use:** [artifacts](artifacts), [README.md](README.md), Sections 11.8 and 11.12 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Task 2.
- **Expected evidence:** `docs/experiment_protocol.md`, an experiment manifest template, and a run directory containing checksums for all inputs and outputs.
- **Validate:** Perform a dry-run with one existing artifact and verify that another researcher can identify the exact environment, command, timestamp, and source artifact for every reported value.

### Task 4 - Define ground truth and evaluation datasets

- **Do:** Select controlled cases for clean software, known vulnerable package/framework versions, manipulated model artifacts, modified binaries or package contents, and runtime anomalies. Define inclusion criteria and what counts as a true positive, false positive, false negative, or unconfirmed result.
- **Use:** Sections 11.3-11.5 and 11.12 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md); CVE, OSV, and NVD records; package release metadata.
- **Prerequisite:** Tasks 1-3.
- **Expected evidence:** A versioned ground-truth table with case ID, affected component/version, vulnerability/advisory ID, expected layer, expected observable evidence, and safe reproduction conditions.
- **Validate:** Independently verify each vulnerability record against its original advisory and ensure that every labeled case has a documented basis. Never execute an unknown exploit outside an isolated lab.

## Phase 1: Reproduce and Correct the Baseline

### Task 5 - Rebuild the clean baseline environment

- **Do:** Recreate the selected baseline from the direct requirements and hash-verified lockfile. Confirm the application and pipeline dependencies are the ones intended for the experiment.
- **Use:** [requirements.in](requirements.in), [requirements-lock.txt](requirements-lock.txt), [pyproject.toml](pyproject.toml), [.gitignore](.gitignore).
- **Prerequisite:** Task 2.
- **Expected evidence:** Fresh-environment installation log, `pip check` output, package inventory, lockfile hash, and environment manifest.
- **Validate:** Compare installed package names and versions against the lockfile; investigate any mismatch before continuing.

### Task 6 - Make the CNN workload reproducible and auditable

- **Do:** Decide whether to keep the intentionally vulnerable preliminary program as a control or create a hardened experimental variant. For the hardened variant, add deterministic seeding, explicit artifact paths, model hashing, input validation, resource controls, bounded training, and machine-readable logging without changing the control case.
- **Use:** [image_recognition_basic.py](image_recognition_basic.py), [basic_cifar10_cnn.keras](basic_cifar10_cnn.keras), findings in [artifacts/static_report.json](artifacts/static_report.json), and [artifacts/runtime_policy.json](artifacts/runtime_policy.json).
- **Prerequisite:** Tasks 2-5.
- **Expected evidence:** Versioned control and hardened workload files, model hash sidecar, run log, configuration file, dataset/cache status, training/evaluation metrics, and output model hash.
- **Validate:** Run the control and hardened variants in fresh directories. Repeat each run with the same seed and compare predictions, metrics, model metadata, and hashes; document any expected nondeterminism.

### Task 7 - Add automated regression tests for the pipeline

- **Do:** Create focused tests for AST import extraction, lockfile parsing, dependency normalization, report schema, artifact hashing, model inspection, and risk-score calculations. Add fixtures for clean and intentionally modified artifacts.
- **Use:** Empty [tests](tests), [src/step1_dep_tree.py](src/step1_dep_tree.py), [src/step2_vuln_scan.py](src/step2_vuln_scan.py), [src/step3_sbom.py](src/step3_sbom.py), [src/step4_integrity.py](src/step4_integrity.py), [src/step5_static_analysis.py](src/step5_static_analysis.py), [src/step6_binary_extraction.py](src/step6_binary_extraction.py).
- **Prerequisite:** Tasks 3-6.
- **Expected evidence:** Passing pytest output, coverage report for new modules, and test fixtures stored outside generated artifacts.
- **Validate:** Run the suite on a clean checkout and confirm that tests fail when a fixture is tampered with or a required report field is removed.

### Task 8 - Rerun and reconcile Steps 1-6

- **Do:** Execute the pipeline against the frozen baseline; compare new results with the April artifacts. Record changed package counts, vulnerability results, SBOM component counts, integrity outcomes, static findings, and binary inventory.
- **Use:** `python src/step1_dep_tree.py` through `python src/step6_binary_extraction.py`; all files under [src](src), [configs](configs), and [artifacts](artifacts).
- **Prerequisite:** Tasks 5-7.
- **Expected evidence:** Dated raw reports, a baseline comparison table, command log, and discrepancy explanations.
- **Validate:** Check JSON parsing, report timestamps, lockfile references, zero unexpected analysis errors, and consistency between summary reports and detailed reports. Treat a clean scan as "no findings in this snapshot," not proof of absence.

### Task 9 - Complete omitted baseline capabilities

- **Do:** Decide whether SPDX, Semgrep, Sigstore/PEP 740 verification, NVD enrichment, and binary-signature validation are required by the evaluation. Implement or explicitly document each as included, optional, or excluded with rationale.
- **Use:** [configs/bandit.yaml](configs/bandit.yaml), [configs/pip-audit.toml](configs/pip-audit.toml), [src/step5_static_analysis.py](src/step5_static_analysis.py), [src/step4_integrity.py](src/step4_integrity.py), current skipped statuses in [artifacts/static_report.json](artifacts/static_report.json) and [artifacts/integrity_summary.json](artifacts/integrity_summary.json).
- **Prerequisite:** Task 8.
- **Expected evidence:** Tool-version records, completed reports or justified exclusion notes, and a limitation statement for unavailable provenance/signing data.
- **Validate:** Re-run each included tool and confirm the report status is `completed`; do not report skipped checks as clean results.

### Task 10 - Reconcile preliminary-pipeline documentation

- **Do:** Correct the status language in the project documentation so it distinguishes the completed six-step Windows pipeline from the unfinished UMSAF research artifact. Replace unsupported claims such as "production-ready" with "preliminary research prototype" unless later evidence supports the stronger claim. Record whether Semgrep, SPDX, Sigstore/PEP 740, NVD enrichment, and binary-signature validation are included or deferred.
- **Use:** [README.md](README.md), [WHAT_WE_BUILT.md](WHAT_WE_BUILT.md), [PIPELINE_SESSION_SUMMARY.md](PIPELINE_SESSION_SUMMARY.md), [artifacts/static_report.json](artifacts/static_report.json), [artifacts/integrity_summary.json](artifacts/integrity_summary.json), and [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 1, 8, and 9.
- **Expected evidence:** Synchronized documentation, a completed/deferred capability matrix, and a dated changelog or decision note.
- **Validate:** Search active documentation for claims that the full UMSAF framework, runtime analysis, model inspection, cross-layer mapping, or risk classifier is complete; each claim must resolve to an implemented module and reproducible artifact.

## Phase 2: Implement the Missing UMSAF Evidence Producers

### Task 11 - Implement serialized-model inspection

- **Do:** Build a model-analysis module that identifies `.keras` artifacts, records file hashes and size, reads safe metadata/configuration, enumerates layers and operations, records framework/version information, detects unexpected structure, and supports comparison of clean versus modified artifacts. Treat model loading as untrusted and isolate it.
- **Use:** [basic_cifar10_cnn.keras](basic_cifar10_cnn.keras), [image_recognition_basic.py](image_recognition_basic.py), Section 10.3.5 and Section 11.7 Step 7 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 3, 6, and 7.
- **Expected evidence:** `model_analysis.json`, operator/layer inventory, metadata extract, clean-model hash, modified-model comparison, and a safety note describing what was and was not executed during inspection.
- **Validate:** The analyzer must produce stable output for the same artifact, detect a deliberate metadata/structure change, reject a hash mismatch, and avoid executing untrusted model content in the analysis process.

### Task 12 - Define and run model-artifact security scenarios

- **Do:** Create controlled scenarios for intact, bit-flipped, metadata-modified, unsupported-operation, and externally sourced model artifacts. Do not claim malicious execution unless it is safely reproduced and directly observed.
- **Use:** Model-analysis output from Task 11, [artifacts/runtime_policy.json](artifacts/runtime_policy.json), and the model trust-boundary discussion in [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Task 11.
- **Expected evidence:** Scenario manifest, artifact hashes, analyzer findings, load/validation outcomes, and evidence-strength classification for every result.
- **Validate:** The intact case passes; modified cases are detected or clearly classified as out of analyzer scope; no scenario is run with network or unrestricted filesystem access.

### Task 13 - Implement controlled runtime observation

- **Do:** Define runtime events and collect Windows process, thread, file, network, dynamically loaded-DLL, resource, and framework/native execution evidence using tools appropriate to the selected platform, such as Windows Event Tracing, Process Monitor, Process Explorer, or a documented equivalent. Capture clean control and hardened runs. Treat Windows observations as platform-specific evidence.
- **Use:** [src/step5_static_analysis.py](src/step5_static_analysis.py), [artifacts/runtime_policy.json](artifacts/runtime_policy.json), Section 10.3.6 and Section 11.7 Step 8 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 2, 3, 6, and 8.
- **Expected evidence:** `runtime_report.json`, raw trace files, dynamically loaded component list, file/network/resource event summary, run configuration, and trace-to-process mapping.
- **Validate:** Repeat the same run and measure stable versus variable events; confirm the dataset download is the only expected network event and that observed binaries map to the inventory from Task 8.

### Task 14 - Perform targeted reverse engineering

- **Do:** Select a small, justified sample of PE components based on package relevance, known vulnerability evidence, runtime reachability, or unusual imports. Analyze PE structure, imports, exports, symbols, strings, control flow, and selected functions in Ghidra or platform-equivalent Windows tools. Do not claim a vulnerability from a suspicious pattern without corroborating evidence.
- **Use:** [artifacts/binaries_report.json](artifacts/binaries_report.json), [artifacts/wheelhouse](artifacts/wheelhouse), [src/step6_binary_extraction.py](src/step6_binary_extraction.py), Ghidra project files, and Section 10.3.4 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 8 and 13.
- **Expected evidence:** Target-selection rationale, binary hashes, Ghidra project/exported reports, import/export tables, function notes, screenshots where needed, and observed-versus-inferred findings.
- **Validate:** Reopen the analyzed binary by hash, verify that the report references the correct package/version, and independently check at least one import/export or control-flow observation with a second tool.

### Task 15 - Map application APIs to framework and native evidence

- **Do:** Trace the selected CNN operations from Python API calls to framework components, loaded native binaries, and runtime observations where feasible. Use conservative mapping when direct call-level attribution is unavailable.
- **Use:** [image_recognition_basic.py](image_recognition_basic.py), dependency and binary reports, Task 13 traces, Task 14 analysis, and Section 10.3.7 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 11-14.
- **Expected evidence:** Versioned mapping table or graph with source event, target component, evidence source, layer transition, confidence label, and unresolved links.
- **Validate:** Every `directly_observed` edge must cite a trace or explicit structural record; sample edges must be manually reviewed; unsupported Python-to-native claims remain `potential` or `unconfirmed`.

## Phase 3: Build the Integrated UMSAF Artifact

### Task 16 - Define the common evidence and component schema

- **Do:** Define identifiers and schemas for applications, packages, vulnerabilities, SBOM components, model artifacts, binaries, runtime events, layers, relationships, evidence, confidence, and timestamps. Preserve provenance for every derived field.
- **Use:** Outputs from Tasks 8-15; Sections 10.3, 10.4, 10.7, and 11.12 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 8-15.
- **Expected evidence:** JSON Schema or equivalent typed model, examples, schema version, and migration notes.
- **Validate:** Load all current reports into the schema; reject duplicate identifiers, missing provenance, invalid layer names, and relationships that reference nonexistent components.

### Task 17 - Implement the cross-layer evidence graph

- **Do:** Build the graph/mapper that joins dependency edges, SBOM components, vulnerability records, binaries, model structures, runtime observations, and infrastructure dependencies across the seven layers.
- **Use:** [src](src), Task 16 schema, Task 15 mappings, and the propagation procedure in Section 11.12 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Task 16.
- **Expected evidence:** `cross_layer_graph.json`, graph statistics, rendered graph or queryable representation, and a documented list of unresolved relationships.
- **Validate:** Test the graph with known toy paths and confirm that a known dependency-to-binary-to-runtime path is represented only when its supporting evidence exists.

### Task 18 - Implement propagation analysis with confidence levels

- **Do:** Detect candidate paths such as vulnerable dependency -> affected binary -> framework operation -> runtime event and manipulated model -> framework operation -> native/runtime event. Separate directly observed, strongly correlated, potential, and unconfirmed paths.
- **Use:** Task 16 graph; vulnerability records; model, binary, and runtime reports; Section 11.12 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Task 16.
- **Expected evidence:** `propagation_report.json`, path evidence lists, confidence rationale, and examples of isolated vulnerabilities that do not propagate.
- **Validate:** Negative controls must not produce a directly observed propagation path; removing one required edge must lower or invalidate the path confidence.

### Task 19 - Implement interpretable integrated risk scoring

- **Do:** Define a documented rule-based score using severity, dependency depth/centrality, runtime reachability, native involvement, affected layers, artifact integrity, propagation evidence, exposure, and uncertainty. Keep severity-only scoring as a baseline.
- **Use:** Task 16 schema, Task 18 paths, Section 10.3.8 and Section 11.5.7 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Task 18.
- **Expected evidence:** Scoring specification, feature dictionary, worked examples, `risk_scores.json`, and sensitivity analysis for weight changes.
- **Validate:** Scores are deterministic, bounded, explainable, and monotonic for explicitly defined factors; missing evidence must not silently receive the highest risk.

### Task 20 - Build and evaluate ML-based prioritization only if justified

- **Do:** Decide whether the available labeled cases support ML. If yes, construct leakage-resistant train/validation/test splits, compare simple models with severity-only and rule-based baselines, and report uncertainty. If no, document why ML would be methodologically unsound and retain rule-based scoring.
- **Use:** Ground truth from Task 4, features from Tasks 16-19, scikit-learn if selected in [pyproject.toml](pyproject.toml), and H6 in [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 4 and 19.
- **Expected evidence:** Feature matrix, split manifest, model/configuration, baseline results, precision/recall/F1 or ranking metrics, calibration/error analysis, and reproducible seed.
- **Validate:** Ensure no artifact, package version, or duplicate vulnerability instance leaks across splits; compare against the severity-only baseline and report when the ML model does not improve it.

### Task 21 - Generate the integrated UMSAF report

- **Do:** Produce one report that links application inputs, dependency/SBOM evidence, vulnerability data, integrity, binaries, reverse engineering, model analysis, runtime observations, cross-layer paths, risk scores, limitations, and recommendations.
- **Use:** All outputs from Tasks 8-20; Section 10.7 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 16-20.
- **Expected evidence:** `umsaf_report_<experiment_id>.json`, human-readable report, and a report-to-source evidence index.
- **Validate:** Every reported finding resolves to at least one source artifact and timestamp; summary counts equal detailed counts; unsupported conclusions are explicitly labeled.

## Phase 4: Execute the Empirical Evaluation

### Task 22 - Establish the primary controlled workload results

- **Do:** Run the clean and hardened CIFAR-10 CNN under the frozen baseline with repeated trials. Record training/evaluation behavior only as workload context, not as a model-performance contribution.
- **Use:** [image_recognition_basic.py](image_recognition_basic.py), model artifact, Tasks 2, 3, and 6, and UMSAF report generation from Task 21.
- **Prerequisite:** Task 21.
- **Expected evidence:** Trial manifest, logs, runtime traces, model hashes, dependency/SBOM/vulnerability/binary/model reports, and integrated report for each trial.
- **Validate:** Confirm repeated trials use the same configuration; report deterministic and nondeterministic fields separately; verify no network access after the dataset cache is warmed.

### Task 23 - Run known-vulnerable and controlled security cases

- **Do:** Apply UMSAF to the cases selected in Task 4, using isolated environments and safe reproduction procedures. Include clean negative controls and cases that test package, binary, model, and runtime evidence separately.
- **Use:** Task 4 dataset, separate lockfiles/environments, UMSAF modules, and the runtime containment policy.
- **Prerequisite:** Tasks 4 and 21-22.
- **Expected evidence:** Per-case manifest, raw tool reports, expected-versus-observed table, TP/FP/FN/TN decisions where defensible, and containment log.
- **Validate:** Verify package/version identities and advisory applicability before interpreting detection results; destroy or reset each contaminated environment after the run.

### Task 24 - Run isolated-analysis baselines

- **Do:** Run dependency/SCA-only, vulnerability-only, static-only, binary-only, serialized-model-only, runtime-only, and any justified fuzzing/testing baselines with equivalent inputs and resource limits.
- **Use:** Existing pipeline scripts, model analyzer, runtime analyzer, Ghidra/binary tools, and Section 11.6 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 11-15 and 23.
- **Expected evidence:** Baseline configuration and raw outputs, per-baseline findings, component/layer coverage, time and resource use, and comparison-ready normalized records.
- **Validate:** Confirm that integrated UMSAF does not receive evidence unavailable to a baseline unless that difference is the independent variable being tested.

### Task 25 - Measure visibility, coverage, traceability, and performance

- **Do:** Calculate applicable detection, dependency/SBOM, binary, model, runtime, cross-layer, risk-prioritization, performance, scalability, and reproducibility metrics defined in Section 11.5.
- **Use:** Outputs from Tasks 21-24, metric definitions in [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md), and analysis notebooks/scripts stored outside raw artifacts.
- **Prerequisite:** Tasks 22-24.
- **Expected evidence:** Versioned metric dataset, calculation code, tables, plots, confidence intervals or uncertainty notes where appropriate, and missing-ground-truth disclosure.
- **Validate:** Recompute metrics from raw normalized records; hand-check a sample; ensure precision/recall/F1 are not reported where labels are not defensible.

### Task 26 - Analyze hypotheses H1-H7 without assuming success

- **Do:** Evaluate each hypothesis against predefined evidence and thresholds, classify it as supported, partially supported, or not supported, and record counterexamples and tradeoffs.
- **Use:** Tasks 22-24, H1-H7 in Section 11.11 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md), and the scope register from Task 1.
- **Prerequisite:** Task 25.
- **Expected evidence:** Hypothesis decision table with claim, operational measure, result, uncertainty, threats, and conclusion; no hypothesis should be accepted solely because the framework produced more findings.
- **Validate:** An independent review of each conclusion must be able to trace it to raw evidence and the predefined metric or qualitative protocol.

### Task 27 - Perform scalability and cross-configuration analysis

- **Do:** Increase ecosystem complexity by package count, binary count, model size, workload count, or selected Windows framework configuration. Additional ML/DL frameworks are optional and should be included only if they answer a defined research question and have a reproducible Windows baseline. Linux/ELF comparison is future work, not a prerequisite for completion.
- **Use:** Multiple Windows configurations, [artifacts](artifacts), Task 25 measurement code, and Section 11.5.8 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md).
- **Prerequisite:** Tasks 2, 25, and 26.
- **Expected evidence:** Scaling matrix, runtime/memory/storage measurements, failure modes, Windows-configuration comparison table, and explanation of non-comparable observations.
- **Validate:** Repeat selected points, confirm resource measurements use the same protocol, and identify analysis stages that dominate cost.

## Phase 5: Interpret, Document, and Finish the Dissertation

### Task 28 - Conduct threats-to-validity and reproducibility audit

- **Do:** Review internal, external, construct, conclusion, and reproducibility threats. Address instrumentation effects, incomplete ground truth, platform mismatch, changing vulnerability data, nondeterminism, and inferred propagation paths.
- **Use:** Section 11.8 of [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md), all experiment manifests, and Tasks 25-27 results.
- **Prerequisite:** Tasks 25-27.
- **Expected evidence:** Threats-to-validity matrix with threat, affected result, severity, mitigation, residual risk, and reproducibility status.
- **Validate:** A second review must be able to identify which conclusions are directly observed, correlated, or limited by unavailable evidence.

### Task 29 - Write the results and discussion chapters

- **Do:** Convert the experiment outputs into tables, figures, methodology descriptions, baseline comparisons, hypothesis results, negative results, limitations, and implications for RQ1-RQ7. Keep preliminary April findings separate from final evaluation results.
- **Use:** [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md), [Dissertation_Research_Old.md](Dissertation/writing/Dissertation_Research_Old.md), [proposal.md](Dissertation/proposal.md), and all frozen experiment artifacts.
- **Prerequisite:** Tasks 26-28.
- **Expected evidence:** Updated dissertation sections with figure/table source references, reproducibility appendix, and a claims-to-evidence matrix.
- **Validate:** Every quantitative statement can be regenerated from a saved artifact; every literature-derived quantitative claim has a verified citation and source record.

### Task 30 - Reconcile dissertation versions and remove stale claims

- **Do:** Choose the authoritative dissertation source. Reconcile [Dissertation_Research.md](Dissertation/writing/Dissertation_Research.md), the updated Markdown/DOCX/TXT versions, [Dissertation_Research_Old.md](Dissertation/writing/Dissertation_Research_Old.md), and [proposal.md](Dissertation/proposal.md). Remove contradictory platform/version statements, duplicate timelines, and claims that describe planned work as completed.
- **Use:** All files under [Dissertation/writing](Dissertation/writing) and [Dissertation](Dissertation).
- **Prerequisite:** Task 29.
- **Expected evidence:** One authoritative Markdown source, a version/reconciliation note, updated DOCX/PDF if required, and a list of intentionally retained historical documents.
- **Validate:** Search for stale version numbers, old dates, "completed," "demonstrates," and "production-ready" claims; each occurrence must be supported by final evidence or revised to future/planned/limited language.

### Task 31 - Package the reproducibility and defense archive

- **Do:** Assemble source code, tests, environment manifests, lockfiles, raw and derived artifacts, analysis scripts, figures, tables, Ghidra exports, model hashes, run commands, data-source timestamps, and a README explaining how to reproduce the final results.
- **Use:** Entire [InventoryDependencyTree](.) repository, especially [src](src), [tests](tests), [configs](configs), [artifacts](artifacts), and dissertation files.
- **Prerequisite:** Tasks 28-30.
- **Expected evidence:** Release/archive manifest with SHA-256 checksums, clean-checkout reproduction log, final dissertation, and final contribution/evidence matrix.
- **Validate:** Rebuild the environment from the archive, rerun a representative end-to-end experiment, compare key outputs, run all tests, and verify that no credentials, unsafe live exploit material, or untracked required files are missing.

### Task 32 - Final review, submission, and defense preparation

- **Do:** Perform final technical, methodological, editorial, citation, and formatting review; prepare defense slides and a concise explanation of UMSAF architecture, evidence, metrics, limitations, and supported/unsupported hypotheses.
- **Use:** Final dissertation, final archive, [README.md](README.md), and the claims-to-evidence matrix.
- **Prerequisite:** Task 31.
- **Expected evidence:** Submission-ready dissertation, defense deck, anticipated-question log, final checklist, and advisor review record.
- **Validate:** Confirm that the submitted document, archive, and cited artifacts use the same version identifiers and that every research question has a direct answer grounded in the completed experiments.

## Completion Definition

The dissertation experiment program is complete only when:

- The platform/version decision is explicit and reproducible.
- The baseline pipeline has been rerun and its skipped capabilities are disclosed.
- Model inspection, runtime observation, cross-layer correlation, propagation confidence, and risk prioritization have executable evidence or explicit justified exclusions.
- UMSAF has been compared with isolated baselines using predefined metrics.
- H1-H7 and RQ1-RQ7 have evidence-based conclusions, including negative results.
- Threats to validity, platform boundaries, and data-source timestamps are documented.
- The dissertation and reproducibility archive can be rebuilt and checked from a clean environment.
