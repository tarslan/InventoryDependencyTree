Tony Arslan\
University of Nebraska\
Advisor: Dr. Witawas Srisa-an\
Date: April, 2026

## **Abstract**

Modern machine learning applications are predominantly developed using
high-level programming languages such as Python; however, they rely
extensively on native C and C++ libraries for computational efficiency.
Frameworks such as TensorFlow, Keras, and NumPy utilize compiled
binaries, shared libraries, and hardware acceleration components that
operate outside the visibility of traditional source-code analysis
tools. As a result, vulnerabilities residing in native
components—including memory corruption, unsafe APIs, outdated
dependencies, and supply-chain risks—may remain undetected.

This research proposes a comprehensive cyber system analysis and
modeling framework for multilayer machine learning systems that
integrates software composition analysis, software bill of materials
(SBOM) generation, vulnerability intelligence, and binary reverse
engineering. The framework will analyze interactions between Python
applications and their underlying native libraries, extracting
dependency graphs, identifying known vulnerabilities, and applying
reverse engineering techniques to inspect compiled binaries. Tools such
as Ghidra will be used to analyze TensorFlow, Keras, and NumPy native
components, enabling cross-layer visibility into potential security
weaknesses.

The proposed system will further incorporate machine learning techniques
to classify high-risk components and prioritize vulnerabilities. The
ultimate objective is to develop a scalable and automated framework
capable of improving the security posture of modern artificial
intelligence software systems.

**Keywords:** Machine Learning Security, Reverse Engineering, Binary
Analysis, TensorFlow, SBOM, Software Supply Chain, Vulnerability
Detection

## **1. Introduction**

The rapid adoption of machine learning and deep learning technologies
has transformed modern software systems across domains such as
healthcare, finance, energy, and cybersecurity. Developers increasingly
rely on high-level languages such as Python to build machine learning
applications due to their flexibility, ease of use, and extensive
ecosystem of libraries. However, the performance demands of machine
learning workloads necessitate the use of optimized native
implementations written in C and C++. Consequently, frameworks such as
TensorFlow, Keras, and NumPy operate as multilayer systems in which
Python code serves as a thin abstraction layer over complex native
execution environments.

While Python itself is generally considered memory-safe, the underlying
native libraries are not subject to the same guarantees. These libraries
may introduce vulnerabilities such as buffer overflows, improper memory
management, unsafe system calls, and exposure to outdated or compromised
dependencies. Furthermore, the increasing complexity of software supply
chains introduces additional risks, including dependency confusion
attacks, malicious package insertion, and tampering with binary
artifacts.

Existing software security tools primarily focus on source code analysis
or dependency scanning, often treating third-party libraries as opaque
components. This limitation is particularly problematic in machine
learning systems, where critical functionality is delegated to native
binaries that are rarely inspected by developers. As highlighted in
prior work, multilayer systems are often analyzed in isolation rather
than holistically, leading to incomplete assessments of system security.

This dissertation addresses this gap by proposing a unified framework
that integrates software composition analysis, binary reverse
engineering, and machine learning techniques to analyze Python-based
machine learning systems across multiple layers. Focusing on the
interactions between Python applications and native libraries, this
research aims to uncover vulnerabilities that traditional approaches may
overlook.

## **2. Problem Statement**

Modern machine learning software systems operate across multiple layers,
including Python application code, third-party libraries, native
binaries, and hardware acceleration modules. Existing security analysis
approaches are fragmented and fail to provide a comprehensive view of
vulnerabilities across these layers.

Specifically:

- Source-level analysis tools do not inspect native binaries

- Dependency scanners do not analyze binary behavior

- Binary analysis tools are not integrated with dependency intelligence

- Cross-layer interactions are rarely modeled or evaluated

This fragmentation results in blind spots where vulnerabilities may
exist but remain undetected. There is a critical need for a unified
framework capable of analyzing the full software stack of machine
learning applications.

## **3. Research Objectives**

1.  Identify full dependency trees of Python-based machine learning
    applications

2.  Detect vulnerabilities using CVE, OSV, and NVD databases

3.  Generate SBOMs for machine learning software systems

4.  Extract and analyze native binary components from ML frameworks

5.  Apply reverse engineering techniques to inspect compiled libraries

6.  Model cross-layer interactions between Python and native code

7.  Develop automated vulnerability classification mechanisms

## **4. Research Questions**

1.  What vulnerabilities exist within native libraries used by
    Python-based ML frameworks?

2.  How can reverse engineering reveal hidden security risks in ML
    software stacks?

3.  Can software composition analysis and binary analysis be unified
    into a single framework?

4.  How can machine learning techniques assist in identifying high-risk
    components?

## **5. Research Timeline** 

This research will follow an **accelerated timeline**, reflecting prior
progress and the goal of submitting the first research paper by **August
2026**, with full completion targeted for **December 2026**.

### **Phase 1 — Scope Finalization & Literature Review**

**May – June 2026**

- Refine research scope

- Expand literature review

- Finalize experimental design

### **Phase 2 — Prototype Development**

**June – July 2026**

- Implement dependency analysis

- Generate SBOMs

- Integrate CVE/OSV scanning

- Implement package integrity verification

- Extract wheel binaries

### **Phase 3 — Binary Analysis**

**July 2026**

- Analyze TensorFlow, Keras, NumPy binaries

- Use Ghidra for reverse engineering

- Identify native-level vulnerabilities

### **Phase 4 — Paper Preparation**

**Late July – August 2026**

- Evaluate findings

- Write and submit first research paper

### **Phase 5 — Framework Expansion**

**August – October 2026**

- Develop cross-layer interaction modeling

- Implement automated risk scoring

### **Phase 6 — Full System Evaluation**

**October – November 2026**

- Test across multiple ML applications

- Validate against known vulnerabilities

### **Phase 7 — Dissertation Completion**

**November – December 2026**

- Final writing

- Defense preparation

- Submission

# **6. Related Work**

## **6.1 Reverse Engineering and Binary Analysis**

Reverse engineering is a well-established technique for analyzing
compiled software, uncovering hidden behaviors, and identifying
vulnerabilities in binary executables. Tools such as Ghidra, IDA Pro,
and Binary Ninja provide capabilities including disassembly,
decompilation, control-flow graph reconstruction, and symbolic analysis.

Traditionally, reverse engineering has been applied to malware analysis,
exploit development, and standalone binary inspection. However, its
application to **machine learning (ML) frameworks** remains limited.
This gap is significant because modern ML systems rely heavily on
compiled native libraries written in C and C++, where many
security-critical operations occur. Existing research has not
sufficiently integrated reverse engineering with higher-level software
analysis, particularly in the context of Python-based ML systems.

## **6.2 Static Analysis Limitations in Machine Learning Libraries**

Static analysis tools have been widely adopted for detecting software
bugs and vulnerabilities. However, recent empirical studies demonstrate
that these tools are largely ineffective for ML libraries.

A comprehensive study analyzing 410 real-world bugs across popular ML
libraries—including TensorFlow, PyTorch, and MXNet—found that
state-of-the-art static analysis tools detected only **approximately
0.01% of vulnerabilities (5–6 out of 410)** . A parallel study on
vulnerability detection confirmed similar findings, showing that static
tools fail to detect the vast majority of real-world vulnerabilities in
ML systems .

These results highlight fundamental limitations of static analysis when
applied to ML libraries:

- ML libraries exhibit **high complexity and data dependency**

- Many vulnerabilities arise from **runtime behaviors**

- Critical operations are implemented in **native C/C++ code**

- Static tools lack visibility into **cross-layer interactions**

These findings strongly motivate the need for alternative approaches
that go beyond traditional static analysis.

## **6.3 Characteristics of Vulnerabilities in ML Libraries**

Understanding the nature of vulnerabilities in ML systems is essential
for designing effective detection mechanisms. A large-scale empirical
study analyzing **683 vulnerabilities across seven major ML libraries**
(including TensorFlow, NumPy, and SciPy) provides critical insights into
their characteristics .

The study identifies key dimensions of ML vulnerabilities:

- **Root Causes:** improper input validation, memory mismanagement

- **Symptoms:** crashes, incorrect outputs, undefined behavior

- **Fix Patterns:** validation checks, algorithmic corrections

- **Distribution:** vulnerabilities appear across all stages of the ML
  pipeline

Importantly, the study highlights that vulnerabilities in ML libraries
are:

- **Systematic but poorly understood**

- Often **different from traditional software vulnerabilities**

- Spread across both **API-level and implementation-level code**

This supports the need for a framework capable of **classifying and
modeling vulnerabilities across multiple layers**.

## **6.4 Native Code as the Primary Attack Surface**

Machine learning frameworks rely heavily on native implementations for
performance optimization. Studies on TensorFlow-based systems show that
many vulnerabilities originate from **C/C++ components**, including:

- Memory corruption

- Integer overflow

- NULL pointer dereference

- Improper input validation

These vulnerabilities are often associated with high-severity impacts on
system confidentiality, integrity, and availability .

This observation is critical: although ML applications are written in
Python, their **security risks are largely embedded in native
binaries**. As a result, approaches that analyze only Python source code
fail to capture the true attack surface.

## **6.5 Limitations of Fuzzing and Dynamic Testing**

Fuzz testing has emerged as a promising technique for identifying
vulnerabilities in ML libraries. Recent work proposes advanced fuzzers
that leverage historical vulnerability patterns and guided input
generation to discover security flaws.

For example, a security knowledge-guided fuzzer identified **135
vulnerabilities in TensorFlow and PyTorch**, including 69 previously
unknown issues . However, despite these successes, fuzzing techniques
face several limitations:

- Difficulty generating **semantically valid input combinations**

- Limited coverage of **developer-level APIs**

- Incomplete modeling of **internal execution paths**

- Lack of integration with **dependency and binary analysis**

These limitations suggest that fuzzing alone is insufficient and must be
complemented by structural analysis techniques.

## **6.6 Multilayer Architecture of Machine Learning Systems**

Modern ML systems exhibit a multilayer architecture consisting of:

Application → ML Library → Framework → Native Backend

Research on deep learning systems demonstrates that faults and
vulnerabilities can originate at any of these layers, including the
application code, third-party libraries, and underlying frameworks .

This multilayer structure introduces several challenges:

- Dependencies span multiple abstraction levels

- Errors propagate across layers

- Security analysis requires **holistic system modeling**

Existing tools typically analyze only a single layer, failing to capture
the interactions between components.

## **6.7 Fault Injection and Runtime Behavior Analysis**

Fault injection techniques have been used to study the resilience of ML
systems under various failure conditions. Tools such as
TensorFlow-specific fault injectors demonstrate that ML systems exhibit
complex and sometimes unpredictable behavior under injected faults .

These findings indicate that:

- Runtime behavior differs significantly from static expectations

- Faults in lower layers can propagate to higher-level outputs

- Native execution layers are difficult to inspect and control

This further supports the need for deeper analysis techniques, including
reverse engineering and cross-layer modeling.

## **6.8 Security Implications in Real-World Applications**

Machine learning systems are increasingly deployed in safety-critical
domains, including:

- Autonomous vehicles

- Healthcare systems

- Financial services

- Cybersecurity applications

For example, ML techniques have been used to detect zero-day attacks in
real-world environments, demonstrating both their utility and their
exposure to emerging threats .

The widespread adoption of ML amplifies the impact of vulnerabilities,
making robust security analysis essential.

## **6.9 Gap Analysis and Research Positioning**

Based on the reviewed literature, several critical gaps emerge:

### **1. Ineffectiveness of Existing Tools**

- Static analysis detects **~0.01% of vulnerabilities**

- Fuzzing provides partial coverage

- SCA tools analyze metadata but not binaries

### **2. Lack of Cross-Layer Modeling**

No existing approach models interactions across:

Python → ML Framework → Native Libraries → OS

### **3. Limited Binary-Level Visibility**

Current tools do not analyze:

- Embedded native code in Python packages

- Low-level execution behavior

### **4. Fragmented Security Approaches**

Existing techniques operate independently:

- Static analysis

- Dependency scanning

- Binary analysis

- Machine learning-based detection

## **6.10 Positioning of This Research**

This dissertation addresses the identified gaps by proposing a **unified
multilayer security analysis framework** that integrates:

- Dependency graph extraction

- SBOM generation

- Vulnerability intelligence (CVE / OSV)

- Binary reverse engineering

- Cross-layer interaction modeling

- Machine learning-based risk classification

Unlike prior work, this research:

✔ Demonstrates the **limitations of existing tools using empirical
evidence**\
✔ Targets **native components within ML frameworks**\
✔ Models **interactions across software layers**\
✔ Combines **software engineering, cybersecurity, and machine learning
techniques**\
✔ Provides a **scalable and automated approach** for securing ML systems

# **7. Preliminary Study**

## **7.1 Overview**

To evaluate the feasibility of the proposed multilayer security analysis
framework, a preliminary study was conducted using a basic image
recognition application implemented in Python. The objective of this
study is to demonstrate how vulnerabilities and security-relevant
characteristics can be identified across multiple layers of a machine
learning (ML) software stack, including Python source code, third-party
libraries, and native binary components.

The study focuses on analyzing widely used ML frameworks—specifically
TensorFlow, Keras, and NumPy—which are representative of modern deep
learning ecosystems and are known to rely heavily on native C and C++
implementations.

## **7.2 Experimental Setup**

A simple convolutional neural network (CNN) application was developed
using TensorFlow and Keras. The program utilizes the CIFAR-10 dataset
for image classification.

import tensorflow as tf

from tensorflow import keras

import numpy as np

\# Load dataset

(x_train, y_train), (x_test, y_test) =
keras.datasets.cifar10.load_data()

\# Normalize

x_train = x_train / 255.0

x_test = x_test / 255.0

\# Build model

model = keras.Sequential(\[

keras.layers.Conv2D(32, (3,3), activation='relu'),

keras.layers.MaxPooling2D(),

keras.layers.Flatten(),

keras.layers.Dense(64, activation='relu'),

keras.layers.Dense(10, activation='softmax')

\])

model.compile(optimizer='adam',

loss='sparse_categorical_crossentropy',

metrics=\['accuracy'\])

model.fit(x_train, y_train, epochs=2)

This application serves as the **entry point for multilayer analysis**.

## **7.3 Dependency and SBOM Analysis**

The first phase of the preliminary study involved identifying the
complete dependency tree of the application.

### **Findings:**

- TensorFlow introduces a large number of transitive dependencies

- Dependencies include both Python packages and compiled binaries

- Many dependencies are not directly visible to developers

An SBOM was generated to capture:

- Package names and versions

- Dependency relationships

- Distribution artifacts (wheels)

This step demonstrates that even simple ML programs rely on **complex
and deep dependency chains**, supporting prior findings that ML systems
have extensive software supply chains .

## **7.4 Vulnerability Scanning**

Dependency scanning tools were applied to identify known vulnerabilities
using CVE and OSV databases.

### **Observations:**

- Vulnerabilities were detected in transitive dependencies

- Many vulnerabilities were associated with:

  - Input validation issues

  - Memory-related flaws

- Some vulnerabilities originated from components not directly used in
  the application code

These findings align with prior research showing that vulnerabilities in
ML libraries are widespread and often hidden within dependency chains

## **7.5 Binary Extraction and Analysis**

A key focus of this study was extracting and analyzing native binary
components embedded in ML frameworks.

### **Process:**

1.  Download TensorFlow and NumPy wheel packages

2.  Extract .so, .pyd, and .dll files

3.  Identify native modules (e.g., TensorFlow internal wrappers)

### **Key Findings:**

- TensorFlow includes large native binaries such as:

  - \_pywrap_tensorflow_internal

- NumPy includes compiled C extensions

- Native libraries link to external dependencies (e.g., BLAS, MKL)

These results confirm that ML frameworks are **not purely
Python-based**, but heavily depend on native code.

## **7.6 Reverse Engineering Analysis**

Selected binaries were analyzed using Ghidra.

### **Analysis Focus:**

- Function structures

- Imported libraries

- Strings and symbols

- Control-flow patterns

### **Observations:**

- Complex native functions handle core ML computations

- External libraries are dynamically linked

- Low-level operations (memory management, numerical computation) are
  present

These findings support prior research indicating that many
vulnerabilities originate in native C/C++ components of ML frameworks

## **7.7 Cross-Layer Interaction Analysis**

The study examined how Python code interacts with native binaries.

### **Observed Execution Flow:**

Python Application\
↓\
TensorFlow / Keras API\
↓\
Python Wrapper Layer\
↓\
Native C/C++ Implementation\
↓\
System Libraries / Hardware

This confirms that:

- Python acts as an abstraction layer

- Critical operations occur in native code

- Security risks may originate in lower layers

This multilayer interaction aligns with prior findings that ML systems
require holistic analysis across layers

## **7.8 Key Insights**

The preliminary study reveals several important insights:

### **1. Hidden Complexity**

Even simple ML programs depend on large and complex ecosystems.

### **2. Native Code Dominance**

Security-critical operations occur in native binaries rather than Python
code.

### **3. Vulnerability Distribution**

Vulnerabilities exist across multiple layers, particularly in
dependencies.

### **4. Tool Limitations**

Traditional tools do not provide full visibility into:

- Binary internals

- Cross-layer interactions

This aligns with prior findings that static analysis tools are largely
ineffective for ML libraries .

## **7.9 Implications for Proposed Research**

This preliminary study validates the feasibility of the proposed
research framework.

It demonstrates that:

✔ Dependency analysis is achievable\
✔ SBOM generation is practical\
✔ Vulnerabilities can be identified in ML ecosystems\
✔ Native binaries can be extracted and analyzed\
✔ Cross-layer interactions can be modeled

Most importantly, it confirms that:

A unified framework integrating these techniques is both necessary and
feasible.

# **8. Proposed Framework**

## **8.1 Overview**

This research proposes a **Unified Multilayer Security Analysis
Framework (UMSAF)** designed to analyze Python-based machine learning
(ML) systems that rely on native C/C++ libraries. The framework
integrates software composition analysis, binary reverse engineering,
vulnerability intelligence, and machine learning techniques to provide
comprehensive security analysis across multiple software layers.

The primary goal of the framework is to overcome the limitations of
existing tools by enabling **end-to-end visibility from Python source
code to native binary execution**, thereby identifying vulnerabilities
that are otherwise undetectable through isolated analysis approaches.

## **8.2 Architectural Design**

The proposed framework consists of six major components:

Python ML Application

↓

\(1\) Dependency Intelligence Engine

↓

\(2\) SBOM & Vulnerability Analyzer

↓

\(3\) Binary Extraction Module

↓

\(4\) Reverse Engineering Engine

↓

\(5\) Cross-Layer Interaction Mapper

↓

\(6\) Risk Scoring & ML Classification Engine

↓

Security Report & Recommendations

## **8.3 Component Descriptions**

### **8.3.1 Dependency Intelligence Engine**

This component identifies all direct and transitive dependencies of the
ML application.

#### **Functions:**

- Resolve dependency trees

- Identify package versions

- Map dependencies to distribution artifacts (wheels, source files)

- Generate dependency graphs

#### **Output:**

- Full dependency graph

- Package metadata

### **8.3.2 SBOM and Vulnerability Analyzer**

This module generates Software Bills of Materials (SBOMs) and performs
vulnerability scanning.

#### **Functions:**

- Generate SBOM (CycloneDX / SPDX format)

- Query vulnerability databases (CVE, OSV, NVD)

- Map vulnerabilities to dependencies

- Identify vulnerable versions

#### **Output:**

- SBOM file

- Vulnerability report

### **8.3.3 Binary Extraction Module**

This module extracts native binaries from Python packages.

#### **Functions:**

- Download wheel files

- Extract .so, .pyd, .dll binaries

- Identify compiled extensions

- Collect binary metadata (hashes, architecture, size)

#### **Output:**

- Binary inventory

- Artifact repository

### **8.3.4 Reverse Engineering Engine**

This component performs static analysis on native binaries.

#### **Tools:**

- Ghidra

#### **Functions:**

- Disassemble and decompile binaries

- Extract function signatures

- Identify imported/exported symbols

- Detect unsafe patterns:

  - Memory operations

  - Input validation issues

  - Unsafe API usage

#### **Output:**

- Binary analysis report

- Control-flow and dependency graphs

### **8.3.5 Cross-Layer Interaction Mapper**

This is a **key innovation of the framework**.

#### **Purpose:**

To model interactions between Python code and native binaries.

#### **Functions:**

- Trace Python imports and API usage

- Map Python functions to native calls

- Construct cross-layer call graphs

#### **Example Mapping:**

model.fit()\
↓\
TensorFlow API\
↓\
Python wrapper (\_pywrap_tensorflow)\
↓\
Native C++ function\
↓\
System library / hardware

#### **Output:**

- Cross-layer interaction graph

- Execution flow mapping

### **8.3.6 Risk Scoring and ML Classification Engine**

This component evaluates and prioritizes security risks.

#### **Functions:**

- Aggregate findings from all modules

- Apply rule-based risk scoring

- Train ML models to classify vulnerabilities

- Identify high-risk components

#### **Features Used:**

- Dependency depth

- Vulnerability severity

- Binary complexity

- API usage patterns

#### **Output:**

- Risk scores

- Vulnerability prioritization

- Classification results

## **8.4 Data Flow Model**

The framework operates as a pipeline:

1.  Input: Python ML application

2.  Extract dependencies

3.  Generate SBOM

4.  Scan vulnerabilities

5.  Extract binaries

6.  Reverse engineer binaries

7.  Map cross-layer interactions

8.  Compute risk scores

9.  Generate final report

## **8.5 Key Innovations**

This framework introduces several novel contributions:

### **1. Unified Multilayer Analysis**

Combines:

- Source code analysis

- Dependency analysis

- Binary analysis

into a single framework.

### **2. Cross-Layer Interaction Modeling**

Explicitly models:

Python → ML Framework → Native Binary → OS

This is largely absent in existing research.

### **3. Integration of SCA and Reverse Engineering**

Existing tools treat dependencies as black boxes.\
This framework **opens the black box**.

### **4. Binary-Level Security Analysis for ML Systems**

Focuses on native components where vulnerabilities actually reside.

### **5. ML-Based Risk Classification**

Applies machine learning to:

- Prioritize vulnerabilities

- Detect high-risk patterns

## **8.6 System Implementation Plan**

The framework will be implemented as a modular system:

### **Technologies:**

- Python (core framework)

- Dependency tools: pip, pipdeptree

- SBOM tools: CycloneDX

- Vulnerability tools: pip-audit, OSV

- Binary tools: Ghidra

- ML libraries: TensorFlow / scikit-learn

## **8.7 Expected Outputs**

The framework will generate:

1.  Dependency Graph

2.  SBOM Document

3.  Vulnerability Report

4.  Binary Inventory

5.  Reverse Engineering Report

6.  Cross-Layer Interaction Graph

7.  Risk Assessment Report

## **8.8 Research Hypothesis**

The proposed framework is based on the hypothesis that:

Integrating dependency analysis, binary reverse engineering, and
cross-layer modeling will significantly improve the detection and
understanding of vulnerabilities in machine learning software systems
compared to existing approaches.

# **9. Research Methodology and Evaluation Plan**

## **9.1 Overview**

This research adopts a **design science and empirical evaluation
methodology** to develop and validate the proposed Unified Multilayer
Security Analysis Framework (UMSAF). The study combines system design,
implementation, and experimental validation using real-world machine
learning (ML) applications and known vulnerability datasets.

The methodology is structured into four major phases:

Design → Implementation → Experimentation → Evaluation

## **9.2 Research Design**

### **9.2.1 Approach**

This study follows a **design science research (DSR)** paradigm, where
the primary artifact is the proposed framework. The research process
includes:

- Problem identification (limitations of current ML security tools)

- Artifact development (UMSAF framework)

- Demonstration (application to ML systems)

- Evaluation (quantitative and qualitative analysis)

## **9.3 Experimental Setup**

### **9.3.1 Subject Systems**

The framework will be evaluated on multiple categories of ML systems:

#### **Category A — Controlled Experimental Programs**

- Basic image recognition applications (e.g., CIFAR-10 CNN)

- Synthetic test cases with injected vulnerabilities

#### **Category B — Real-World Open-Source ML Applications**

- TensorFlow-based projects

- Keras-based applications

- NumPy-heavy scientific computing projects

#### **Category C — Vulnerable Library Versions**

- Historical versions of TensorFlow, NumPy, and related libraries

- Versions associated with known CVEs

### **9.3.2 Data Sources**

The study will utilize:

- CVE / NVD databases

- OSV vulnerability database

- GitHub repositories

- ML vulnerability datasets (e.g., 683 vulnerabilities identified in
  prior work )

## **9.4 Evaluation Objectives**

The evaluation aims to answer the following:

1.  **Effectiveness:** Can the framework detect vulnerabilities missed
    by existing tools?

2.  **Coverage:** How much of the ML software stack is analyzed?

3.  **Accuracy:** What is the precision and recall of detected
    vulnerabilities?

4.  **Scalability:** Can the framework handle large ML systems?

5.  **Insight Generation:** Does the framework provide meaningful
    cross-layer insights?

## **9.5 Evaluation Metrics**

### **9.5.1 Detection Metrics**

- **True Positives (TP):** Correctly identified vulnerabilities

- **False Positives (FP):** Incorrectly identified vulnerabilities

- **False Negatives (FN):** Missed vulnerabilities

From these:

- **Precision** = TP / (TP + FP)

- **Recall** = TP / (TP + FN)

- **F1 Score** = harmonic mean of precision and recall

### **9.5.2 Coverage Metrics**

- Percentage of dependencies analyzed

- Percentage of binaries extracted and analyzed

- Depth of dependency tree coverage

### **9.5.3 Cross-Layer Metrics**

- Number of mapped Python-to-native interactions

- Completeness of cross-layer call graphs

- Percentage of vulnerabilities linked across layers

### **9.5.4 Performance Metrics**

- Execution time per analysis

- Memory usage

- Scalability with increasing dependency size

## **9.6 Baseline Comparison**

The framework will be compared against existing approaches:

### **Baselines:**

1.  Static analysis tools

2.  Software composition analysis (SCA) tools

3.  Vulnerability scanners

4.  Fuzzing-based approaches (where applicable)

### **Expected Outcome:**

Prior research shows static tools detect only **~0.01% of
vulnerabilities** , which establishes a strong baseline for comparison.

## **9.7 Experimental Procedure**

### **Step 1 — Input Selection**

Select ML applications and vulnerable library versions.

### **Step 2 — Framework Execution**

Run UMSAF pipeline:

- Dependency extraction

- SBOM generation

- Vulnerability scanning

- Binary extraction

- Reverse engineering

- Cross-layer mapping

### **Step 3 — Data Collection**

Collect:

- Detected vulnerabilities

- Binary analysis results

- Interaction graphs

### **Step 4 — Ground Truth Comparison**

Compare results with:

- Known CVEs

- Published vulnerability datasets

### **Step 5 — Metric Calculation**

Compute precision, recall, F1 score, and coverage metrics.

## **9.8 Threats to Validity**

### **Internal Validity**

- Incorrect vulnerability mapping

- Incomplete binary extraction

### **Mitigation:**

- Use verified vulnerability datasets

- Cross-validate results with multiple tools

### **External Validity**

- Results may not generalize to all ML frameworks

### **Mitigation:**

- Evaluate across multiple frameworks and applications

### **Construct Validity**

- Metrics may not capture all aspects of security

### **Mitigation:**

- Use multiple complementary metrics

## **9.9 Expected Results**

The framework is expected to:

✔ Detect vulnerabilities missed by static analysis\
✔ Provide deeper insight into native components\
✔ Improve vulnerability coverage across layers\
✔ Enable better prioritization of security risks

## **9.10 Success Criteria**

The research will be considered successful if:

- Detection accuracy exceeds baseline tools

- Cross-layer interactions are successfully modeled

- Native binary vulnerabilities are identified

- Framework scales to real-world ML applications

# **10. Expected Contributions**

This dissertation is expected to contribute to the fields of **software
security, machine learning systems, and software engineering** in the
following ways:

### **10.1 Theoretical Contributions**

1.  **Multilayer Security Model for ML Systems**\
    A formalized model that characterizes interactions across:

Python → ML Framework → Native Binary → OS/Hardware

This model advances understanding of where and how vulnerabilities
manifest in ML software stacks.

2.  **Cross-Layer Vulnerability Taxonomy**\
    A taxonomy that classifies vulnerabilities by:

    1.  Layer (application, library, binary, OS)

    2.  Root cause (e.g., input validation, memory safety)

    3.  Propagation path across layers

3.  **Integration Paradigm for SCA + Binary Analysis**\
    A principled approach that unifies software composition analysis
    (SBOM/CVE) with reverse engineering outputs.

### **10.2 Methodological Contributions**

1.  **Unified Multilayer Security Analysis Framework (UMSAF)**\
    A modular, reproducible pipeline that integrates:

    1.  Dependency resolution

    2.  SBOM generation

    3.  Vulnerability intelligence

    4.  Binary extraction and reverse engineering

    5.  Cross-layer interaction mapping

    6.  ML-based risk scoring

2.  **Cross-Layer Interaction Mapping Technique**\
    A method to link Python-level calls to native functions and
    downstream system libraries, enabling traceability of risk.

3.  **Binary-Aware Vulnerability Prioritization**\
    A scoring mechanism that combines:

    1.  CVE severity

    2.  Dependency depth

    3.  Binary complexity

    4.  Reachability (from entry points)

### **10.3 Empirical Contributions**

1.  **Curated Dataset of ML Software Vulnerabilities**

    1.  Mapped CVEs/OSV entries to packages and binaries

    2.  Cross-layer links (Python → native)

    3.  Reproducible cases with affected versions

2.  **Benchmarking of Security Tools on ML Systems**\
    Comparative evaluation showing gaps of:

    1.  Static analysis tools

    2.  SCA tools

    3.  Fuzzing approaches

3.  **Case Studies on TensorFlow/Keras/NumPy**\
    Deep dives demonstrating binary-level findings and cross-layer
    propagation.

### **10.4 Practical Contributions**

1.  **Open-Source Prototype Tool**\
    A CLI-based tool (mlsec-analyze) implementing UMSAF with
    standardized outputs (SBOM, vuln reports, binary inventory,
    interaction graphs).

2.  **Developer Guidelines and Checklists**\
    Actionable practices for:

    1.  Secure dependency management

    2.  Safe model loading

    3.  Binary awareness in ML pipelines

3.  **Integration Blueprint for CI/CD (DevSecOps)**\
    Guidance for incorporating ML security checks into pipelines (SBOM,
    audit, binary scanning).

# **11. Limitations and Assumptions**

### **11.1 Limitations**

1.  **Incomplete Binary Coverage**

    1.  Some native libraries are dynamically loaded (e.g., via dlopen),
        which may limit static discovery.

2.  **Platform Dependency**

    1.  Binary artifacts vary by OS/architecture (Linux/Windows/macOS,
        CPU/GPU), affecting reproducibility across environments.

3.  **Reverse Engineering Complexity**

    1.  Large binaries (e.g., TensorFlow) may limit full decompilation
        and require sampling or targeted analysis.

4.  **Vulnerability Ground Truth**

    1.  Public CVE/OSV data may be incomplete or lag behind real-world
        disclosures.

5.  **Fuzzing/Dynamic Analysis Scope**

    1.  The framework focuses on static + structural analysis; deep
        dynamic fuzzing is complementary but not exhaustive in this
        work.

### **11.2 Assumptions**

1.  ML applications are primarily Python-based and use standard package
    managers (e.g., pip).

2.  Dependencies are obtainable via public repositories (e.g., PyPI) or
    mirrors.

3.  Native binaries are distributed as wheels or linked libraries
    accessible for analysis.

4.  Vulnerability databases (CVE/OSV) provide sufficiently accurate
    identifiers for mapping.

# **12. Conclusion**

Machine learning systems are increasingly central to critical
applications, yet their security remains difficult to assess due to
**multilayer architectures and reliance on opaque native binaries**.
While developers interact with Python code, core execution frequently
occurs in C/C++ libraries, where many high-severity vulnerabilities
originate.

This dissertation proposes a **Unified Multilayer Security Analysis
Framework (UMSAF)** that integrates dependency analysis, SBOM
generation, vulnerability intelligence, binary reverse engineering, and
cross-layer interaction modeling. By bridging gaps between software
composition analysis and binary inspection, the framework enables
**end-to-end visibility** from Python entry points to native execution
layers.

The preliminary study demonstrates feasibility, and the proposed
methodology establishes a rigorous path for evaluation using real-world
ML systems and known vulnerability datasets. The expected outcome is a
**scalable, automated, and empirically validated approach** for
improving the security posture of modern AI software.

# **13. References (APA/IEEE Style – Starter Set)**

*Note: Expand to 25–40 sources for submission. Below is a curated
starter list aligned with your proposal. Format per your university (APA
7th or IEEE).*

### **Core ML Security & Vulnerabilities**

- Shiri Harzevili, N., Shin, J., Wang, J., Wang, S., & Nagappan, N.
  (2023). Characterizing and understanding software security
  vulnerabilities in machine learning libraries. *MSR*.

- Filus, K., & Domańska, J. (2023). Software vulnerabilities in
  TensorFlow-based deep learning applications. *Computers & Security*.

### **Testing, Fuzzing, and Reliability**

- Harzevili, N. S., et al. (2023). Security knowledge-guided fuzzing of
  deep learning libraries.

- Narayanan, N., et al. (2022). Fault injection for TensorFlow
  applications. *IEEE TDSC*.

### **DL Systems & Multilayer Architecture**

- Quan, L., et al. (2022). Towards understanding the faults of
  JavaScript-based deep learning systems. *ASE*.

### **Applied ML Security**

- Topcu, A. E., et al. (2023). Social media zero-day attack detection
  using TensorFlow.

### **Standards and Security Foundations**

- MITRE. Common Vulnerabilities and Exposures (CVE).

- MITRE. Common Weakness Enumeration (CWE).

- NVD (National Vulnerability Database).

- OWASP Secure Coding Practices.

### **Tools & Platforms**

- TensorFlow Documentation

- Keras Documentation

- NumPy Documentation

- Ghidra User Guide

## **Recommended Final Step (Practical)**

Convert this into:

- **APA (Word)** or **IEEE (LaTeX)** format

- Add:

  - Proper citations formatting

  - Section numbering consistency

  - Figures (architecture diagram)

  - Table of contents
