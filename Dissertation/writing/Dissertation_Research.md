# **Multilayer Security Analysis of Machine Learning Software Ecosystems Through Dependency Intelligence, Binary Reverse Engineering, and Cross-Layer Threat Modeling**

Tony Arslan  
University of Nebraska  
Advisor: Dr. Witawas Srisa-an  
Date: August, 2026

## **Abstract**

Modern machine learning software ecosystems extend far beyond application source code and include serialized models, computational graphs, native binaries, runtime environments, hardware acceleration layers, third-party dependencies, and complex software supply chains. Frameworks such as TensorFlow, Keras, and NumPy rely heavily on native C and C++ implementations that operate beneath high-level Python abstractions. As a result, vulnerabilities embedded within native binaries, serialized model artifacts, dependency chains, and runtime execution layers may remain undetected by traditional software security tools.

Recent studies demonstrate that existing static analysis techniques detect only a very small percentage of vulnerabilities in machine learning libraries, while additional research has revealed silent computational failures, malicious model behaviors, hidden TensorFlow APIs, software supply-chain risks, and runtime vulnerabilities within deep learning ecosystems. These findings highlight the limitations of fragmented security approaches that analyze source code, dependencies, binaries, and runtime behaviors independently.

This research proposes a Unified Multilayer Security Analysis Framework (UMSAF) for machine learning software ecosystems that integrates dependency intelligence, software bill of materials (SBOM) generation, vulnerability intelligence, binary reverse engineering, serialized model inspection, runtime behavior analysis, and cross-layer threat modeling. The framework will analyze interactions between Python applications and their underlying native libraries, computational graphs, and execution environments to identify vulnerabilities, hidden execution paths, malicious model behaviors, and software supply-chain risks.

The proposed system will further incorporate machine learning techniques to classify high-risk components and prioritize vulnerabilities using features derived from dependency graphs, binary structures, API interactions, and runtime behaviors. Reverse engineering tools such as Ghidra will be used to inspect TensorFlow, Keras, and NumPy native components, enabling deeper visibility into compiled machine learning infrastructure.

The ultimate objective of this research is to develop a scalable, automated, and holistic security analysis framework capable of improving the security posture, transparency, and trustworthiness of modern artificial intelligence software ecosystems.

**Keywords:** Machine Learning Security, AI Software Assurance, Reverse Engineering, Binary Analysis, TensorFlow, Keras, NumPy, SBOM, Software Supply Chain Security, Cross-Layer Threat Modeling, Vulnerability Detection, Serialized Model Security

## **1. Introduction**

The rapid adoption of machine learning and deep learning technologies has transformed modern software systems across domains such as healthcare, finance, energy, and cybersecurity. Developers increasingly rely on high-level languages such as Python to build machine learning applications due to their flexibility, ease of use, and extensive ecosystem of libraries. However, the performance demands of machine learning workloads necessitate the use of optimized native implementations written in C and C++. Consequently, frameworks such as TensorFlow, Keras, and NumPy operate as multilayer systems in which Python code serves as a thin abstraction layer over complex native execution environments.

While Python itself is generally considered memory-safe, the underlying native libraries are not subject to the same guarantees. These libraries may introduce vulnerabilities such as buffer overflows, improper memory management, unsafe system calls, and exposure to outdated or compromised dependencies. Furthermore, the increasing complexity of software supply chains introduces additional risks, including dependency confusion attacks, malicious package insertion, and tampering with binary artifacts.

Existing software security tools primarily focus on source code analysis or dependency scanning, often treating third-party libraries as opaque components. This limitation is particularly problematic in machine learning systems, where critical functionality is delegated to native binaries that are rarely inspected by developers. As highlighted in prior work, multilayer systems are often analyzed in isolation rather than holistically, leading to incomplete assessments of system security.

Unlike prior approaches that focus narrowly on isolated vulnerability detection or binary inspection, this research positions machine learning security as a holistic software ecosystem assurance problem involving dependencies, serialized models, native binaries, runtime environments, and cross-layer interactions. The proposed framework therefore extends beyond conventional reverse engineering and vulnerability analysis by integrating software supply-chain security, runtime analysis, threat modeling, and multilayer interaction analysis into a unified security assurance methodology for machine learning ecosystems.

## **2. Problem Statement**

Modern machine learning software systems operate across multiple layers, including Python application code, third-party libraries, native binaries, and hardware acceleration modules. Existing security analysis approaches are fragmented and fail to provide a comprehensive view of vulnerabilities across these layers.

Specifically:

- Source-level analysis tools do not inspect native binaries

- Dependency scanners do not analyze binary behavior

- Binary analysis tools are not integrated with dependency intelligence

- Cross-layer interactions are rarely modeled or evaluated

This fragmentation results in blind spots where vulnerabilities may exist but remain undetected. There is a critical need for a unified framework capable of analyzing the full software stack of machine learning applications.

Existing approaches largely analyze machine learning software layers independently rather than treating ML systems as interconnected software ecosystems. As a result, vulnerabilities propagating across dependencies, runtime layers, serialized models, and native binaries frequently remain undetected.

## **3. Research Objectives**

1.  Identify full dependency trees of Python-based machine learning applications

2.  Detect vulnerabilities using CVE, OSV, and NVD databases

3.  Generate SBOMs for machine learning software systems

4.  Extract and analyze native binary components from ML frameworks

5.  Apply reverse engineering techniques to inspect compiled libraries

6.  Model cross-layer interactions between Python and native code

7.  Develop automated vulnerability classification mechanisms

## **4. Scope of Research**

This research focuses on the security analysis of modern machine learning software ecosystems that rely on Python-based deep learning frameworks and native computational libraries. The primary objective is to investigate how vulnerabilities, unsafe execution behaviors, and hidden attack surfaces propagate across multiple software layers, including:

- application code,

- machine learning frameworks,

- serialized computational graphs,

- native binaries,

- runtime environments,

- and infrastructure components.

The scope of this dissertation is limited primarily to machine learning and deep learning ecosystems utilizing:

- TensorFlow,

- Keras,

- NumPy,

- and related Python-based machine learning dependencies.

The experimental analysis emphasizes environments in which high-level Python APIs invoke lower-level native C and C++ implementations through dynamically linked libraries, runtime execution engines, and hardware acceleration components.

The proposed research specifically investigates:

- dependency intelligence,

- software bill of materials (SBOM) generation,

- software supply-chain analysis,

- vulnerability identification,

- binary extraction,

- reverse engineering of native machine learning components,

- serialized model inspection,

- runtime behavior analysis,

- and cross-layer vulnerability propagation.

The research further focuses on identifying how vulnerabilities propagate across interconnected machine learning software layers rather than analyzing isolated software components independently.

The dissertation does not attempt to fully address all aspects of deep learning security. In particular, the following topics are considered outside the primary scope of this research:

- adversarial robustness optimization,

- model accuracy improvement,

- federated learning security,

- cryptographic privacy-preserving machine learning,

- side-channel attacks against hardware accelerators,

- and formal verification of neural network correctness.

Although adversarial machine learning literature is reviewed for contextual purposes, the primary emphasis of this research is software ecosystem security and multilayer software assurance rather than adversarial perturbation defense techniques.

The experimental implementation is also limited to controlled research environments and representative machine learning / depp learning applications used to evaluate the feasibility of the proposed Unified Multilayer Security Analysis Framework (UMSAF). The research does not attempt to provide exhaustive vulnerability coverage for all machine learning frameworks or deployment environments.

Despite these limitations, the proposed research aims to provide a scalable and extensible foundation for holistic security assurance within modern machine learning software ecosystems.

## **5. Research Questions**

#### 1 - How can dependencies and native binary components embedded within machine learning or deep learning ecosystems be systematically identified and analyzed?

#### 2 - How effective are traditional software security techniques when applied to machine learning frameworks and native libraries?

#### 3 - Can binary reverse engineering techniques recover meaningful structural and behavioral information from machine learning binaries?

#### 4 - How can serialized machine learning models and computational graphs be inspected for hidden malicious functionality?

#### 5 - Can cross-layer interaction modeling improve vulnerability detection in multilayer ML systems?

#### 6 - How can automated testing and mutation-analysis techniques improve vulnerability discovery in machine learning frameworks?

##  **6. Threat Model for Machine Learning Software Ecosystems**

**6.1 Overview**

Modern deep learning or machine learning (ML) software ecosystems consist of multiple interconnected layers, including application code, machine learning frameworks, serialized models, native binaries, runtime environments, hardware acceleration components, and external software dependencies. These multilayer architectures introduce complex attack surfaces that extend beyond traditional software systems.

Unlike conventional applications, ML systems frequently rely on:

- dynamically loaded native libraries,

- computational graph serialization,

- hardware-specific execution paths,

- third-party package repositories,

- and externally distributed pretrained models.

As a result, vulnerabilities may originate from multiple layers simultaneously and propagate across abstraction boundaries.

This research adopts a holistic threat-modeling approach to characterize threats affecting machine learning software ecosystems and to guide the design of the proposed Unified Multilayer Security Analysis Framework (UMSAF).

Consequently, machine learning security must be approached as an ecosystem-level assurance problem rather than a single-layer software analysis problem.

**6.2 ML Ecosystem Layer Model**

Machine learning software ecosystems operate across multiple interconnected software and runtime layers. Unlike conventional software systems that are often analyzed primarily at the application layer, modern machine learning environments rely heavily on interactions between:

- high-level application code,

- machine learning frameworks,

- serialized computational graphs,

- native binary libraries,

- runtime execution environments,

- and infrastructure components.

These multilayer interactions introduce complex attack surfaces and trust boundaries that extend beyond traditional software security models. Vulnerabilities originating within one layer may propagate across other layers through dependency relationships, runtime interactions, serialized model execution, or native library invocation.

As a result, this research adopts a multilayer ecosystem perspective for threat modeling and security analysis rather than treating machine learning systems as isolated software applications.

A more detailed conceptual layer model and associated vulnerability propagation analysis are presented in Section 6.10.

**6.3 Threat Actors**

The threat model considers several categories of adversaries:

**6.3.1 Malicious Package Maintainers**

Attackers may publish:

- compromised Python packages,

- malicious wheel distributions,

- or tampered dependency updates.

These attacks may target:

- PyPI repositories,

- dependency resolution mechanisms,

- and transitive package chains.

**6.3.2 Supply-Chain Attackers**

Adversaries may compromise:

- dependency repositories,

- CI/CD pipelines,

- model-sharing platforms,

- or build environments.

Potential impacts include:

- insertion of malicious binaries,

- dependency poisoning,

- or hidden backdoors.

**6.3.3 Malicious Model Providers**

Attackers may distribute:

- malicious TensorFlow SavedModel artifacts,

- poisoned pretrained models,

- or serialized computational graphs containing hidden functionality.

Recent research demonstrates that TensorFlow models may abuse hidden APIs capable of:

- file access,

- networking,

- and arbitrary code execution.

**6.3.4 Adversarial Users**

Attackers may craft malicious inputs intended to:

- trigger memory corruption,

- exploit unsafe native operations,

- or manipulate inference behavior.

**6.3.5 Insider Threats**

Internal developers or administrators may:

- introduce vulnerable dependencies,

- disable security controls,

- or deploy compromised models.

**6.4 Threat Surfaces**

The proposed threat model identifies the following primary attack surfaces.

**6.4.1 Python Dependency Ecosystem**

ML applications depend heavily on:

- TensorFlow,

- Keras,

- NumPy,

- PyTorch,

- and numerous transitive dependencies.

Threats include:

- dependency confusion,

- typosquatting,

- compromised packages,

- and vulnerable transitive libraries.

**6.4.2 Native Binary Components**

Machine learning frameworks rely extensively on:

- compiled C/C++ binaries,

- dynamically linked libraries,

- GPU kernels,

- and hardware acceleration modules.

Threats include:

- buffer overflows,

- integer overflows,

- use-after-free vulnerabilities,

- and unsafe memory operations.

**6.4.3 Serialized Models and Computational Graphs**

Modern machine learning frameworks frequently utilize serialized model artifacts and computational graph representations to support portability, deployment, distributed execution, interoperability, and runtime optimization. These serialized artifacts allow trained models to be transferred across systems and executed in heterogeneous environments without requiring direct access to the original training code.

Frameworks such as TensorFlow, Keras, PyTorch, and ONNX rely on serialization mechanisms that encapsulate:

- model architectures,

- computational graphs,

- tensor operations,

- operators,

- metadata,

- weights,

- execution descriptors,

- and runtime configuration information.

In TensorFlow, for example, the SavedModel format stores graph definitions, variable states, signatures, and execution metadata necessary for deployment and inference. Similarly, ONNX representations provide standardized graph-based interchange formats that enable model portability across different frameworks and runtime environments.

Computational graphs define execution flows that describe how tensor operations are evaluated and propagated throughout the machine learning pipeline. These graphs may include:

- mathematical operators,

- data transformation functions,

- execution dependencies,

- hardware optimization directives,

- and runtime execution paths.

Because serialized computational graphs abstract execution behavior into portable representations, they frequently span multiple software layers, including:

- application-level APIs,

- framework execution engines,

- native binary libraries,

- hardware acceleration runtimes,

- and operating system interfaces.

Serialized model artifacts therefore represent a critical architectural component of modern machine learning ecosystems. Although these mechanisms improve scalability, portability, and deployment efficiency, they also introduce additional complexity and expand the overall software attack surface.

Understanding the structure and behavior of serialized computational graphs is therefore essential for analyzing machine learning software ecosystems and identifying how execution logic propagates across multiple layers of the underlying software stack.

**6.4.4 Serialized Model Security Implications**

Although serialized machine learning artifacts improve portability, interoperability, and deployment flexibility, they also introduce significant security risks because serialized computational graphs may encapsulate executable behaviors, runtime operators, metadata, and hidden execution logic. Unlike traditional static configuration files, serialized model artifacts frequently participate directly in runtime execution and may invoke complex framework functionality during model loading, initialization, inference, and distributed processing.

Recent research demonstrates that serialized machine learning artifacts such as TensorFlow SavedModel files may expose hidden attack surfaces capable of performing:

- unauthorized file access,

- network communication,

- runtime API invocation,

- arbitrary execution behaviors,

- and hidden operator execution.

These risks are amplified because serialized graphs frequently operate across multiple software layers, including:

- application code,

- framework execution engines,

- native libraries,

- hardware acceleration runtimes,

- and infrastructure environments.

As a result, malicious or tampered model artifacts may propagate unsafe behavior throughout the machine learning ecosystem while remaining difficult to detect through traditional source-level security analysis techniques.

Potential threats associated with serialized model artifacts include:

- malicious graph execution,

- embedded executable behaviors,

- hidden operators,

- unauthorized runtime invocation,

- model tampering,

- poisoned pretrained models,

- unsafe deserialization,

- and abuse of undocumented framework APIs.

An attacker may, for example, distribute a pretrained model containing manipulated computational graphs designed to trigger unexpected runtime behavior during inference or deployment. Because many machine learning workflows rely on externally sourced pretrained models obtained from repositories, model hubs, or third-party providers, the integrity and trustworthiness of serialized artifacts become critical security concerns.

Additional risks arise from the complexity of modern computational graph execution. Serialized models may invoke dynamically loaded native operators, runtime plugins, GPU kernels, and external libraries that are not fully visible at the application layer. Consequently, vulnerabilities embedded within lower software layers may remain hidden from developers and security tools operating solely at the Python source-code level.

Serialized model security therefore represents an important component of machine learning software assurance. Effective security analysis requires inspection not only of application code and dependencies, but also of:

- graph structures,

- execution operators,

- runtime interactions,

- metadata relationships,

- and hidden execution paths embedded within serialized machine learning artifacts.

For these reasons, the proposed Unified Multilayer Security Analysis Framework (UMSAF) incorporates serialized model inspection and computational graph analysis as core components of its multilayer security analysis methodology.

**6.4.5 Runtime Execution Environment**

Threats may arise during:

- model loading,

- training,

- inference,

- GPU execution,

- and distributed computation.

Potential attacks include:

- runtime manipulation,

- execution hijacking,

- and silent computational corruption.

**6.4.6 Operating System and Infrastructure Layer**

Underlying infrastructure may introduce:

- insecure system libraries,

- vulnerable drivers,

- container escape vulnerabilities,

- or cloud misconfigurations.

**6.5 Threat Categories**

The threat model categorizes threats into the following classes.

**6.5.1 Software Supply-Chain Attacks**

Examples:

- compromised dependencies,

- malicious wheel files,

- dependency poisoning.

**6.5.2 Native Memory Corruption**

Examples:

- heap overflows,

- stack corruption,

- use-after-free conditions,

- integer overflows.

**6.5.3 Malicious Model Artifacts**

Examples:

- poisoned models,

- malicious SavedModel files,

- hidden executable behaviors.

**6.5.4 Silent Computational Failures**

Examples:

- incorrect inference results,

- hidden training corruption,

- numerical instability,

- silent framework bugs.

**6.5.5 Adversarial ML Attacks**

Examples:

- adversarial inputs,

- model extraction,

- inference manipulation,

- evasion attacks.

**6.5.6 Runtime and Infrastructure Threats**

Examples:

- GPU runtime exploitation,

- insecure distributed execution,

- cloud infrastructure compromise.

**6.6 Trust Boundaries**

The framework identifies several critical trust boundaries:

| **Boundary**                             | **Description**                                |
|------------------------------------------|------------------------------------------------|
| Python ↔ Native Binary                   | Transition from managed to unmanaged execution |
| Application ↔ External Dependencies      | Trust in third-party packages                  |
| Serialized Model ↔ Runtime               | Execution of imported computational graphs     |
| Framework ↔ Hardware Layer               | GPU/kernel interaction                         |
| Local Environment ↔ Cloud Infrastructure | Distributed deployment boundary                |

These boundaries represent locations where:

- assumptions may fail,

- privilege transitions occur,

- and vulnerabilities may propagate.

**6.7 Threat Propagation Across Layers**

A key assumption of this research is that vulnerabilities propagate across multiple software layers.

Example propagation path:

Malicious Python Package  
↓  
Compromised Native Binary  
↓  
Unsafe Runtime Execution  
↓  
System-Level Compromise

Another example:

Malicious SavedModel  
↓  
TensorFlow Graph Execution  
↓  
Hidden Native API Invocation  
↓  
Unauthorized System Access

These propagation paths demonstrate why isolated analysis techniques are insufficient.

**6.8 Security Objectives**

The proposed framework seeks to improve the following security properties:

| **Objective**   | **Description**                                      |
|-----------------|------------------------------------------------------|
| Integrity       | Detect tampered dependencies and binaries            |
| Confidentiality | Prevent unauthorized access through malicious models |
| Availability    | Detect denial-of-service vulnerabilities             |
| Transparency    | Improve visibility into hidden native execution      |
| Traceability    | Map vulnerabilities across layers                    |
| Trustworthiness | Improve confidence in ML ecosystems                  |

**6.9 Threat Model Implications for UMSAF**

The threat model directly motivates the design of the proposed framework.

Specifically, UMSAF will:

- analyze dependency chains,

- inspect native binaries,

- reverse engineer ML components,

- inspect serialized models,

- map cross-layer interactions,

- and identify threat propagation paths.

This enables comprehensive visibility into vulnerabilities that are otherwise hidden within modern machine learning software ecosystems.

## **6.10 ML Software Ecosystem Layer Model**

The proposed research models machine learning software ecosystems as multilayer architectures composed of interconnected application, framework, runtime, binary, and infrastructure components. This conceptual model provides the foundation for analyzing how vulnerabilities propagate across machine learning ecosystems and how hidden execution behavior emerges across multiple abstraction layers.

The model consists of the following layers:

Application Layer  
↓  
ML Framework Layer  
↓  
Serialization / Computational Graph Layer  
↓  
Native Binary Layer  
↓  
Runtime / Hardware Acceleration Layer  
↓  
Operating System / Infrastructure Layer

Each layer introduces distinct attack surfaces, trust boundaries, dependency relationships, and vulnerability propagation paths.

The **Application Layer** contains developer-written Python code, external APIs, training scripts, inference logic, and user-facing functionality. Although this layer is typically the most visible to developers, many critical execution paths occur in lower layers outside direct application visibility.

The **ML Framework Layer** includes frameworks such as TensorFlow, Keras, PyTorch, and NumPy. These frameworks provide abstractions for tensor computation, model training, graph execution, optimization, and deployment. Because these frameworks expose high-level APIs while internally relying on native implementations, vulnerabilities within lower layers may remain hidden from application developers.

The **Serialization and Computational Graph Layer** includes serialized model artifacts such as TensorFlow SavedModel files, ONNX representations, computational graphs, operators, metadata, and execution descriptors. These artifacts may encapsulate executable logic and hidden runtime behaviors, thereby introducing additional attack surfaces associated with model tampering, malicious serialization, hidden operators, and unauthorized execution paths.

The **Native Binary Layer** contains compiled C and C++ libraries, dynamically linked modules, numerical computation engines, tensor operation implementations, and hardware interaction components. This layer represents one of the most critical security boundaries because it frequently contains memory-unsafe code capable of introducing vulnerabilities such as buffer overflows, integer overflows, use-after-free conditions, and unsafe memory operations.

The **Runtime and Hardware Acceleration Layer** includes GPU runtimes, CUDA libraries, distributed execution engines, thread schedulers, memory managers, and hardware optimization frameworks. Runtime environments may introduce additional security risks associated with execution inconsistencies, distributed computation, hardware-specific behavior, and silent computational failures.

Finally, the **Operating System and Infrastructure Layer** includes system libraries, containerization environments, cloud infrastructure, orchestration platforms, drivers, and deployment configurations. Vulnerabilities at this layer may propagate upward into machine learning frameworks and application-level behavior.

A key assumption of this research is that vulnerabilities within machine learning ecosystems frequently propagate across multiple layers rather than remaining isolated within a single software component. For example, a compromised Python dependency may introduce malicious native binaries, which subsequently affect runtime execution and system-level behavior. Similarly, malicious serialized model artifacts may invoke hidden runtime operations that bypass application-level security controls.

This layered conceptual model therefore provides the foundation for the proposed Unified Multilayer Security Analysis Framework (UMSAF), enabling cross-layer visibility into dependencies, binaries, runtime behaviors, serialized artifacts, and vulnerability propagation paths across modern machine learning software ecosystems.

## **7. Research Timeline** 

This research will follow an **accelerated timeline**, reflecting prior progress and the goal of submitting the first research paper by **August 2026**, with full completion targeted for **December 2026**.

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

# **8. Related Work **

# Existing machine learning security research has evolved from isolated studies of adversarial examples toward broader concerns involving software vulnerabilities, runtime behaviors, software supply chains, binary analysis, and lifecycle threat modeling. This evolution reflects a growing recognition that modern ML systems function as complex software ecosystems requiring holistic security assurance methodologies.

## **8.1 Reverse Engineering and Binary Analysis**

Reverse engineering is a well-established technique for analyzing compiled software, uncovering hidden behaviors, and identifying vulnerabilities in binary executables. Tools such as Ghidra, IDA Pro, and Binary Ninja provide capabilities including disassembly, decompilation, control-flow graph reconstruction, and symbolic analysis.

Traditionally, reverse engineering has been applied to malware analysis, exploit development, and standalone binary inspection. However, its application to **machine learning (ML) frameworks** remains limited. This gap is significant because modern ML systems rely heavily on compiled native libraries written in C and C++, where many security-critical operations occur. Existing research has not sufficiently integrated reverse engineering with higher-level software analysis, particularly in the context of Python-based ML systems.

## **8.2 Static Analysis Limitations in Machine Learning Libraries**

Static analysis tools have been widely adopted for detecting software bugs and vulnerabilities. However, recent empirical studies demonstrate that these tools are largely ineffective for ML libraries.

A comprehensive study analyzing 410 real-world bugs across popular ML libraries—including TensorFlow, PyTorch, and MXNet—found that state-of-the-art static analysis tools detected only **approximately 0.01% of vulnerabilities (5–6 out of 410)** . A parallel study on vulnerability detection confirmed similar findings, showing that static tools fail to detect the vast majority of real-world vulnerabilities in ML systems .

These results highlight fundamental limitations of static analysis when applied to ML libraries:

- ML libraries exhibit **high complexity and data dependency**

- Many vulnerabilities arise from **runtime behaviors**

- Critical operations are implemented in **native C/C++ code**

- Static tools lack visibility into **cross-layer interactions**

These findings strongly motivate the need for alternative approaches that go beyond traditional static analysis.

## **8.3 Characteristics of Vulnerabilities in ML Libraries**

Understanding the nature of vulnerabilities in ML systems is essential for designing effective detection mechanisms. A large-scale empirical study analyzing **683 vulnerabilities across seven major ML libraries** (including TensorFlow, NumPy, and SciPy) provides critical insights into their characteristics .

The study identifies key dimensions of ML vulnerabilities:

- **Root Causes:** improper input validation, memory mismanagement

- **Symptoms:** crashes, incorrect outputs, undefined behavior

- **Fix Patterns:** validation checks, algorithmic corrections

- **Distribution:** vulnerabilities appear across all stages of the ML pipeline

Importantly, the study highlights that vulnerabilities in ML libraries are:

- **Systematic but poorly understood**

- Often **different from traditional software vulnerabilities**

- Spread across both **API-level and implementation-level code**

This supports the need for a framework capable of **classifying and modeling vulnerabilities across multiple layers**.

## **8.4 Native Code as the Primary Attack Surface**

Machine learning frameworks rely heavily on native implementations for performance optimization. Studies on TensorFlow-based systems show that many vulnerabilities originate from **C/C++ components**, including:

- Memory corruption

- Integer overflow

- NULL pointer dereference

- Improper input validation

These vulnerabilities are often associated with high-severity impacts on system confidentiality, integrity, and availability .

This observation is critical: although ML applications are written in Python, their **security risks are largely embedded in native binaries**. As a result, approaches that analyze only Python source code fail to capture the true attack surface.

## **8.5 Limitations of Fuzzing and Dynamic Testing**

Fuzz testing has emerged as a promising technique for identifying vulnerabilities in ML libraries. Recent work proposes advanced fuzzers that leverage historical vulnerability patterns and guided input generation to discover security flaws.

For example, a security knowledge-guided fuzzer identified **135 vulnerabilities in TensorFlow and PyTorch**, including 69 previously unknown issues . However, despite these successes, fuzzing techniques face several limitations:

- Difficulty generating **semantically valid input combinations**

- Limited coverage of **developer-level APIs**

- Incomplete modeling of **internal execution paths**

- Lack of integration with **dependency and binary analysis**

These limitations suggest that fuzzing alone is insufficient and must be complemented by structural analysis techniques.

## **8.6 Multilayer Architecture of Machine Learning Systems**

Modern ML systems exhibit a multilayer architecture consisting of:

Application → ML Library → Framework → Native Backend

Research on deep learning systems demonstrates that faults and vulnerabilities can originate at any of these layers, including the application code, third-party libraries, and underlying frameworks .

This multilayer structure introduces several challenges:

- Dependencies span multiple abstraction levels

- Errors propagate across layers

- Security analysis requires **holistic system modeling**

Existing tools typically analyze only a single layer, failing to capture the interactions between components.

## **8.7 Fault Injection and Runtime Behavior Analysis**

Fault injection techniques have been used to study the resilience of ML systems under various failure conditions. Tools such as TensorFlow-specific fault injectors demonstrate that ML systems exhibit complex and sometimes unpredictable behavior under injected faults .

These findings indicate that:

- Runtime behavior differs significantly from static expectations

- Faults in lower layers can propagate to higher-level outputs

- Native execution layers are difficult to inspect and control

This further supports the need for deeper analysis techniques, including reverse engineering and cross-layer modeling.

## **8.8 Security Implications in Real-World Applications**

Machine learning systems are increasingly deployed in safety-critical domains, including:

- Autonomous vehicles

- Healthcare systems

- Financial services

- Cybersecurity applications

For example, ML techniques have been used to detect zero-day attacks in real-world environments, demonstrating both their utility and their exposure to emerging threats .

The widespread adoption of ML amplifies the impact of vulnerabilities, making robust security analysis essential.

## **8.9 Gap Analysis and Research Positioning**

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

## **8.10 Positioning of This Research**

This dissertation addresses the identified gaps by proposing a **unified multilayer security analysis framework** that integrates:

- Dependency graph extraction

- SBOM generation

- Vulnerability intelligence (CVE / OSV)

- Binary reverse engineering

- Cross-layer interaction modeling

- Machine learning-based risk classification

Unlike prior work, this research:

✔ Demonstrates the **limitations of existing tools using empirical evidence**  
✔ Targets **native components within ML frameworks**  
✔ Models **interactions across software layers**  
✔ Combines **software engineering, cybersecurity, and machine learning techniques**  
✔ Provides a **scalable and automated approach** for securing ML systems

**8.11 Evolution of Machine Learning Security**

Early machine learning security research focused primarily on adversarial attacks against trained models. Initial studies demonstrated that carefully crafted perturbations could manipulate neural network predictions while remaining nearly imperceptible to human observers. These findings established that machine learning systems were vulnerable to input-level manipulation and evasion attacks.

Subsequent research expanded beyond adversarial examples to include poisoning attacks, model extraction, model inversion, and privacy leakage. Poisoning attacks demonstrated that maliciously modified training data could influence model behavior, while model extraction attacks showed that attackers could reconstruct proprietary models through repeated query interactions. Additional work on model inversion revealed that sensitive training information could sometimes be reconstructed from model outputs.

As machine learning frameworks became widely adopted in production environments, researchers increasingly recognized that security risks extend beyond model robustness into the underlying software infrastructure itself. Recent studies have identified vulnerabilities within TensorFlow, PyTorch, NumPy, and related libraries, including memory corruption flaws, runtime vulnerabilities, serialization risks, and software supply-chain weaknesses.

More recent work further expanded the field toward lifecycle-oriented machine learning security, incorporating:

- dependency management,

- model distribution,

- serialized model security,

- runtime behavior analysis,

- binary reverse engineering,

- and software assurance methodologies.

This evolution demonstrates that machine learning security has transitioned from a narrow focus on adversarial robustness into a broader discipline encompassing software engineering, cybersecurity, software supply-chain analysis, and runtime system assurance.

**8.12 Security Vulnerabilities in ML Frameworks**

Machine learning frameworks such as TensorFlow, Keras, PyTorch, and NumPy contain large native codebases implemented primarily in C and C++ for performance optimization. While these native implementations enable efficient numerical computation and hardware acceleration, they also introduce traditional software security risks commonly associated with low-level systems programming.

Recent studies have identified numerous vulnerabilities within machine learning frameworks, including:

- buffer overflows,

- integer overflows,

- use-after-free conditions,

- NULL pointer dereferences,

- memory corruption vulnerabilities,

- and improper input validation.

Many of these vulnerabilities originate within native components responsible for tensor operations, serialization, graph execution, and GPU acceleration. Research also demonstrates that vulnerabilities frequently propagate through transitive dependency chains and embedded third-party libraries.

An important observation from prior work is that many vulnerabilities remain invisible to application developers because the affected components operate beneath high-level Python abstractions. Consequently, developers may unknowingly deploy vulnerable native binaries even when application-level source code appears secure.

These findings strongly motivate the need for security analysis approaches capable of inspecting both high-level machine learning applications and their underlying native implementations.

**8.13 Bugs and Silent Failures in Deep Learning Systems**

Deep learning systems exhibit unique failure characteristics that differ substantially from conventional software systems. In addition to explicit crashes and runtime exceptions, machine learning frameworks may experience silent computational failures in which incorrect outputs are produced without visible indicators of failure.

Recent empirical studies identified numerous silent bugs within TensorFlow and Keras systems. These bugs include:

- incorrect tensor computations,

- silent training corruption,

- numerical instability,

- inconsistent inference behavior,

- and invalid gradient calculations.

Silent failures are particularly dangerous because machine learning outputs are often probabilistic and difficult to validate manually. Consequently, incorrect behavior may remain undetected for extended periods while still producing apparently plausible results.

Additional studies demonstrate that runtime behaviors in machine learning frameworks may vary across:

- hardware configurations,

- compiler optimizations,

- execution backends,

- and distributed processing environments.

These findings suggest that conventional software testing techniques are insufficient for identifying many classes of machine learning failures. As a result, runtime analysis, behavioral tracing, anomaly detection, and cross-layer monitoring become essential components of ML security assurance.

**8.14 Reverse Engineering of ML Systems**

Reverse engineering techniques have traditionally been applied to malware analysis, binary inspection, exploit analysis, and software recovery. These techniques include:

- disassembly,

- decompilation,

- control-flow reconstruction,

- symbolic analysis,

- and dynamic tracing.

Recent research demonstrates that these techniques are increasingly applicable to machine learning systems and deep learning frameworks. Studies show that compiled ML binaries can reveal:

- neural network structures,

- operator implementations,

- computational graphs,

- and execution behaviors.

Additional work demonstrates that reverse engineering techniques may recover:

- model architectures,

- hyperparameters,

- layer relationships,

- and internal execution logic from deployed binaries.

Modern ML frameworks rely heavily on native libraries implemented in C and C++, making them suitable targets for binary analysis and reverse engineering tools such as Ghidra and IDA Pro. Furthermore, the growing complexity of TensorFlow and similar frameworks introduces opaque execution layers that are difficult to analyze through source-level inspection alone.

These findings support the feasibility of applying reverse engineering methodologies to machine learning software ecosystems as part of a broader security analysis framework.

**8.15 ML Threat Assessment and Lifecycle Security**

Machine learning systems introduce security risks across the entire software lifecycle, including:

- data collection,

- model training,

- model serialization,

- deployment,

- inference,

- and runtime execution.

Threat modeling research demonstrates that vulnerabilities may propagate across multiple layers of ML ecosystems, including:

- application code,

- framework libraries,

- serialized computational graphs,

- native binaries,

- and infrastructure environments.

Training-phase attacks such as data poisoning and malicious model injection can compromise model integrity before deployment. During deployment, serialized artifacts such as TensorFlow SavedModel files may contain hidden operators or malicious execution logic. Runtime environments further introduce risks associated with GPU execution, distributed processing, and hardware acceleration.

Recent work also highlights the importance of software supply-chain security in machine learning ecosystems. ML applications frequently depend on large numbers of third-party packages, pretrained models, and external repositories, increasing exposure to dependency compromise and malicious package insertion.

These observations reinforce the need for lifecycle-oriented security methodologies capable of analyzing machine learning systems holistically rather than focusing solely on isolated components.

**8.16 Testing and Validation of Deep Learning Libraries**

Testing deep learning systems presents unique challenges due to:

- nondeterministic execution,

- numerical instability,

- hardware acceleration,

- and complex runtime behavior.

Traditional software testing approaches are often insufficient because many machine learning failures do not produce explicit exceptions or deterministic outputs. As a result, researchers have proposed specialized testing methodologies for deep learning systems.

Fuzzing techniques have been applied to machine learning frameworks to identify vulnerabilities through malformed or unexpected inputs. Recent fuzzing approaches guided by vulnerability knowledge and API behavior have successfully identified vulnerabilities within TensorFlow and PyTorch libraries.

Additional research has explored:

- mutation testing,

- differential testing,

- metamorphic testing,

- and runtime validation techniques for ML systems.

Mutation testing evaluates whether testing frameworks can detect intentionally modified defects, while differential testing compares outputs across multiple implementations or execution environments. Metamorphic testing validates expected behavioral relationships between transformed inputs and outputs.

These approaches demonstrate that effective machine learning security analysis requires a combination of:

- static analysis,

- dynamic analysis,

- runtime validation,

- behavioral monitoring,

- and cross-layer inspection techniques.

Consequently, comprehensive testing methodologies represent an important component of secure machine learning software engineering.

# **9. Preliminary Study**

## **9.1 Overview**

To evaluate the feasibility of the proposed multilayer security analysis framework, a preliminary study was conducted using a basic image recognition application implemented in Python. The objective of this study is to demonstrate how vulnerabilities and security-relevant characteristics can be identified across multiple layers of a machine learning (ML) software stack, including Python source code, third-party libraries, and native binary components.

The study focuses on analyzing widely used ML frameworks—specifically TensorFlow, Keras, and NumPy—which are representative of modern deep learning ecosystems and are known to rely heavily on native C and C++ implementations.

## **9.2 Experimental Setup**

To evaluate the feasibility of the proposed Unified Multilayer Security Analysis Framework (UMSAF), a preliminary experimental environment was developed using a simplified convolutional neural network (CNN) application implemented in Python with TensorFlow and Keras. The purpose of this experimental setup is to provide a controlled and reproducible machine learning application suitable for dependency analysis, SBOM generation, vulnerability assessment, binary extraction, reverse engineering, and cross-layer interaction analysis.

The experimental application utilizes the CIFAR-10 dataset, a widely used benchmark dataset for image classification research. CIFAR-10 contains 60,000 color images distributed across 10 object categories and is commonly used for evaluating deep learning models and machine learning frameworks.

The preliminary CNN application performs the following operations:

- dataset loading,

- data normalization,

- convolutional neural network construction,

- model compilation,

- and supervised training.

Although intentionally simplified, the application is sufficient to trigger interactions across multiple machine learning ecosystem layers, including:

- Python application code,

- TensorFlow and Keras framework APIs,

- serialized model structures,

- native C/C++ libraries,

- and runtime execution components.

The following experimental application was used throughout the preliminary study.

Listing 1 — Preliminary CNN Experimental Application

import tensorflow as tf

from tensorflow import keras

import numpy as np

\# Load CIFAR-10 dataset

(x_train, y_train), (x_test, y_test) = keras.datasets.cifar10.load_data()

\# Normalize image data

x_train = x_train / 255.0

x_test = x_test / 255.0

\# Build CNN model

model = keras.Sequential(\[

keras.layers.Conv2D(32, (3, 3), activation='relu'),

keras.layers.MaxPooling2D(),

keras.layers.Flatten(),

keras.layers.Dense(64, activation='relu'),

keras.layers.Dense(10, activation='softmax')

\])

\# Compile model

model.compile(

optimizer='adam',

loss='sparse_categorical_crossentropy',

metrics=\['accuracy'\]

)

\# Train model

model.fit(x_train, y_train, epochs=2)

The application serves as the entry point for multilayer security analysis and enables observation of interactions between high-level Python APIs and underlying native machine learning framework components. During execution, TensorFlow and Keras invoke multiple native binaries, dynamically linked libraries, runtime execution engines, and hardware-acceleration modules that can subsequently be analyzed using dependency analysis, SBOM generation, binary extraction, reverse engineering, and runtime tracing techniques.

This experimental setup therefore provides a practical foundation for evaluating the proposed multilayer security analysis methodology across modern machine learning software ecosystems

**9.2.1 Experimental Environment**

The preliminary experiments conducted in this research utilized a controlled machine learning analysis environment designed to support dependency analysis, vulnerability scanning, binary extraction, reverse engineering, runtime inspection, and serialized model analysis.

The experimental environment consisted primarily of Linux-based systems due to the widespread use of Linux within machine learning development, cloud deployment, and scientific computing environments. The primary analysis platform utilized Ubuntu 24.04 LTS running on x86_64 architecture.

The machine learning software stack included:

- Python 3.12,

- TensorFlow 2.18,

- Keras 3.x,

- NumPy 2.x,

- and supporting scientific computing libraries commonly used within modern machine learning ecosystems.

Additional experimental configurations may include PyTorch and ONNX environments for comparative analysis and framework interoperability testing.

Reverse engineering and binary analysis activities were performed using:

- Ghidra 11.x,

- objdump,

- readelf,

- strings,

- dependency inspection utilities,

- and additional Linux binary-analysis tools.

Software dependency analysis and SBOM generation utilized:

- pip dependency inspection,

- CycloneDX SBOM tooling,

- pip-audit,

- OSV vulnerability feeds,

- CVE/NVD databases,

- and software composition analysis techniques.

The experimental environment also incorporated isolated virtual environments and containerized execution contexts to improve reproducibility and reduce contamination between experiments. Where applicable, Docker-based environments were used to reproduce framework-specific runtime behavior and dependency configurations.

Hardware acceleration support was enabled in selected experiments through NVIDIA GPU infrastructure and CUDA runtime libraries in order to analyze:

- GPU-related execution paths,

- hardware-accelerated tensor operations,

- runtime dependency loading,

- and framework interactions with hardware acceleration layers.

The preliminary study utilized a basic image-recognition application based on the CIFAR-10 dataset to evaluate:

- dependency resolution,

- SBOM generation,

- vulnerability discovery,

- native library extraction,

- computational graph analysis,

- and runtime behavior tracing.

This experimental environment provides a reproducible and extensible platform for evaluating the proposed Unified Multilayer Security Analysis Framework (UMSAF) across multiple machine learning frameworks, dependency ecosystems, runtime environments, and binary execution layers.

## **9.3 Dependency and SBOM Analysis**

The first phase of the preliminary study involved identifying the complete dependency tree of the application.

### **Findings:**

- TensorFlow introduces a large number of transitive dependencies

- Dependencies include both Python packages and compiled binaries

- Many dependencies are not directly visible to developers

An SBOM was generated to capture:

- Package names and versions

- Dependency relationships

- Distribution artifacts (wheels)

This step demonstrates that even simple ML programs rely on **complex and deep dependency chains**, supporting prior findings that ML systems have extensive software supply chains .

## **9.4 Vulnerability Scanning**

Dependency scanning tools were applied to identify known vulnerabilities using CVE and OSV databases.

### **Observations:**

- Vulnerabilities were detected in transitive dependencies

- Many vulnerabilities were associated with:

  - Input validation issues

  - Memory-related flaws

- Some vulnerabilities originated from components not directly used in the application code

These findings align with prior research showing that vulnerabilities in ML libraries are widespread and often hidden within dependency chains

## **9.5 Binary Extraction and Analysis**

A key focus of this study was extracting and analyzing native binary components embedded in ML frameworks.

### **Process:**

1.  Download TensorFlow and NumPy wheel packages

2.  Extract .so, .pyd, and .dll files

3.  Identify native modules (e.g., TensorFlow internal wrappers)

### **Key Findings:**

- TensorFlow includes large native binaries such as:

  - \_pywrap_tensorflow_internal

- NumPy includes compiled C extensions

- Native libraries link to external dependencies (e.g., BLAS, MKL)

These results confirm that ML frameworks are **not purely Python-based**, but heavily depend on native code.

## **9.6 Reverse Engineering Analysis**

Selected binaries were analyzed using Ghidra.

### **Analysis Focus:**

- Function structures

- Imported libraries

- Strings and symbols

- Control-flow patterns

### **Observations:**

- Complex native functions handle core ML computations

- External libraries are dynamically linked

- Low-level operations (memory management, numerical computation) are present

These findings support prior research indicating that many vulnerabilities originate in native C/C++ components of ML frameworks

## **9.7 Cross-Layer Interaction Analysis**

The study examined how Python code interacts with native binaries.

### **Observed Execution Flow:**

Python Application  
↓  
TensorFlow / Keras API  
↓  
Python Wrapper Layer  
↓  
Native C/C++ Implementation  
↓  
System Libraries / Hardware

This confirms that:

- Python acts as an abstraction layer

- Critical operations occur in native code

- Security risks may originate in lower layers

This multilayer interaction aligns with prior findings that ML systems require holistic analysis across layers

## **9.8 Preliminary Findings**

The preliminary study reveals several important insights:

### **1. Hidden Complexity**

Even simple ML programs depend on large and complex ecosystems.

### **2. Native Code Dominance**

Security-critical operations occur in native binaries rather than Python code.

### **3. Vulnerability Distribution**

Vulnerabilities exist across multiple layers, particularly in dependencies.

### **4. Tool Limitations**

Traditional tools do not provide full visibility into:

- Binary internals

- Cross-layer interactions

This aligns with prior findings that static analysis tools are largely ineffective for ML libraries .

## **9.9 Implications for Proposed Research**

This preliminary study validates the feasibility of the proposed research framework.

It demonstrates that:

✔ Dependency analysis is achievable  
✔ SBOM generation is practical  
✔ Vulnerabilities can be identified in ML ecosystems  
✔ Native binaries can be extracted and analyzed  
✔ Cross-layer interactions can be modeled

Most importantly, it confirms that:

A unified framework integrating these techniques is both necessary and feasible.

# **10. Proposed Framework**

## **10.1 Overview**

This research proposes a **Unified Multilayer Security Analysis Framework (UMSAF)** designed to analyze Python-based machine learning (ML) systems that rely on native C/C++ libraries. The framework integrates software composition analysis, binary reverse engineering, vulnerability intelligence, and machine learning techniques to provide comprehensive security analysis across multiple software layers.

The primary goal of the framework is to overcome the limitations of existing tools by enabling **end-to-end visibility from Python source code to native binary execution**, thereby identifying vulnerabilities that are otherwise undetectable through isolated analysis approaches.

Unlike traditional approaches that analyze source code, dependencies, binaries, or runtime behaviors independently, UMSAF is designed as a holistic security assurance framework capable of correlating findings across multiple layers of the machine learning ecosystem.

## **10.2 Architectural Design**

The proposed framework consists of the following major components:

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

\(5\) Serialized Model Inspection Engine

↓

\(6\) Runtime Behavior & Silent Failure Detection Module

↓

\(7\) Cross-Layer Interaction Mapper

↓

\(8\) Risk Scoring & ML Classification Engine

↓

Security Report & Recommendations

## **10.3 Component Descriptions**

### **10.3.1 Dependency Intelligence Engine**

This component identifies all direct and transitive dependencies of the ML application.

#### **Functions:**

- Resolve dependency trees

- Identify package versions

- Map dependencies to distribution artifacts (wheels, source files)

- Generate dependency graphs

#### **Output:**

- Full dependency graph

- Package metadata

### **10.3.2 SBOM and Vulnerability Analyzer**

This module generates Software Bills of Materials (SBOMs) and performs vulnerability scanning.

#### **Functions:**

- Generate SBOM (CycloneDX / SPDX format)

- Query vulnerability databases (CVE, OSV, NVD)

- Map vulnerabilities to dependencies

- Identify vulnerable versions

#### **Output:**

- SBOM file

- Vulnerability report

### **10.3.3 Binary Extraction Module**

This module extracts native binaries from Python packages.

#### **Functions:**

- Download wheel files

- Extract .so, .pyd, .dll binaries

- Identify compiled extensions

- Collect binary metadata (hashes, architecture, size)

#### **Output:**

- Binary inventory

- Artifact repository

### **10.3.4 Reverse Engineering Engine**

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

### **10.3.5 Serialized Model Inspection Engine**

Functions:

- inspect TensorFlow SavedModel artifacts

- parse computational graphs

- identify hidden operators

- detect suspicious APIs

- inspect embedded execution logic

Output:

- serialized model analysis report

- graph structure report

- suspicious execution mapping

### **10.3.6 Runtime Behavior and Silent Failure Detection Module**

Functions:

- runtime tracing

- anomaly detection

- execution inconsistency analysis

- silent computational deviation detection

- runtime propagation analysis

Output:

- runtime behavior report

- silent-failure analysis

- execution anomaly mapping

### **10.3.7 Cross-Layer Interaction Mapper**

This is a **key innovation of the framework**.

#### **Purpose:**

To model interactions between Python code and native binaries.

#### **Functions:**

- Trace Python imports and API usage

- Map Python functions to native calls

- Construct cross-layer call graphs

#### **Example Mapping:**

model.fit()  
↓  
TensorFlow API  
↓  
Python wrapper (\_pywrap_tensorflow)  
↓  
Native C++ function  
↓  
System library / hardware

#### **Output:**

- Cross-layer interaction graph

- Execution flow mapping

### **10.3.8 Risk Scoring and ML Classification Engine**

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

## **10.4 Data Flow Model**

The framework operates as a pipeline:

1\. Input: Python ML application

2\. Extract dependencies

3\. Generate SBOM

4\. Scan vulnerabilities

5\. Extract binaries

6\. Reverse engineer binaries

7\. Inspect serialized models

8\. Perform runtime behavior analysis

9\. Map cross-layer interactions

10\. Compute risk scores

11\. Generate final report

## **10.5 Key Innovations**

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

Existing tools treat dependencies as black boxes.  
This framework **opens the black box**.

### **4. Binary-Level Security Analysis for ML Systems**

Focuses on native components where vulnerabilities actually reside.

### **5. ML-Based Risk Classification**

Applies machine learning to:

- Prioritize vulnerabilities

- Detect high-risk patterns

## **10.6 System Implementation Plan**

The framework will be implemented as a modular system:

### **Technologies:**

- Python (core framework)

- Dependency tools: pip, pipdeptree

- SBOM tools: CycloneDX

- Vulnerability tools: pip-audit, OSV

- Binary tools: Ghidra

- ML libraries: TensorFlow / scikit-learn

## **10.7 Expected Outputs**

The framework will generate:

1.  Dependency Graph

2.  SBOM Document

3.  Vulnerability Report

4.  Binary Inventory

5.  Reverse Engineering Report

6.  Cross-Layer Interaction Graph

7.  Risk Assessment Report

# **11. Research Methodology & Hypotheses** 

## **11.1 Overview**

This research adopts a **design science and empirical evaluation methodology** to develop and validate the proposed Unified Multilayer Security Analysis Framework (UMSAF). The study combines system design, implementation, and experimental validation using real-world machine learning (ML) applications and known vulnerability datasets.

The methodology is structured into four major phases:

Design → Implementation → Experimentation → Evaluation

## **11.2 Research Design**

### **11.2.1 Approach**

This study follows a **design science research (DSR)** paradigm, where the primary artifact is the proposed framework. The research process includes:

- Problem identification (limitations of current ML security tools)

- Artifact development (UMSAF framework)

- Demonstration (application to ML systems)

- Evaluation (quantitative and qualitative analysis)

## **11.3 Experimental Setup**

### **11.3.1 Subject Systems**

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

### **11.3.2 Data Sources**

The study will utilize:

- CVE / NVD databases

- OSV vulnerability database

- GitHub repositories

- ML vulnerability datasets (e.g., 683 vulnerabilities identified in prior work )

## **11.4 Evaluation Objectives**

The evaluation aims to answer the following:

1.  **Effectiveness:** Can the framework detect vulnerabilities missed by existing tools?

2.  **Coverage:** How much of the ML software stack is analyzed?

3.  **Accuracy:** What is the precision and recall of detected vulnerabilities?

4.  **Scalability:** Can the framework handle large ML systems?

5.  **Insight Generation:** Does the framework provide meaningful cross-layer insights?

## **11.5 Evaluation Metrics**

### **11.5.1 Detection Metrics**

- **True Positives (TP):** Correctly identified vulnerabilities

- **False Positives (FP):** Incorrectly identified vulnerabilities

- **False Negatives (FN):** Missed vulnerabilities

From these:

- **Precision** = TP / (TP + FP)

- **Recall** = TP / (TP + FN)

- **F1 Score** = harmonic mean of precision and recall

### **11.5.2 Coverage Metrics**

- Percentage of dependencies analyzed

- Percentage of binaries extracted and analyzed

- Depth of dependency tree coverage

### **11.5.3 Cross-Layer Metrics**

- Number of mapped Python-to-native interactions

- Completeness of cross-layer call graphs

- Percentage of vulnerabilities linked across layers

### **11.5.4 Performance Metrics**

- Execution time per analysis

- Memory usage

- Scalability with increasing dependency size

## **11.6 Baseline Comparison**

The framework will be compared against existing approaches:

### **Baselines:**

1.  Static analysis tools

2.  Software composition analysis (SCA) tools

3.  Vulnerability scanners

4.  Fuzzing-based approaches (where applicable)

### **Expected Outcome:**

Prior research shows static tools detect only **~0.01% of vulnerabilities** , which establishes a strong baseline for comparison.

## **11.7 Experimental Procedure**

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

## **11.8 Threats to Validity**

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

## **11.9 Expected Results**

The framework is expected to:

✔ Detect vulnerabilities missed by static analysis  
✔ Provide deeper insight into native components  
✔ Improve vulnerability coverage across layers  
✔ Enable better prioritization of security risks

## **11.10 Success Criteria**

The research will be considered successful if:

- Detection accuracy exceeds baseline tools

- Cross-layer interactions are successfully modeled

- Native binary vulnerabilities are identified

- Framework scales to real-world ML applications

## **11.11 Research Hypotheses**

This research is guided by the hypothesis that vulnerabilities within machine learning software ecosystems cannot be fully identified through isolated analysis techniques that examine only application source code, dependency metadata, or binary artifacts independently. Instead, effective machine learning security assurance requires integrated multilayer analysis capable of correlating findings across dependencies, serialized models, native binaries, runtime environments, and infrastructure layers.

To evaluate this assumption, the dissertation proposes the following research hypotheses.

**H1 — Integrated Multilayer Security Analysis Improves Vulnerability Detection**

Integrated multilayer security analysis combining dependency intelligence, SBOM generation, vulnerability intelligence, reverse engineering, serialized model inspection, and runtime analysis will identify vulnerabilities that are not detectable through isolated static analysis techniques alone.

This hypothesis evaluates whether combining multiple analysis layers improves visibility into hidden vulnerabilities within machine learning ecosystems.

**H2 — Binary Reverse Engineering Improves Visibility into ML Ecosystem Attack Surfaces**

Binary reverse engineering combined with dependency analysis improves visibility into machine learning ecosystem attack surfaces by identifying unsafe native operations, hidden execution paths, dynamically loaded components, and undocumented runtime behaviors embedded within native machine learning libraries.

This hypothesis evaluates the effectiveness of reverse engineering techniques when applied to TensorFlow, Keras, NumPy, and related native ML components.

**H3 — Cross-Layer Interaction Modeling Improves Vulnerability Traceability**

Cross-layer interaction modeling improves the ability to trace vulnerabilities across machine learning software ecosystems by correlating:

- Python application behavior,

- framework API interactions,

- serialized computational graphs,

- native binary execution,

- and runtime dependencies.

This hypothesis evaluates whether vulnerabilities propagating across multiple software layers can be identified more effectively through ecosystem-level interaction analysis.

**H4 — Serialized Model Inspection Identifies Hidden Malicious Functionality**

Serialized model inspection and computational graph analysis can identify hidden malicious functionality, suspicious operators, unauthorized runtime interactions, and unsafe execution behaviors that are not detectable through conventional source-code analysis techniques.

This hypothesis specifically evaluates the security implications of TensorFlow SavedModel artifacts, computational graphs, and serialized execution structures.

**H5 — Runtime Behavior Analysis Improves Detection of Silent Failures**

Runtime behavioral analysis and execution tracing improve detection of silent computational failures, anomalous inference behaviors, inconsistent runtime execution paths, and hidden framework-level faults within machine learning systems.

This hypothesis evaluates whether runtime monitoring provides additional visibility into failure conditions that may remain undetected through static analysis and dependency inspection alone.

**H6 — Holistic Ecosystem Analysis Improves Machine Learning Software Assurance**

Holistic ecosystem-level security analysis integrating software engineering, cybersecurity, reverse engineering, runtime analysis, and supply-chain intelligence improves the overall security assurance and trustworthiness of machine learning software ecosystems.

This hypothesis represents the overarching conceptual foundation of the dissertation and evaluates whether machine learning systems should be analyzed as interconnected software ecosystems rather than isolated software components.

Collectively, these hypotheses guide the design, implementation, and evaluation of the proposed Unified Multilayer Security Analysis Framework (UMSAF). The experimental evaluation described in later sections of this dissertation will assess the validity of these hypotheses using real-world machine learning applications, known vulnerabilities, serialized model artifacts, and native machine learning libraries.

## **11.12 Cross-Layer Vulnerability Propagation Analysis**

A central assumption of this research is that vulnerabilities within machine learning software ecosystems frequently propagate across multiple software and runtime layers rather than remaining isolated within a single component. Consequently, understanding how vulnerabilities traverse dependencies, frameworks, binaries, serialized artifacts, and runtime environments represents a critical aspect of machine learning security assurance.

The proposed Unified Multilayer Security Analysis Framework (UMSAF) incorporates cross-layer vulnerability propagation analysis to model relationships between:

- application-level code,

- machine learning frameworks,

- serialized computational graphs,

- native binaries,

- runtime environments,

- and infrastructure components.

The objective of this analysis is to identify how vulnerabilities introduced at one layer may influence behavior or security properties at other layers within the machine learning ecosystem.

For example, a compromised Python dependency may introduce a malicious native binary that subsequently affects:

- runtime execution,

- memory management,

- hardware acceleration,

- or operating system interactions.

Similarly, a malicious serialized TensorFlow SavedModel artifact may invoke hidden operators capable of triggering unauthorized file access, runtime API invocation, or unexpected execution paths during inference or deployment.

To analyze these relationships, UMSAF constructs cross-layer interaction maps that correlate:

- Python imports,

- framework API calls,

- serialized graph structures,

- dynamically loaded libraries,

- native function invocations,

- runtime execution traces,

- and infrastructure dependencies.

The framework further analyzes:

- dependency chains,

- binary linkage relationships,

- operator mappings,

- and execution flows

to identify possible vulnerability propagation paths across the ecosystem.

The proposed analysis also incorporates runtime behavioral monitoring to detect:

- anomalous execution patterns,

- silent computational deviations,

- inconsistent inference behavior,

- and suspicious runtime interactions.

These runtime observations are correlated with:

- dependency metadata,

- SBOM records,

- binary analysis results,

- and vulnerability intelligence feeds

to improve traceability and risk assessment.

An example propagation path analyzed by the framework is shown below:

Compromised Python Package  
↓  
Malicious Native Binary  
↓  
Unsafe Runtime Execution  
↓  
System-Level Compromise

Another possible propagation scenario involves serialized model artifacts:

Malicious SavedModel Artifact  
↓  
Hidden Computational Graph Operator  
↓  
Native Runtime Invocation  
↓  
Unauthorized System Interaction

These examples illustrate that vulnerabilities within machine learning ecosystems may propagate through multiple interconnected software layers before becoming observable at the application level.

The proposed cross-layer propagation analysis therefore enables:

- improved visibility into hidden attack paths,

- enhanced vulnerability traceability,

- more accurate risk prioritization,

- and stronger machine learning software assurance capabilities.

By correlating vulnerabilities across dependencies, binaries, serialized artifacts, runtime behaviors, and infrastructure layers, the framework seeks to overcome the limitations of isolated security analysis techniques and provide a holistic understanding of machine learning ecosystem security.

# **12. Expected Contributions**

Collectively, these contributions aim to advance machine learning security from isolated vulnerability detection toward holistic software ecosystem assurance methodologies. This dissertation is expected to contribute to the fields of cybersecurity, software engineering, machine learning systems, reverse engineering, and AI software assurance through theoretical, methodological, empirical, and practical advancements.

### **12.1 Theoretical Contributions**

**12.1.1 Multilayer Security Model for Machine Learning Systems**

This research proposes a formalized multilayer security model that characterizes interactions across interconnected machine learning ecosystem layers, including:

Python Application Layer

↓

ML Framework Layer

↓

Serialized Model / Computational Graph Layer

↓

Native Binary Layer

↓

Runtime / Hardware Acceleration Layer

↓

Operating System / Infrastructure Layer

The proposed model advances understanding of how vulnerabilities emerge, propagate, and interact across modern machine learning software stacks.

**12.1.2 Cross-Layer Vulnerability Taxonomy**

This dissertation develops a cross-layer vulnerability taxonomy capable of classifying vulnerabilities according to:

- software layer,

- root cause,

- execution context,

- and propagation behavior.

The taxonomy categorizes vulnerabilities across:

- application layers,

- framework libraries,

- serialized model artifacts,

- native binaries,

- runtime systems,

- and infrastructure environments.

The taxonomy further incorporates:

- memory-safety weaknesses,

- dependency vulnerabilities,

- unsafe serialization behaviors,

- runtime inconsistencies,

- and software supply-chain risks.

**12.1.3 Integrated Security Analysis Paradigm**

This research introduces a holistic security analysis paradigm that unifies:

- software composition analysis (SCA),

- SBOM generation,

- vulnerability intelligence,

- binary reverse engineering,

- runtime analysis,

- and cross-layer interaction modeling.

The proposed paradigm extends beyond isolated vulnerability detection approaches and frames machine learning security as a multilayer software ecosystem assurance problem.

**12.2 Methodological Contributions**

**12.2.1 Unified Multilayer Security Analysis Framework (UMSAF)**

The dissertation proposes the Unified Multilayer Security Analysis Framework (UMSAF), a modular and reproducible analysis pipeline integrating:

- dependency intelligence,

- SBOM generation,

- vulnerability analysis,

- binary extraction,

- reverse engineering,

- serialized model inspection,

- runtime analysis,

- cross-layer interaction mapping,

- and machine learning–based risk scoring.

The framework is designed to provide scalable visibility into vulnerabilities embedded within modern machine learning software ecosystems.

**12.2.2 Cross-Layer Interaction Mapping Methodology**

This research introduces a methodology for correlating:

- Python-level API interactions,

- framework execution flows,

- serialized computational graphs,

- native binary invocations,

- and runtime execution behavior.

The proposed mapping technique improves vulnerability traceability and enables analysis of how security risks propagate across machine learning software layers.

**12.2.3 Binary-Aware Vulnerability Prioritization**

The dissertation develops a binary-aware vulnerability prioritization methodology that combines:

- CVE severity metrics,

- dependency depth,

- binary complexity,

- runtime reachability,

- and execution-path analysis.

This methodology seeks to improve prioritization of vulnerabilities within machine learning ecosystems where many critical risks originate in hidden native components.

**12.3 Empirical Contributions**

**12.3.1 Curated Dataset of Machine Learning Software Vulnerabilities**

This research is expected to produce a curated dataset mapping:

- CVE and OSV records,

- machine learning packages,

- native binaries,

- serialized model artifacts,

- and cross-layer dependency relationships.

The dataset will include reproducible examples and version-specific vulnerability mappings for representative machine learning frameworks.

**12.3.2 Comparative Evaluation of Security Analysis Tools**

The dissertation will evaluate the effectiveness and limitations of existing:

- static analysis tools,

- software composition analysis tools,

- vulnerability scanners,

- fuzzing frameworks,

- and runtime-analysis approaches

when applied to machine learning software ecosystems.

The evaluation will identify security-analysis gaps within current machine learning security tooling.

**12.3.3 Case Studies on TensorFlow, Keras, and NumPy**

The research will present detailed case studies involving TensorFlow, Keras, NumPy, and related machine learning frameworks. These case studies will demonstrate:

- dependency relationships,

- binary extraction,

- reverse engineering results,

- serialized model inspection,

- runtime interactions,

- and cross-layer vulnerability propagation behavior.

**12.4 Practical Contributions**

**12.4.1 Open-Source Prototype Implementation**

This dissertation proposes the development of an open-source prototype tool implementing the UMSAF architecture. The prototype is expected to provide:

- dependency analysis,

- SBOM generation,

- vulnerability reporting,

- binary inventory generation,

- serialized model inspection,

- and interaction-graph visualization.

The prototype may be implemented as a command-line tool tentatively named:

mlsec-analyze

**12.4.2 Machine Learning Security Guidelines**

This research is expected to produce actionable security guidelines and operational checklists for:

- secure dependency management,

- safe model loading practices,

- runtime monitoring,

- serialized model validation,

- and binary-awareness within machine learning pipelines.

These recommendations aim to support secure software engineering practices for modern AI systems.

**12.4.3 DevSecOps Integration Blueprint**

The dissertation further proposes a practical integration blueprint for incorporating machine learning security analysis into CI/CD and DevSecOps workflows.

The proposed blueprint includes guidance for:

- automated SBOM generation,

- dependency auditing,

- binary scanning,

- runtime analysis,

- and vulnerability monitoring within machine learning deployment pipelines.

**12.5 Additional Contributions**

Additional expected contributions include:

- a serialized model security analysis methodology,

- an ML ecosystem threat-modeling framework,

- a cross-layer vulnerability propagation model,

- a binary-aware ML security assessment pipeline,

- runtime behavioral anomaly analysis techniques for ML systems,

- and a unified testing and reverse-engineering methodology for deep learning frameworks.

Ultimately, this dissertation aims to establish a holistic security assurance paradigm for modern machine learning software ecosystems.

# **13. Limitations and Assumptions**

### **13.1 Limitations**

1.  **Incomplete Binary Coverage**

> Some native libraries are dynamically loaded (e.g., via dlopen), which may limit static discovery.

2.  **Platform Dependency**

> Binary artifacts vary by OS/architecture (Linux/Windows/macOS, CPU/GPU), affecting reproducibility across environments.

3.  **Reverse Engineering Complexity**

> Large binaries (e.g., TensorFlow) may limit full decompilation and require sampling or targeted analysis.

4.  **Vulnerability Ground Truth**

> Public CVE/OSV data may be incomplete or lag behind real-world disclosures.

5.  **Fuzzing/Dynamic Analysis Scope**

> The framework focuses on static + structural analysis; deep dynamic fuzzing is complementary but not exhaustive in this work.

6.  **Framework Evolution Limitation**

> Machine learning frameworks evolve rapidly, and vulnerability characteristics, dependency structures, and runtime behaviors may change across framework versions. Consequently, findings derived from specific framework versions may require reevaluation as machine learning ecosystems evolve.

### **13.2 Assumptions**

1.  ML applications are primarily Python-based and use standard package managers (e.g., pip).

2.  Dependencies are obtainable via public repositories (e.g., PyPI) or mirrors.

3.  Native binaries are distributed as wheels or linked libraries accessible for analysis.

4.  Vulnerability databases (CVE/OSV) provide sufficiently accurate identifiers for mapping.

# **14. Conclusion**

Machine learning systems are increasingly central to critical applications, yet their security remains difficult to assess due to **multilayer architectures and reliance on opaque native binaries**. While developers interact with Python code, core execution frequently occurs in C/C++ libraries, where many high-severity vulnerabilities originate.

This dissertation proposes a **Unified Multilayer Security Analysis Framework (UMSAF)** that integrates dependency analysis, SBOM generation, vulnerability intelligence, binary reverse engineering, and cross-layer interaction modeling. By bridging gaps between software composition analysis and binary inspection, the framework enables **end-to-end visibility** from Python entry points to native execution layers.

The preliminary study demonstrates feasibility, and the proposed methodology establishes a rigorous path for evaluation using real-world ML systems and known vulnerability datasets. The expected outcome is a **scalable, automated, and empirically validated approach** for improving the security posture of modern AI software.

Ultimately, this research argues that machine learning security should no longer be viewed solely as a problem of adversarial robustness or isolated vulnerability detection. Instead, modern AI systems must be treated as complex multilayer software ecosystems requiring holistic security assurance approaches that integrate software engineering, cybersecurity, reverse engineering, runtime analysis, and supply-chain security.

# **15. References**

The dissertation incorporates literature from multiple interdisciplinary domains, including:

- machine learning security,

- reverse engineering,

- software supply-chain security,

- software vulnerability analysis,

- binary analysis,

- runtime analysis,

- threat modeling,

- deep learning testing,

- and AI software assurance.

The references section will ultimately contain approximately 50–70 scholarly sources covering the following categories.

**15.1 Machine Learning Security**

This category includes foundational research related to:

- adversarial machine learning,

- poisoning attacks,

- model extraction,

- model inversion,

- privacy attacks,

- and lifecycle security threats.

Representative references include:

- adversarial ML security surveys,

- machine learning threat modeling frameworks,

- and deep learning security analyses.

These works establish the evolution of machine learning security from adversarial robustness toward broader software ecosystem security concerns.

**15.2 Security Vulnerabilities in Machine Learning Frameworks**

This category focuses on implementation-level vulnerabilities within:

- TensorFlow,

- Keras,

- PyTorch,

- NumPy,

- and related machine learning libraries.

Representative topics include:

- memory corruption vulnerabilities,

- integer overflows,

- runtime vulnerabilities,

- serialization flaws,

- dependency risks,

- and silent computational failures.

These references provide empirical evidence demonstrating that machine learning frameworks themselves represent critical attack surfaces.

**15.3 Reverse Engineering and Binary Analysis**

This category includes literature related to:

- binary reverse engineering,

- decompilation,

- control-flow reconstruction,

- symbolic analysis,

- malware analysis,

- and native library inspection.

Representative references include:

- neural reverse engineering of binaries,

- reverse engineering of deep learning models,

- and binary inspection methodologies for native machine learning components.

These works support the feasibility of analyzing machine learning ecosystems through native binary analysis.

**15.4 Software Supply-Chain Security and SBOM Research**

This category focuses on:

- software bill of materials (SBOM),

- dependency intelligence,

- software composition analysis (SCA),

- dependency graph analysis,

- package ecosystem security,

- and software provenance verification.

Representative references include:

- CycloneDX,

- SPDX,

- software supply-chain security standards,

- and dependency vulnerability analysis methodologies.

These references support the dependency-analysis and SBOM-generation components of the proposed framework.

**15.5 Serialized Model and Computational Graph Security**

This category includes literature related to:

- TensorFlow SavedModel security,

- computational graph inspection,

- malicious model artifacts,

- hidden TensorFlow APIs,

- and serialized execution behaviors.

Representative references examine:

- malicious model distribution,

- unauthorized runtime invocation,

- and hidden execution logic embedded within serialized machine learning artifacts.

These studies directly support the dissertation’s serialized-model inspection and graph-analysis components.

**15.6 Runtime Analysis and Silent Failure Research**

This category includes studies related to:

- silent computational failures,

- runtime inconsistencies,

- anomaly detection,

- behavioral tracing,

- hardware-specific execution behavior,

- and distributed runtime analysis.

Representative work demonstrates that machine learning systems may exhibit incorrect runtime behavior without producing explicit exceptions or crashes.

These references support the runtime-monitoring and silent-failure-detection aspects of the proposed framework.

**15.7 Testing and Validation of Deep Learning Systems**

This category includes research related to:

- fuzzing,

- mutation testing,

- differential testing,

- metamorphic testing,

- runtime validation,

- and behavioral consistency analysis.

Representative studies demonstrate that conventional software testing approaches are insufficient for deep learning systems due to:

- nondeterministic execution,

- numerical instability,

- and complex runtime behaviors.

These references support the dissertation’s automated testing and validation methodology.

**15.8 Threat Modeling and AI Software Assurance**

This category includes literature related to:

- cybersecurity threat modeling,

- ML lifecycle security,

- AI assurance methodologies,

- cross-layer threat analysis,

- and trustworthiness of AI systems.

Representative references examine:

- attack surfaces,

- trust boundaries,

- threat propagation,

- infrastructure risks,

- and secure deployment practices.

These works support the dissertation’s holistic security assurance perspective.

**15.9 Representative Reference Categories**

The final dissertation will include references from:

- peer-reviewed journal articles,

- conference proceedings,

- academic surveys,

- industry standards,

- technical reports,

- and official framework documentation.

Major publication venues include:

- IEEE,

- ACM,

- USENIX,

- NDSS,

- CCS,

- ASE,

- ICSE,

- MSR,

- and Computers & Security.

Additional references will include documentation and technical materials related to:

- TensorFlow,

- Keras,

- NumPy,

- PyTorch,

- Ghidra,

- CycloneDX,

- SPDX,

- CVE,

- NVD,

- and OSV.

**15.10 Preliminary Core References**

The following references currently form the foundational basis of this dissertation proposal:

- Security Risks in Deep Learning Implementations

- Characterizing and Understanding Software Security Vulnerabilities in Machine Learning Libraries

- Silent Bugs in TensorFlow and Keras

- Neural Reverse Engineering of Stripped Binaries

- Security Knowledge-Guided Fuzzing of Deep Learning Libraries

- TensorFlow SavedModel and Hidden API Security Research

- Machine Learning Security Threats and Countermeasures

- Threat Assessment Frameworks for Machine Learning Systems

- Differential Testing and Mutation Testing for Deep Learning Libraries

- Reverse Engineering Deep Learning Models from Compiled Binaries

These references collectively support:

- the problem statement,

- threat model,

- proposed framework,

- research methodology,

- and expected contributions of the dissertation.

**IMPORTANT NOTE**

Later, before final submission, you should replace this “categorized references overview” with:

- 50–70 references

- Fully formatted APA 7 or IEEE (LaTeX) references

- Alphabetical ordering (APA), or numbered citations (IEEE)

- Proper in-text citations

- Add:

  - Proper citations formatting

  - Section numbering consistency

  - Figures (architecture diagram)

  - Table of contents

At the current stage, this structured references section is completely acceptable and significantly stronger than placeholder text.
