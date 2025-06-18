# 🛠️ ZeroBuilder: A Modern Deep Vulnerability Discovery Pipeline  
**June 2025 – June 2027**  
_Solo developer 40h/week project — LLM-assisted — goal to surpass DARPA CGC and Meta CaRE 2.0_

[![Project](https://img.shields.io/badge/Project-ZeroBuilder-blue)](https://github.com/iptracej-education/ZeroBuilder)


## 🚀 Project Overview

**Goal**: Build an end-to-end vulnerability discovery pipeline with:

- Guided fuzzing (GAT + RL)
- Dynamic tracing & taint analysis
- Global state inference
- Concurrency modeling
- Parallel SMT solving
- Automated exploit & patch synthesis
- CI/CD integration
- CVE submission & public open-source

**Target software**: Linux kernel, Chrome (libjpeg, libpng), SMB, HTTP

**Compute**:  
- Cheapest cloud services for A100 GPUs or a local server (32-core, 128GB RAM, 2x A100 GPUs) 
- AWS EKS 10 nodes (Steps 9, 12, 13)

**LLM Agents**:  
- Grok 3  
- DeepSeekCoder  
- GPT-4o

---

## 🎯 Objective & Project Ambitions

**ZeroBuilder** is a modern deep vulnerability discovery pipeline — designed to:

- Push the boundaries of automated vulnerability discovery beyond legacy systems such as DARPA CGC winners (Mayhem, Mechanical Phish) and Meta CaRE 2.0  
- Achieve full-spectrum vulnerability coverage — from guided fuzzing to concurrency bugs, SMT-based exploit synthesis, and collaborative review with human  
- Apply the latest advances in:
  - Graph-based neural modeling (GATs, TGNs)
  - Deep reinforcement learning (DRL)
  - Large Language Models (LLM-guided state inference and exploit generation)
  - Human-in-the-loop XAI interfaces for collaborative review  
- Demonstrate capability to find previously unknown bugs in high-value targets such as:
  - The Linux kernel (UAF, races, TOCTOU)
  - Chrome browser (libpng, libjpeg)
  - Complex protocols (SMB, HTTP/2)


**Technical Supremacy Targets (June 2027):**

| Target Area                      | Goal |
|----------------------------------|------|
| Fuzzing coverage                 | Surpass OSS-Fuzz for SMB/HTTP stateful targets |
| Kernel race condition discovery  | Detect previously unknown races in Linux kernel 6.x |
| Exploit synthesis                | Generate reliable PoCs bypassing ASLR, stack canaries |
| Patch synthesis                  | Generate functional, validated patches with CI/CD verification |
| End-to-end pipeline automation   | Public GitHub repo with 1-click install and full test suite |
| Learning feedback loops          | Achieve adaptive ML model retraining from bug discovery drift |

**Comparison Ambition:**  
While DARPA CGC and Meta CaRE 2.0 were multi-institution, funded programs — ZeroBuilder aims to demonstrate that, by leveraging modern LLM agents (Grok 3, DeepSeekCoder, GPT-4o), a **single developer with discipline and compute** can surpass many 2015–2020 level approaches.

---

## 🗺️ Project Roadmap

| Step | Purpose | Timeline |
|------|---------|----------|
| 1. Guided Fuzzing | Maximize coverage | Month 1–3 |
| 2. Lightweight Tracing | Capture object lifetimes | Month 1–3 |
| 3. State Inference | Infer state machines | Month 7–9 |
| 4. TGN Modeling | Detect UAF, double-free | Month 9–11 |
| 5. Taint Tracking | Track exploitable data | Month 11–14 |
| 6. Race Modeling | Detect concurrency bugs | Month 11–14 |
| 7. Path Ranking | Prioritize paths | Month 15–16 |
| 8. Predicate Abstraction | Solve exploitability | Month 17–18 |
| 9. Parallel SMT + Exploit | Generate PoCs | Month 19–21 |
| 10. Variant Patch Synthesis | Harden with variants | Month 21 |
| 11. Human-in-the-Loop Review | Reduce false positives | Month 22 |
| 12. Feedback Loops | Adapt to drift | Month 23 |
| 13. Continuous Learning | CVE ingestion | Month 24 |
| Wrap-Up | Final test & open-source | Month 24 |

---

## 🗂️ Open-source Components

| Step             | Repos |
|------------------|-------|
| Fuzzing          | AFL++, SymCC, Angr |
| Tracing          | QASan, TSan, Intel Pin |
| State Inference  | LearnLib |
| TGN              | PyTorch Geometric, TGN |
| Taint            | LibDFT, Zyan DTA |
| Race             | DRCHECKER, SPIN |
| Ranking          | XGBoost, SHAP, Featuretools |
| Abstraction      | CPAchecker |
| SMT              | Z3, Yices |
| Exploit          | Angr, Ropper, pwntools |
| Sandbox          | QEMU |
| Patch            | PatchDiff2 |
| XAI UI           | SHAP, Flask, React, D3.js |
| Feedback         | MLflow, Optuna |
| CVE              | CVE-Search, NVD API wrapper |

## 🤝 License
Apache 2.0

## 🤝 Contribution

ZeroBuilder is currently a **solo developer project** — but external feedback, ideas, and contributions are welcome!

If you'd like to contribute:

1. Open an [Issue](https://github.com/iptracej-education/ZeroBuilder/issues) for feature ideas, bug reports, or tool integration suggestions.
2. Fork this repository and submit a Pull Request (PR).
3. Share protocol datasets, fuzzing configs, or CVE cases that could improve pipeline performance.

Contributions of any kind are appreciated:

- Bug reports  
- Improvements to tracing or modeling steps  
- New components (e.g. additional fuzzers, analyzers)  
- Better CI/CD integrations  
- Documentation improvements

**Note:** Please make sure your contributions respect the project's **Apache 2.0 license** and align with responsible disclosure practices.

---

**Project taglines:**  
*Built to surpass DARPA CGC & Meta CaRE 2.0 — one step at a time, one bug at a time.*

---



## 💬 Contact

- Solo project by [Kiyoshi Watanabe]
- Twitter: [@iptracej]
- Blog: [iptracej-education.github.io]