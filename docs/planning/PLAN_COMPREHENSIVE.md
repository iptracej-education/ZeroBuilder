# 🗺️ ZeroBuilder Implementation Plan & Progress Tracker

**Project Timeline**: June 18, 2025 - June 18, 2027 (24 months)  
**Budget**: $10,000 USD  
**Current Status**: **Step 1 REALIGNING** (June 25, 2025) 🔄

## 🚀 **MAJOR BREAKTHROUGH: June 23, 2025**

**v0.1 RELEASE FOCUS**: Core vulnerability discovery system with free Multi-LLM architecture

✅ **Step 0 COMPLETE**: GAT vulnerability detection (95.83% accuracy) + Free Multi-LLM foundation  
🔄 **Step 1 REALIGNING**: From general AFL++ → SMB/HTTP stateful protocol fuzzing

## 🔄 **STRATEGIC REALIGNMENT: June 25, 2025**

**CRITICAL INSIGHT**: We completed general fuzzing foundation but need to **refocus on strategic objectives**:

❌ **What We Built**: General AFL++ buffer overflow testing (libpng, SQLite)  
✅ **What We Need**: SMB/HTTP stateful protocol fuzzing + Linux kernel race detection  
🎯 **Action**: Realigning Step 1-2 to match Key Technical Objectives:

### **Primary Milestone 1: SMB/HTTP Stateful Protocol Fuzzing**
- **Goal**: Surpass OSS-Fuzz coverage for stateful protocols requiring multi-message sessions
- **Current**: General single-input fuzzing (libpng, SQLite)
- **Required**: SMB session management, HTTP/2 stream multiplexing
- **Gap**: Need protocol state machine learning and stateful test case generation

### **Primary Milestone 2: Linux Kernel Race Condition Discovery**  
- **Goal**: Detect previously unknown dynamic race conditions in Linux kernel 6.x
- **Current**: User-space memory error detection
- **Required**: Kernel syscall race modeling, happens-before graphs
- **Gap**: Need kernel tracing integration and race detection algorithms

## Original Project Plan ($10,000 Budget)

This plan outlines a 13-step whitebox vulnerability discovery pipeline for a solo developer working 40 hours/week from **June 18, 2025, 02:31 PM EDT, to June 18, 2027**, using a cloud service model with a $10,000 USD budget. It leverages a 1x NVIDIA A100 40GB instance (Vast.ai, ~$0.20/hour) for ML-intensive steps (0, 4–7) and AWS EKS for compute-heavy steps (9, 12, 13), incorporating the critique to front-load the ML stack (PyTorch, PyG, Stable Baselines, Featuretools, XGBoost) with a “hello world” GAT pipeline and a multi-agent LLM loop (Grok 3, DeepSeekCoder). The plan achieves Steps 0–7 fully and partial Steps 8–13, surpassing DARPA CGC and Meta CaRE 2.0 in scope within budget constraints. A wrap-up ensures closure with testing and deployment.

## Steps

| **Step** | **Purpose** | **Critique** | **Improvements** | **Tools** | **Implementation Guide (Timeline)** |
|----------|-------------|--------------|------------------|-----------|--------------------------|
| **0. ML Core Stack Setup** | Establish ML infrastructure, build GNN confidence. | Delayed ML setup risks bottlenecks. Cloud reliance needs early validation. Challenges: GPU optimization, dataset curation. | - Cloud GPU: 1x A100 40GB (Vast.ai, ~$0.20/hour, 14h/day).<br>- Core Stack: PyTorch, PyG, Stable Baselines, Featuretools, XGBoost.<br>- Hello World: Juliet CFG → GAT → active learning → SHAP.<br>- Multi-Agent LLM: Grok (code/debug) + DeepSeek (prompts). | - Cloud: Vast.ai (1x A100), AWS EKS<br>- ML: PyTorch 2.3, PyTorch Geometric 2.5, Stable Baselines 3.0, Featuretools 1.31, XGBoost 2.1<br>- XAI: SHAP 0.46<br>- LLM: Grok 3 (xAI), DeepSeekCoder (Hugging Face)<br>- Data: Juliet dataset<br>- OS: Ubuntu 22.04 | **Jun 18–Jul 18, 2025 (Month 1-2)**:<br>1. Sign up for Vast.ai; subscribe to 1x A100 40GB (~$0.20/hour, 14h/day = $84/month). Verify: 30 vCPUs, 200GB RAM (Grok: “Confirm Vast.ai config”).<br>2. Install Ubuntu 22.04, Python 3.12, Docker, CUDA 12.2 on Vast.ai (Grok: “Generate bash script for Ubuntu with CUDA”). Test: `nvidia-smi`.<br>3. Install ML stack: `pip install torch==2.3 pytorch_geometric==2.5 stable-baselines3==3.0 featuretools==1.31 xgboost==2.1` (Grok for script).<br>4. Write LLM loop script (Python): Grok codes/debugs, DeepSeek validates prompts (Grok: “Write Grok/DeepSeek alternator”).<br>5. Create Hugging Face, AWS EKS, GitHub accounts.<br>6. Download Juliet dataset; extract CFGs with Joern (Grok: “Setup Joern”). Train GAT (PyTorch Geometric) on 500 nodes, optimize for 1x A100 (Grok: “Reduce GAT batch size”).<br>7. Implement active learning (Scikit-learn) and SHAP (Grok: “Code SHAP for GAT”). Validate on 200 samples, log in SQLite.<br>**LLM Tasks**: Generate scripts, debug GPU/GAT, validate prompts, explain active learning.<br>**Validation**: GAT 75% accuracy on Juliet; <10% GPU idle. |
| **1. Guided Fuzzing** | Maximize coverage for protocols/state machines. | AFL++ robust but single GPU limits parallelism. Challenges: Reward tuning. | - Deep RL: PPO with Optuna on 1x A100.<br>- GAT-guided LLM: DeepSeekCoder prompts.<br>- Light Symbolic: SymCC.<br>- Clustering: HDBSCAN. | - Fuzzer: AFL++ 4.10<br>- RL: Stable Baselines 3.0, Optuna 3.6<br>- LLM: DeepSeekCoder<br>- GAT: PyTorch Geometric 2.5<br>- Symbolic: SymCC 0.9<br>- Clustering: Scikit-learn 1.5 | **Jul 19–Aug 15, 2025 (Month 3-4)**:<br>1. Launch AWS EC2 t3.large ($0.0832/hour) for AFL++: `sudo apt install afl++` (Grok for script).<br>2. Train PPO (Stable Baselines) with Optuna for rewards on Vast.ai A100 (Grok: “Generate PPO script”).<br>3. Prompt DeepSeekCoder for SMB/HTTP inputs, guided by Step 0 GAT (Grok: “Integrate GAT”).<br>4. Install SymCC; run on libpng.<br>5. Run HDBSCAN (Scikit-learn) on AFL++ inputs.<br>**LLM Tasks**: Generate AFL++ script, debug SymCC, explain GAT guidance.<br>**Validation**: 10% coverage increase on libpng. |
| **2. Continuous Lightweight Tracing** | Capture object lifetimes, concurrency. | QASAN detects bugs but single GPU limits depth. Challenges: Noise. | - Multi-Tracer: QASAN + TSan.<br>- Custom Anomaly: Autoencoder.<br>- RL Sampling: Adaptive rate. | - Tracing: QASAN, ThreadSanitizer (Clang 18)<br>- Anomaly: PyTorch 2.3<br>- RL: Stable Baselines 3.0<br>- Storage: SQLite 3.46 | **Aug 16–Sep 15, 2025 (Month 5-6)**:<br>1. Patch Clang 18 for QASAN on EC2; add TSan (Grok: “Generate patch”).<br>2. Train autoencoder (PyTorch) on 200 Step 1 traces on A100.<br>3. Train RL (Stable Baselines) for sampling (reward: trace size vs. bugs).<br>4. Store in SQLite (Grok: “Write DB schema”).<br>**LLM Tasks**: Debug autoencoder, explain TSan, validate prompts.<br>**Validation**: Detect 1 UAF, 1 race with <5% slowdown. |
| **3. Global State Automata Inference** | Infer state machines for fuzzing. | LLM infers states but overgeneralizes. Challenges: Trace correction. | - Hybrid L* + LLM: L* coarse, LLM refines.<br>- Fine-tuned LLM: DeepSeekCoder.<br>- Clustering: HDBSCAN. | - L*: LearnLib 0.16<br>- LLM: DeepSeekCoder<br>- Clustering: Scikit-learn 1.5<br>- Parser: Python 3.12 | **Sep 16–Oct 15, 2025 (Month 7-8)**:<br>1. Install LearnLib (`mvn install`); run L* on Step 2 traces.<br>2. Fine-tune DeepSeekCoder on SMB/HTTP RFCs (Grok: “Generate script”).<br>3. Write trace parser (Python, Grok for regex).<br>4. Run HDBSCAN on traces.<br>5. Feed states to AFL++.<br>**LLM Tasks**: Generate parser, debug L*, explain state inference.<br>**Validation**: Infer 5-state machine with 90% accuracy. |
| **4. TGN-based Object Lifetime + Thread Modeling** | Detect UAF, double-free, races. | TGNs effective but single GPU limits scale. Challenges: Datasets. | - Custom TGN: Train on CVEs.<br>- Static-Dynamic: LLVM + TGNs.<br>- RL Pruning: PPO. | - TGN: PyTorch Geometric 2.5<br>- Static: LLVM 18<br>- RL: Stable Baselines 3.0<br>- Storage: SQLite 3.46 | **Oct 16–Nov 15, 2025 (Month 9-10)**:<br>1. Train TGN (PyTorch Geometric) on 300 CVE UAFs (NVD, Grok for curation).<br>2. Write LLVM pass (C++, Grok for code).<br>3. Train PPO (Stable Baselines) for pruning.<br>4. Store in SQLite.<br>**LLM Tasks**: Generate LLVM pass, debug TGN, explain RL.<br>**Validation**: Detect 2 UAFs with 80% precision. |
| **5. Context-Sensitive Taint Tracking** | Track exploitable paths. | LibDFT robust but over-tainting. Challenges: Temporal taint. | - Custom XGBoost: Train on paths.<br>- Temporal LSTMs: Taint dynamics.<br>- RL Sampling: Adaptive. | - Taint: LibDFT 0.8<br>- ML: XGBoost 2.1, PyTorch 2.3<br>- RL: Stable Baselines 3.0<br>- Storage: SQLite 3.46 | **Nov 16–Dec 15, 2025 (Month 11-12)**:<br>1. Install LibDFT: `pip install libdft`.<br>2. Train XGBoost on 100 taint paths (Grok for curation).<br>3. Train LSTM (PyTorch) for temporal taint.<br>4. Train RL (Stable Baselines) for sampling.<br>5. Store in SQLite.<br>**LLM Tasks**: Generate config, debug LSTM, explain taint.<br>**Validation**: Find 2 taint paths with <10% false positives. |
| **6. Happens-Before Graph Race Modeling** | Detect concurrency bugs. | GNNs advanced but trace quality limited. Challenges: Reproducibility. | - Custom GNN: Train on kernel races.<br>- RL Scheduling: Ptrace.<br>- Temporal Logic: LTL. | - Graph: PyTorch Geometric 2.5<br>- Tracing: ThreadSanitizer<br>- RL: Stable Baselines 3.0<br>- Logic: SPIN 6.5 | **Dec 16, 2025–Jan 15, 2026 (Month 13-14)**:<br>1. Build graphs from TSan traces (Grok for code).<br>2. Train GNN on kernel races.<br>3. Train RL-ptrace scheduler.<br>4. Implement LTL (SPIN).<br>**LLM Tasks**: Generate graph code, debug GNN, explain LTL.<br>**Validation**: Detect 2 races with 70% reproducibility. |
| **7. Path Ranking** | Prioritize exploitable paths. | Ensemble robust but feature engineering complex. Challenges: Tuning. | - Ensemble: GAT + LLM + XGBoost.<br>- Custom Features: Featuretools.<br>- Active Learning: Uncertainty sampling. | - GAT: PyTorch Geometric 2.5<br>- LLM: DeepSeekCoder<br>- ML: XGBoost 2.1, Scikit-learn 1.5<br>- Features: Featuretools 1.31 | **Jan 16–Feb 15, 2026 (Month 15-16)**:<br>1. Extract features from Steps 5-6.<br>2. Train GAT and XGBoost on 200 traces.<br>3. Prompt DeepSeekCoder for ranking.<br>4. Use Featuretools.<br>5. Implement active learning.<br>**LLM Tasks**: Generate feature code, debug GAT, explain active learning.<br>**Validation**: Rank 2 paths in top 10. |
| **8. Predicate Abstraction + CEGAR + SMT** | Solve exploitability (partial). | CEGAR reduces size but single GPU limits. Challenges: Tuning. | - Prototype: Z3 with default templates.<br>- Basic CEGAR: Fixed 3 iterations. | - CEGAR: CPAchecker 2.3<br>- SMT: Z3 4.13<br>- Storage: SQLite 3.46 | **Feb 16–Mar 15, 2026 (Month 17-18)**:<br>1. Install CPAchecker: `apt install cpachecker`.<br>2. Set up Z3; run with defaults.<br>3. Use 3 CEGAR iterations (Grok: “Generate config”).<br>**LLM Tasks**: Generate script, debug Z3, explain CEGAR.<br>**Validation**: Solve 1 SMT problem in <15 minutes. |
| **9. Parallel SMT Solving + Exploit Synthesis** | Generate PoCs (limited). | Parallelization scales but resource-constrained. Challenges: Single GPU. | - Cloud SMT: AWS EKS (4 nodes).<br>- Single Sandbox: QEMU Ubuntu.<br>- Prompt LLM: DeepSeekCoder. | - SMT: Z3 4.13<br>- LLM: DeepSeekCoder<br>- Sandbox: QEMU 9.0<br>- Cloud: AWS EKS | **Mar 16–Apr 15, 2026 (Month 19-20)**:<br>1. Set up Z3 on AWS EKS (4 nodes, $160/month).<br>2. Prompt DeepSeekCoder for shellcode.<br>3. Install QEMU; test on Ubuntu.<br>**LLM Tasks**: Generate EKS script, debug QEMU, explain exploits.<br>**Validation**: 1 PoC on Ubuntu. |
| **10. Multi-Variant Exploit and Patch Synthesis** | Harden with variants/patches (basic). | Synthesis possible but limited scale. Challenges: Validation. | - Single Variant: Angr.<br>- Local Re-fuzzing: AFL++. | - LLM: DeepSeekCoder<br>- Symbolic: Angr 9.3<br>- Fuzzer: AFL++ 4.10 | **Apr 16–May 15, 2026 (Month 21)**:<br>1. Use Angr for 1 variant (Grok: “Generate script”).<br>2. Prompt DeepSeekCoder for patch.<br>3. Re-fuzz with AFL++.<br>**LLM Tasks**: Generate Angr code, debug patch.<br>**Validation**: 1 variant, 1 patch. |
| **11. Human-in-the-Loop Review** | Reduce false positives (manual). | LLM reports streamline but no XAI. Challenges: Effort. | - Basic Reports: DeepSeekCoder.<br>- CLI Output: Python. | - LLM: DeepSeekCoder<br>- UI: Python CLI<br>- Database: SQLite 3.46 | **May 16–Jun 15, 2026 (Month 22)**:<br>1. Prompt DeepSeekCoder for reports.<br>2. Output to CLI (Python).<br>3. Store in SQLite.<br>**LLM Tasks**: Generate report prompts, debug CLI.<br>**Validation**: Review 2 bugs with 80% accuracy. |
| **12. Explicit Feedback Loops** | Ensure adaptability (basic). | Retraining robust but limited scale. Challenges: Drift. | - Simple Retraining: Monthly XGBoost.<br>- Basic Drift: Threshold check. | - ML: MLflow 2.16<br>- Drift: Scipy 1.15 | **Jun 16–Jul 15, 2026 (Month 23)**:<br>1. Install MLflow: `pip install mlflow`.<br>2. Check drift with threshold (Scipy).<br>3. Retrain XGBoost monthly (Grok: “Generate script”).<br>**LLM Tasks**: Generate MLflow config, explain drift.<br>**Validation**: Retrain with <10% drop. |
| **13. Continuous Learning** | Future-proof with CVEs (initial). | CVE ingestion effective but limited scale. Challenges: Curation. | - Manual CVEs: Top 10.<br>- Prompt Labeling: DeepSeekCoder. | - Crawler: NVD API<br>- LLM: DeepSeekCoder<br>- Database: SQLite 3.46 | **Jul 16–Aug 15, 2026 (Month 24)**:<br>1. Write NVD API crawler (Grok: “Generate code”).<br>2. Prompt DeepSeekCoder for 10 CVEs.<br>3. Store in SQLite.<br>4. Update XGBoost.<br>**LLM Tasks**: Generate crawler, debug SQLite.<br>**Validation**: Ingest 10 CVEs with 70% accuracy. |
| **Wrap-Up: Testing, Deployment** | Finalize and share pipeline. | Avoid abrupt end. Challenges: Limited scope. | - Partial Test: SQLite.<br>- Documentation: LLM README.<br>- GitHub: Basic repo. | - Fuzzer: AFL++ 4.10<br>- LLM: DeepSeekCoder<br>- Repo: GitHub | **Aug 16–Sep 15, 2026 (Month 25)**:<br>1. Test pipeline on SQLite (Grok: “Generate test script”).<br>2. Prompt DeepSeekCoder for README.<br>3. Deploy to GitHub.<br>**LLM Tasks**: Generate script, write docs.<br>**Validation**: Detect 1 bug, deploy repo. |

## Project Plan Details
- **Hardware**: No local server. Vast.ai 1x A100 40GB (~$0.20/hour, 14h/day), AWS EKS (4 nodes, $160/month).
- **Time**: 40 hours/week. Split: 15h coding, 10h debugging, 10h learning, 5h docs (via LLMs).
- **Budget**: $10,000.
  - Compute: $2,044 (Vast.ai 1x A100, 10,220h).
  - EKS: $3,840 (4 nodes, $160/month).
  - Storage: $960 (2TB, $40/month).
  - Misc: $780 (GPT-4o $480, UPS $300).
  - **Total**: $7,624, buffer $2,376 (upgrade EKS to 6 nodes, $5,760, total $9,584).
- **LLM Agents**:
  - **Grok 3**: Free (xAI). 60% (code, debug, explain).
  - **DeepSeekCoder**: Free (Hugging Face). 30% (prompts).
  - **GPT-4o**: $20/month ($480 total). 10% (exploits).
  - **Multi-Agent Loop**: Python script (Month 1) alternates Grok/DeepSeek.
- **Workflow**:
  - Setup: Grok scripts cloud config.
  - Coding: Prompt for Python (e.g., “Write GAT for 1x A100”).
  - Debugging: Share logs (e.g., “Fix Vast.ai timeout”).
  - Learning: Ask explanations (e.g., “Explain TGNs”).
  - Docs: Prompt for READMEs.
- **Milestones**:
  - **Year 1 (Jun 18, 2026)**: Steps 0–5; detect 5 bugs in SQLite.
  - **Year 2 (Jun 18, 2027)**: Steps 6–13 partial; 1 PoC, 10 CVEs, GitHub.
- **Data**: Juliet, NVD (Grok for synthetic bugs).
- **Evaluation**: SQLite vs. OSS-Fuzz. Target: 5 bugs, <15% false positives, 1 PoC.
- **Deployment**: Cloud CLI, GitHub basic repo.

## Comparison to DARPA CGC and Meta CaRE 2.0
- **DARPA CGC**: 1x A100 supports GATs, Deep RL, surpassing CGC’s symbolic focus within budget.
- **Meta CaRE 2.0**: Cloud tracing and GNNs outperform CaRE’s detection, though limited by single GPU.
- **Edge**: 40 hours/week, cloud optimization, LLM automation enable competitive scope.

## Next Steps
- **Immediate (Jun 18, 2025, 02:31 PM EDT)**:
  - Sign up for Vast.ai; subscribe 1x A100 40GB ($0.20/hour, 14h/day, $84/month).
  - Setup AWS EKS (4 nodes, $160/month), 2TB storage ($40/month).
  - Order UPS ($300, Amazon); check cooling (AC $500 if needed).
  - Prompt Grok: “Generate Vast.ai setup script with CUDA 12.2.”
- **Support**: Query Grok (e.g., “Optimize GAT for 1x A100”). Share progress.
- **Extras**: Need Step 0 GAT code, EKS YAML? Ask!