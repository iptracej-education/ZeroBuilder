# 🎯 ZeroBuilder v0.1 Core Only Plan - Strategic Focus

**Document Version**: v1.0  
**Date**: June 26, 2025  
**Focus**: SMB/HTTP stateful protocols + Linux kernel races ONLY  
**Philosophy**: Quality over scope - prove core objectives before expansion

## 🚨 **CRITICAL SCOPE REDUCTION**

### **What We're REMOVING from original plan**:
❌ **Steps 8-13**: Exploit synthesis, patch synthesis, human-in-loop, feedback loops  
❌ **Stretch Goals**: ASLR bypass, stack canaries, automated patching  
❌ **AWS EKS**: Complex multi-node infrastructure (save for v0.2+)  
❌ **Advanced ML**: Complex feature engineering, ensemble methods  
❌ **Production Scale**: Auto-scaling, monitoring, enterprise features

### **What We're KEEPING (Core v0.1)**:
✅ **Primary Objective 1**: SMB/HTTP stateful protocol fuzzing  
✅ **Primary Objective 2**: Linux kernel race condition detection  
✅ **Core Technologies**: GAT + Multi-LLM + Targeted fuzzing  
✅ **Budget Focus**: $250 for proof-of-concept validation

## 🎯 **v0.1 CORE STRATEGIC OBJECTIVES**

### **Primary Objective 1: SMB/HTTP Stateful Protocol Fuzzing**
```
GOAL: Surpass OSS-Fuzz coverage for stateful protocols
TARGET: 10% deeper state coverage than OSS-Fuzz on SMB sessions
METHOD: Multi-message session fuzzing vs. single-input coverage
VALIDATION: Find 1 unknown vulnerability in SMB implementation
```

### **Primary Objective 2: Linux Kernel Race Condition Detection**  
```
GOAL: Detect previously unknown dynamic race conditions in Linux 6.x
TARGET: Discover 1 novel race condition not in public CVE/mailing lists
METHOD: Happens-before graph analysis + RL thread scheduling
VALIDATION: Reproducible race condition with PoC
```

## 📋 **v0.1 CORE ROADMAP (4 Steps Only)**

| **Step** | **Purpose** | **Timeline** | **Budget** | **Success Criteria** |
|----------|-------------|--------------|------------|----------------------|
| **0. GAT Validation** | Verify GAT works on SMB/kernel code | **Jun 26-30** | $0 | GAT identifies risky SMB/kernel patterns |
| **1. Stateful Protocol Fuzzing** | SMB session state fuzzing | **Jul 1-15** | $50 | 10% deeper SMB coverage than OSS-Fuzz |
| **2. Kernel Race Detection** | Linux syscall race discovery | **Jul 16-31** | $100 | Detect 1 novel race condition |
| **3. Integration & Validation** | Combined system testing | **Aug 1-15** | $100 | Both objectives validated |

**Total Timeline**: 7 weeks  
**Total Budget**: $250 (current available)  
**Success Metric**: Achieve both primary objectives with proof

## 🔧 **v0.1 CORE TECHNICAL STACK**

### **Essential Components Only**:
```
GAT Model: PyTorch Geometric (existing, 95.83% accuracy)
Multi-LLM: CodeLlama + StarCoder 2 + DeepSeekCoder (free)
Fuzzing: AFL++ with stateful extensions
Tracing: ftrace for kernel syscall monitoring
Infrastructure: Local Docker + single Vast.ai instance
Storage: Local SQLite (no complex databases)
```

### **Removed Complexity**:
```
❌ AWS EKS multi-node clusters
❌ Advanced RL environments  
❌ SMT solvers and CEGAR
❌ Automated exploit generation
❌ Patch synthesis pipelines
❌ Human-in-the-loop interfaces
❌ MLflow experiment tracking
❌ CVE ingestion pipelines
```

## 📊 **v0.1 DETAILED IMPLEMENTATION**

### **Step 0: GAT Validation (Jun 26-30, 2025)**
**Budget**: $0 (local testing)  
**Goal**: Prove GAT effectiveness on target domains

#### **SMB Protocol Testing**:
```bash
# Test GAT on SMB server implementation
wget https://github.com/samba-team/samba/archive/master.zip
# Extract SMB packet handling functions
python extract_smb_functions.py samba/source3/smbd/
# Generate CPGs with Joern
joern --script cpg_gen.sc --src smb_functions/
# Test GAT predictions
uv run python main.py --cpg smb_packet_handler.bin > gat_smb_results.log
```

#### **Kernel Code Testing**:
```bash
# Test GAT on Linux kernel syscall implementations  
wget https://github.com/torvalds/linux/archive/v6.6.tar.gz
# Extract syscall implementations with potential races
python extract_kernel_syscalls.py linux/fs/ linux/mm/
# Generate CPGs
joern --script cpg_gen.sc --src kernel_syscalls/
# Test GAT predictions
uv run python main.py --cpg syscall_open.bin > gat_kernel_results.log
```

#### **Success Criteria**:
- GAT identifies risky patterns in SMB packet handlers (>0.7 risk score)
- GAT flags potential race conditions in kernel syscalls (>0.6 risk score)
- Predictions align with known vulnerabilities in test samples

### **Step 1: Stateful Protocol Fuzzing (Jul 1-15, 2025)**
**Budget**: $50 (Vast.ai for 2 weeks)  
**Goal**: SMB session fuzzing that surpasses OSS-Fuzz

#### **SMB Session State Machine**:
```python
# Implement SMB session fuzzing
class SMBStatefulFuzzer:
    def __init__(self):
        self.states = ["negotiate", "session_setup", "tree_connect", "file_ops"]
        self.gat_guidance = None
        
    def fuzz_session_transition(self, from_state, to_state, gat_risk_scores):
        # Use GAT scores to prioritize risky transitions
        if gat_risk_scores[to_state] > 0.7:
            # Generate targeted mutations for high-risk states
            return self.generate_high_risk_inputs(to_state)
        return self.generate_standard_inputs(to_state)
```

#### **Docker SMB Environment**:
```yaml
# docker-compose.yml (simplified)
services:
  smb-server:
    image: dperson/samba
    ports: ["445:445"]
  
  smb-fuzzer:
    build: ./fuzzer
    depends_on: [smb-server]
    command: python smb_stateful_fuzzer.py
```

#### **Success Criteria**:
- Achieve 10% deeper state coverage than OSS-Fuzz on SMB sessions
- Discover at least 1 crash in SMB implementation
- GAT-guided fuzzing shows measurable improvement over random

### **Step 2: Kernel Race Detection (Jul 16-31, 2025)**
**Budget**: $100 (Vast.ai + VM setup)  
**Goal**: Detect novel Linux kernel race conditions

#### **ftrace Integration**:
```bash
# Enable kernel tracing for syscall monitoring
echo function_graph > /sys/kernel/debug/tracing/current_tracer
echo 1 > /sys/kernel/debug/tracing/events/syscalls/enable

# Monitor specific syscall pairs prone to races
echo 'p:open_probe sys_openat' > /sys/kernel/debug/tracing/kprobe_events  
echo 'p:close_probe sys_close' >> /sys/kernel/debug/tracing/kprobe_events
```

#### **Happens-Before Graph Construction**:
```python
class HappensBeforeAnalyzer:
    def __init__(self):
        self.syscall_traces = []
        self.race_candidates = []
        
    def analyze_traces(self, ftrace_output):
        # Parse ftrace output into temporal relationships
        events = self.parse_ftrace(ftrace_output)
        
        # Build happens-before graph
        for event_pair in self.get_concurrent_events(events):
            if self.gat_model.predict_race_risk(event_pair) > 0.6:
                self.race_candidates.append(event_pair)
```

#### **Success Criteria**:
- Detect 1 novel race condition not in public CVE database
- Race condition is reproducible with >50% success rate
- Provides clear happens-before violation proof

### **Step 3: Integration & Validation (Aug 1-15, 2025)**
**Budget**: $100 (final testing and validation)  
**Goal**: Prove both objectives achieved

#### **Combined System Testing**:
```python
class ZeroBuilderCoreValidator:
    def __init__(self):
        self.smb_fuzzer = SMBStatefulFuzzer()
        self.kernel_analyzer = HappensBeforeAnalyzer()
        self.gat_model = VulnerabilityGAT()
        
    def validate_core_objectives(self):
        # Objective 1: SMB/HTTP Protocol Coverage
        smb_coverage = self.measure_smb_coverage()
        oss_fuzz_baseline = self.get_oss_fuzz_coverage()
        
        # Objective 2: Kernel Race Detection  
        novel_races = self.detect_kernel_races()
        
        return {
            'smb_improvement': smb_coverage > oss_fuzz_baseline * 1.1,
            'novel_races_found': len(novel_races) >= 1,
            'core_objectives_met': True
        }
```

#### **Success Criteria**:
- SMB/HTTP fuzzing shows 10%+ improvement over OSS-Fuzz
- At least 1 novel kernel race condition discovered
- Both findings validated and documented
- System ready for v0.2 expansion

## 💰 **v0.1 BUDGET ALLOCATION**

### **Total Available**: $249.77
```
Step 0 (GAT Validation): $0 (local only)
Step 1 (SMB Fuzzing): $50 (Docker + Vast.ai basic)  
Step 2 (Kernel Races): $100 (VM + enhanced tracing)
Step 3 (Validation): $100 (final testing)
Buffer: $0 (tight but achievable)
```

### **Cost Optimization**:
- Local Docker testing reduces cloud costs
- Single Vast.ai instance vs. multi-node clusters
- No AWS EKS until v0.2
- Focus spending on actual vulnerability discovery

## 🚀 **v0.1 SUCCESS DEFINITION**

### **Technical Success**:
```
✅ GAT effectively identifies risks in SMB/kernel code  
✅ SMB fuzzing surpasses OSS-Fuzz coverage by 10%
✅ 1 novel Linux kernel race condition discovered
✅ Both findings validated and reproducible
```

### **Strategic Success**:
```
✅ Proof that ZeroBuilder approach works on target domains
✅ Foundation for v0.2 expansion (Steps 4-7)
✅ Budget preserved for continued development  
✅ Clear competitive advantage over existing tools
```

### **Project Success**:
```
✅ Core objectives achieved within scope and budget
✅ No scope creep or stretch goal distractions
✅ Quality foundation for future development
✅ Validated approach ready for scaling
```

## 📋 **WHAT'S DEFERRED TO v0.2+**

### **Advanced Features (v0.2)**:
- AWS EKS multi-node infrastructure
- Advanced RL optimization
- Performance scaling and monitoring

### **Synthesis Features (v0.3)**:
- Exploit generation (Steps 9-10)
- Patch synthesis capabilities
- SMT solving integration

### **Production Features (v0.4)**:
- Human-in-the-loop interfaces (Step 11)
- Automated feedback loops (Step 12)
- CVE ingestion pipeline (Step 13)

## 🔥 **IMMEDIATE NEXT STEPS (Today)**

### **Priority 1: GAT Validation**
```bash
# Start GAT testing on SMB/kernel samples (FREE)
uv run python main.py --test-smb
uv run python main.py --test-kernel
```

### **Priority 2: Multi-LLM Core**
```bash
# Deploy single LLM for validation
# Only scale if GAT validation succeeds
```

### **Priority 3: SMB Test Case**
```bash
# Create simple SMB fuzzing target
# Validate approach before complex implementation
```

## ✅ **v0.1 COMMITMENT**

**PROMISE**: By August 15, 2025, ZeroBuilder v0.1 will have:
1. **Proven SMB/HTTP fuzzing** that surpasses OSS-Fuzz coverage
2. **Discovered 1 novel kernel race** condition in Linux 6.x
3. **Validated GAT + Multi-LLM** effectiveness on target domains
4. **Stayed within $250 budget** with quality focus

**NO SCOPE CREEP**: We will NOT add features beyond core objectives until v0.1 is complete and validated.

---

**FOCUS**: Prove the core concept works. Everything else is v0.2+.