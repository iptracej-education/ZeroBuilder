# 🤖 **ZeroBuilder Gemini Primary Validation - Usage Guide**

**Version**: v1.0  
**Date**: June 27, 2025  
**Target**: Development and deployment teams  
**Prerequisites**: ZeroBuilder v0.1 with Gemini integration

---

## 🎯 **Quick Start**

### **Run Gemini Primary Validation**
```bash
# Navigate to ZeroBuilder directory
cd /path/to/ZeroBuilder

# Run Gemini Primary validation system
uv run python deployment/validation_runner.py

# Expected output:
# 🚀 Starting ZeroBuilder Gemini Primary Validation
# 💰 Expected cost savings: $175-225 (85-90% reduction)
# 🎯 Gemini assessment score: 88/100 (exceeds 85+ threshold)
# 🤖 Initializing Gemini Primary Validator
```

### **Monitor Validation Progress**
```bash
# Check session state
cat session_state.json

# Monitor validation logs
tail -f validation_session.log

# View intermediate results
cat validation_results_intermediate_*.json
```

---

## 🏗️ **Architecture Overview**

### **Gemini Primary Validation System**

```
┌─────────────────────────────────────────┐
│            Gemini Primary (85%)         │
│  ┌─────────────────────────────────────┐│
│  │ • Python Security Analysis         ││
│  │ • Vulnerability Pattern Recognition││
│  │ • Cross-System Correlation         ││
│  │ • Documentation Enhancement        ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────┐
│       Kernel Specialist (10%)          │
│  ┌─────────────────────────────────────┐│
│  │ • Deep C Code Analysis             ││
│  │ • Kernel UAF Detection             ││
│  │ • Memory Management Analysis       ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
            ▼
┌─────────────────────────────────────────┐
│        Claude Code (5%)                │
│  ┌─────────────────────────────────────┐│
│  │ • Final Orchestration              ││
│  │ • Consensus Generation             ││
│  │ • Report Compilation               ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

---

## ⚙️ **Configuration Options**

### **Core Configuration (`validation_runner.py`)**

```python
class GeminiPrimaryValidator:
    def __init__(self):
        # Workload distribution
        self.gemini_weight = 0.85      # 85% primary validation
        self.specialist_weight = 0.10   # 10% kernel analysis
        self.claude_weight = 0.05      # 5% orchestration
        
        # Processing parameters  
        self.batch_size = 50           # Patterns per batch
        self.max_concurrent = 4        # Parallel processing threads
        
        # Cost optimization
        self.estimated_cost_per_hour = 0.03  # Reduced cost with Gemini
```

### **Environment Variables**
```bash
# Optional: Gemini API configuration
export GEMINI_API_KEY="your_gemini_api_key"
export GEMINI_MODEL="gemini-pro"
export GEMINI_TEMPERATURE=0.7

# Optional: Processing limits
export ZEROBUILDER_BATCH_SIZE=50
export ZEROBUILDER_MAX_CONCURRENT=4
export ZEROBUILDER_BUDGET_LIMIT=250
```

---

## 📊 **Pattern Processing**

### **Supported Pattern Types**

| Pattern Type | Gemini Primary | Specialist Support | Processing Weight |
|-------------|---------------|-------------------|------------------|
| **SMB Concurrent Sessions** | ✅ Primary | Optional | 85% |
| **SMB State Anomalies** | ✅ Primary | Optional | 85% |
| **SMB Differential Testing** | ✅ Primary | Optional | 85% |
| **Kernel Race Conditions** | ✅ Primary | ✅ Required | 85% + 10% |
| **Kernel Temporal Patterns** | ✅ Primary | ✅ Required | 85% + 10% |
| **Python Code Analysis** | ✅ Primary | Not needed | 85% |
| **Cross-System Correlation** | ✅ Primary | Optional | 85% |

### **Processing Flow**

```python
def validate_pattern(self, pattern: Dict) -> ValidationResult:
    """
    1. Primary Gemini validation (85% weight)
    2. Specialist validation for kernel patterns (10% weight)  
    3. Weighted ensemble combination
    4. Claude orchestration (5% weight)
    """
```

---

## 🔍 **Quality Assurance**

### **Gemini Capability Scores**

| Assessment Area | Score | Quality Level |
|----------------|-------|---------------|
| **Python Security Analysis** | 25/30 | Strong |
| **Pattern Recognition** | 23/25 | Excellent |
| **Cross-System Analysis** | 18/20 | Strong |
| **Technical Depth** | 13/15 | Good |
| **Documentation Quality** | 9/10 | Excellent |
| **Total** | **88/100** | **Exceeds Threshold** |

### **Quality Thresholds**
- **85+ points**: Gemini Primary Validation ✅ **ACHIEVED**
- **70-84 points**: Gemini Quality Gate (fallback)
- **<70 points**: Original Multi-LLM plan (fallback)

---

## 💰 **Cost Management**

### **Cost Comparison**

```
Original Multi-LLM Budget: $200-250
├── CodeLlama Python 7B: $62.50 (25%)
├── StarCoder 2 7B: $62.50 (25%)  
├── DeepSeekCoder 6.7B: $25.00 (10%)
└── Claude Code: $100.00 (40%)

Gemini Primary Budget: $25-40
├── Gemini Primary: $21.25-34.00 (85%)
├── Kernel Specialist: $2.50-4.00 (10%)
└── Claude Code: $1.25-2.00 (5%)

Savings: $175-225 (85-90% reduction)
```

### **Budget Monitoring**
```bash
# Check current session costs
grep "estimated_cost" validation_session.log

# Monitor budget remaining
cat session_state.json | grep "budget_remaining"
```

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **1. Gemini API Connection Issues**
```bash
# Symptom: "Gemini loading failed" error
# Solution: Check API key and network connectivity
export GEMINI_API_KEY="your_key_here"
python -c "import google.generativeai as genai; print('Gemini accessible')"
```

#### **2. GPU Memory Issues** 
```bash
# Symptom: "Limited GPU memory" warning
# Solution: Reduce concurrent processing or use Gemini-only mode
export ZEROBUILDER_MAX_CONCURRENT=2

# Or force Gemini-only validation (100% Gemini, 0% specialist)
# Edit validation_runner.py:
# self.models['gemini_primary']['weight'] = 0.95
```

#### **3. Validation Stalling**
```bash
# Symptom: Processing stops at specific batch
# Solution: Resume from checkpoint
python deployment/validation_runner.py  # Automatically resumes
```

#### **4. High Cost Alerts**
```bash
# Symptom: "Budget limit approaching" warning
# Solution: Check cost estimation and adjust batch size
export ZEROBUILDER_BATCH_SIZE=25  # Reduce batch size
```

---

## 📈 **Performance Optimization**

### **Tuning Parameters**

#### **For High Throughput**
```python
# Increase parallelization
self.batch_size = 100
self.max_concurrent = 8

# Gemini-only mode (fastest)
self.gemini_weight = 0.95
self.specialist_weight = 0.0
```

#### **For High Quality**
```python
# Enable specialist for all patterns
# In validate_pattern():
if self.models.get('kernel_specialist'):
    specialist_result = self.validate_with_model(...)
```

#### **For Cost Optimization**
```python
# Gemini-only mode
self.gemini_weight = 0.95
self.specialist_weight = 0.0
self.claude_weight = 0.05
```

---

## 📋 **Session Management**

### **Starting New Session**
```bash
# Remove existing session state
rm session_state.json session_backup_*.json

# Start fresh validation
uv run python deployment/validation_runner.py
```

### **Resuming Session**
```bash
# Session automatically resumes from checkpoint
uv run python deployment/validation_runner.py

# Check resume point
cat session_state.json | grep "current_batch"
```

### **Session Backup**
```bash
# Manual backup
cp session_state.json session_backup_manual_$(date +%s).json

# Automatic backups created every batch
ls session_backup_*.json
```

---

## 📊 **Results Analysis**

### **Output Files**

| File | Purpose | When Created |
|------|---------|--------------|
| `session_state.json` | Current session state | Every batch |
| `session_backup_*.json` | Session backup | Every batch |
| `validation_session.log` | Processing logs | Continuous |
| `validation_results_intermediate_*.json` | Intermediate results | Every 10 batches |
| `validation_results_final_*.json` | Final results | Session end |
| `validation_summary_*.md` | Human-readable summary | Session end |

### **Result Analysis Commands**
```bash
# Check validation statistics
cat validation_summary_*.md

# Count validated patterns by status
jq '.[] | .validation_status' validation_results_final_*.json | sort | uniq -c

# Average confidence by pattern type  
jq '.[] | select(.pattern_type=="smb_concurrent_sessions") | .confidence' validation_results_final_*.json | awk '{sum+=$1; count++} END {print sum/count}'
```

---

## 🚀 **Advanced Usage**

### **Custom Gemini Prompts**
```python
def create_custom_gemini_prompt(self, pattern: Dict, analysis_type: str) -> str:
    """Create specialized prompts for different analysis types"""
    if analysis_type == "smb_deep":
        return f"""
        As an SMB protocol expert, perform deep analysis of:
        {pattern}
        Focus on: state machine vulnerabilities, oplock issues, authentication bypass
        """
    elif analysis_type == "kernel_uaf":
        return f"""
        As a kernel security expert, analyze this UAF pattern:
        {pattern}
        Focus on: memory lifecycle, reference counting, exploitation potential
        """
```

### **Integration with External Tools**
```bash
# Export results to external vulnerability scanner
jq '.[] | select(.validation_status=="validated") | .pattern_id' validation_results_final_*.json > validated_patterns.txt

# Generate CVE reports for high-confidence findings
python tools/generate_cve_reports.py --input validation_results_final_*.json --threshold 0.9
```

---

## 📚 **Reference Documentation**

### **Core Documents**
- `docs/planning/GEMINI_INTEGRATION_STRATEGY.md` - Strategy and decision framework
- `docs/status/GEMINI_INTEGRATION_COMPLETE.md` - Implementation details
- `deployment/validation_runner.py` - Source code
- `README.md` - Project overview

### **Related Guides**
- `docs/research/GEMINI_LOCAL_INTEGRATION_ANALYSIS.md` - Cost-benefit analysis
- `docs/planning/AI_COMMUNICATION_CLARIFICATION.md` - Multi-LLM protocols

---

## 🎯 **Best Practices**

### **Do's:**
- ✅ Monitor session logs for processing progress
- ✅ Use automatic checkpointing for long sessions  
- ✅ Review intermediate results every 10 batches
- ✅ Backup session state before major changes
- ✅ Validate budget limits before starting large batches

### **Don'ts:**
- ❌ Don't remove session_state.json during active processing
- ❌ Don't modify weights without understanding impact
- ❌ Don't ignore budget warnings
- ❌ Don't run multiple validation sessions simultaneously
- ❌ Don't skip intermediate result reviews

---

## 🆘 **Support**

### **Getting Help**
1. **Check Logs**: Review `validation_session.log` for errors
2. **Verify Configuration**: Ensure all weights sum to ~1.0
3. **Test Connection**: Verify Gemini API connectivity
4. **Check Resources**: Monitor GPU memory and disk space
5. **Consult Documentation**: Review strategy and implementation docs

### **Common Solutions**
- **Performance Issues**: Reduce batch size or concurrent threads
- **Quality Concerns**: Enable specialist validation for all patterns
- **Cost Overruns**: Switch to Gemini-only mode or reduce batch frequency
- **Memory Issues**: Restart session with lower concurrency

---

**Document Status**: COMPLETE ✅  
**Last Updated**: June 27, 2025  
**Version**: v1.0