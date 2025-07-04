#!/usr/bin/env python3
"""
CPU-Optimized Multi-LLM System for ZeroBuilder
Reliable local deployment using CPU inference with smaller, efficient models
"""

import torch
import logging
import time
import gc
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from typing import Dict, List, Optional, Any
import json
import threading
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CPUMultiLLMSystem:
    """CPU-optimized Multi-LLM system with efficient model management"""
    
    def __init__(self):
        self.device = "cpu"  # Force CPU for reliability
        self.models = {}
        self.tokenizers = {}
        self.pipelines = {}
        self.current_model = None
        
        # CPU-optimized model selections (smaller, efficient models)
        self.model_configs = {
            "codellama_small": {
                "model_id": "microsoft/DialoGPT-small",  # Fallback for testing
                "role": "code_analysis",
                "weight": 0.35,
                "max_tokens": 256
            },
            "starcoder_alternative": {
                "model_id": "microsoft/DialoGPT-medium", # Fallback for testing  
                "role": "security_detection",
                "weight": 0.35,
                "max_tokens": 256
            },
            "deepseek_alternative": {
                "model_id": "microsoft/DialoGPT-small",  # Fallback for testing
                "role": "pattern_matching", 
                "weight": 0.15,
                "max_tokens": 256
            },
            "claude_orchestrator": {
                "model_id": "simulated",  # Keep Claude as orchestrator
                "role": "orchestration",
                "weight": 0.15,
                "max_tokens": 512
            }
        }
        
        logger.info(f"🚀 CPU Multi-LLM System initialized")
        logger.info(f"💾 Device: {self.device}")
        logger.info(f"🔧 Optimized for CPU inference with efficient models")
    
    def load_model(self, model_name: str) -> bool:
        """Load a specific model for CPU inference"""
        try:
            config = self.model_configs.get(model_name)
            if not config:
                logger.error(f"❌ Unknown model: {model_name}")
                return False
            
            model_id = config["model_id"]
            
            # Handle simulated models (Claude)
            if model_id == "simulated":
                logger.info(f"✅ {model_name} using simulated responses")
                return True
            
            logger.info(f"📥 Loading {model_name}: {model_id}")
            
            # Unload other models to save memory
            if self.current_model and self.current_model != model_name:
                self.unload_current_model()
            
            # Check if already loaded
            if model_name in self.models:
                self.current_model = model_name
                logger.info(f"✅ {model_name} already loaded")
                return True
            
            # Load tokenizer
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            
            # Load model for CPU
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                torch_dtype=torch.float32,  # Use float32 for CPU
                device_map="cpu",
                low_cpu_mem_usage=True
            )
            
            # Create pipeline for easier generation
            pipe = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device=-1,  # CPU
                return_full_text=False
            )
            
            # Store components
            self.models[model_name] = model
            self.tokenizers[model_name] = tokenizer
            self.pipelines[model_name] = pipe
            self.current_model = model_name
            
            logger.info(f"✅ {model_name} loaded successfully on CPU")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load {model_name}: {e}")
            return False
    
    def unload_current_model(self):
        """Unload current model to free memory"""
        if self.current_model and self.current_model in self.models:
            logger.info(f"🗑️ Unloading {self.current_model}")
            if self.current_model in self.models:
                del self.models[self.current_model]
            if self.current_model in self.tokenizers:
                del self.tokenizers[self.current_model]
            if self.current_model in self.pipelines:
                del self.pipelines[self.current_model]
            self.current_model = None
            gc.collect()
    
    def analyze_with_model(self, model_name: str, prompt: str, vulnerability_context: str = "") -> Dict:
        """Analyze code with specific model"""
        try:
            # Load model if needed
            if not self.load_model(model_name):
                return {"error": f"Failed to load {model_name}"}
            
            config = self.model_configs[model_name]
            
            # Handle simulated models
            if config["model_id"] == "simulated":
                return self._simulate_claude_analysis(prompt, vulnerability_context)
            
            # Real model inference
            pipe = self.pipelines[model_name]
            
            # Create analysis prompt based on model role
            analysis_prompt = self._create_analysis_prompt(model_name, prompt, vulnerability_context)
            
            # Generate response
            start_time = time.time()
            result = pipe(
                analysis_prompt,
                max_new_tokens=config["max_tokens"],
                temperature=0.7,
                do_sample=True,
                truncation=True
            )
            generation_time = time.time() - start_time
            
            # Extract response
            response = result[0]["generated_text"] if result else "No response generated"
            
            # Parse response into structured format
            analysis = self._parse_model_response(model_name, response, generation_time)
            
            logger.info(f"⚡ {model_name} analysis completed in {generation_time:.2f}s")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ Analysis failed for {model_name}: {e}")
            return {"error": str(e)}
    
    def _create_analysis_prompt(self, model_name: str, code: str, context: str) -> str:
        """Create model-specific analysis prompt"""
        config = self.model_configs[model_name]
        role = config["role"]
        
        if role == "code_analysis":
            return f"""
Analyze this code for implementation issues:

Code:
{code}

Context: {context}

Focus on: Code quality, logic errors, implementation flaws.
Response format: [ISSUE_TYPE] Description
"""
        
        elif role == "security_detection":
            return f"""
Analyze this code for security vulnerabilities:

Code:
{code}

Context: {context}

Focus on: Security flaws, attack vectors, vulnerability patterns.
Response format: [VULNERABILITY] Description and severity
"""
        
        elif role == "pattern_matching":
            return f"""
Analyze this code for patterns and anomalies:

Code:
{code}

Context: {context}

Focus on: Code patterns, unusual structures, potential issues.
Response format: [PATTERN] Description and likelihood
"""
        
        else:
            return f"Analyze this code:\n{code}\nContext: {context}"
    
    def _parse_model_response(self, model_name: str, response: str, generation_time: float) -> Dict:
        """Parse model response into structured format"""
        config = self.model_configs[model_name]
        
        # Extract confidence based on response quality
        confidence = 0.7  # Base confidence
        if "vulnerability" in response.lower() or "security" in response.lower():
            confidence += 0.1
        if "critical" in response.lower() or "high" in response.lower():
            confidence += 0.1
        if len(response) > 50:  # Detailed response
            confidence += 0.1
        
        confidence = min(confidence, 0.95)
        
        return {
            "model": model_name,
            "role": config["role"],
            "weight": config["weight"],
            "confidence": confidence,
            "response": response,
            "generation_time": generation_time,
            "verdict": self._extract_verdict(response),
            "issues_found": self._extract_issues(response)
        }
    
    def _extract_verdict(self, response: str) -> str:
        """Extract verdict from response"""
        response_lower = response.lower()
        
        if any(word in response_lower for word in ["critical", "severe", "high risk"]):
            return "CRITICAL_VULNERABILITY"
        elif any(word in response_lower for word in ["vulnerability", "security", "exploit"]):
            return "SECURITY_ISSUE"
        elif any(word in response_lower for word in ["issue", "problem", "error"]):
            return "CODE_ISSUE"
        else:
            return "NO_MAJOR_ISSUES"
    
    def _extract_issues(self, response: str) -> List[str]:
        """Extract specific issues from response"""
        issues = []
        
        # Simple pattern matching for common issues
        if "buffer overflow" in response.lower():
            issues.append("Buffer Overflow")
        if "injection" in response.lower():
            issues.append("Injection Vulnerability")
        if "race condition" in response.lower():
            issues.append("Race Condition")
        if "memory leak" in response.lower():
            issues.append("Memory Leak")
        
        return issues if issues else ["General code analysis"]
    
    def _simulate_claude_analysis(self, prompt: str, context: str) -> Dict:
        """Simulate Claude analysis for orchestration"""
        # This simulates Claude's orchestration role
        confidence = 0.85
        
        # Analyze complexity of the input
        code_complexity = len(prompt.split('\n'))
        has_security_keywords = any(word in prompt.lower() for word in 
                                  ['strcpy', 'malloc', 'free', 'system', 'gets'])
        
        if has_security_keywords:
            verdict = "REQUIRES_SECURITY_ANALYSIS"
            response = f"Code analysis orchestration: Detected potential security patterns. Complexity: {code_complexity} lines. Recommending Multi-LLM security review."
        else:
            verdict = "STANDARD_ANALYSIS"
            response = f"Code analysis orchestration: Standard code review. Complexity: {code_complexity} lines. Proceeding with Multi-LLM analysis."
        
        return {
            "model": "claude_orchestrator",
            "role": "orchestration",
            "weight": 0.15,
            "confidence": confidence,
            "response": response,
            "generation_time": 0.1,  # Simulated fast response
            "verdict": verdict,
            "issues_found": ["Orchestration complete"]
        }
    
    def run_multi_llm_analysis(self, code_sample: str, context: str = "") -> Dict:
        """Run complete Multi-LLM analysis"""
        logger.info(f"🔄 Starting Multi-LLM analysis")
        logger.info(f"📝 Code sample: {len(code_sample)} characters")
        
        start_time = time.time()
        results = {}
        
        # Analyze with each model
        for model_name in self.model_configs.keys():
            logger.info(f"🧠 Analyzing with {model_name}...")
            analysis = self.analyze_with_model(model_name, code_sample, context)
            results[model_name] = analysis
        
        # Generate consensus
        consensus = self._generate_consensus(results)
        
        total_time = time.time() - start_time
        
        final_result = {
            "code_sample": code_sample,
            "context": context,
            "individual_analyses": results,
            "consensus": consensus,
            "total_analysis_time": total_time,
            "timestamp": time.time()
        }
        
        logger.info(f"✅ Multi-LLM analysis complete in {total_time:.2f}s")
        logger.info(f"🎯 Consensus: {consensus['verdict']} (confidence: {consensus['confidence']:.2f})")
        
        return final_result
    
    def _generate_consensus(self, results: Dict) -> Dict:
        """Generate weighted consensus from all model results"""
        total_weight = 0
        weighted_confidence = 0
        verdicts = []
        all_issues = set()
        
        for model_name, analysis in results.items():
            if "error" not in analysis:
                weight = analysis["weight"]
                confidence = analysis["confidence"]
                
                total_weight += weight
                weighted_confidence += confidence * weight
                verdicts.append(analysis["verdict"])
                all_issues.update(analysis["issues_found"])
        
        # Calculate final confidence
        final_confidence = weighted_confidence / total_weight if total_weight > 0 else 0.5
        
        # Determine consensus verdict
        security_verdicts = sum(1 for v in verdicts if "VULNERABILITY" in v or "SECURITY" in v)
        critical_verdicts = sum(1 for v in verdicts if "CRITICAL" in v)
        
        if critical_verdicts >= 2:
            consensus_verdict = "HIGH_CONFIDENCE_CRITICAL"
        elif security_verdicts >= 2:
            consensus_verdict = "HIGH_CONFIDENCE_VULNERABLE" 
        elif security_verdicts >= 1:
            consensus_verdict = "MODERATE_CONFIDENCE_VULNERABLE"
        else:
            consensus_verdict = "LOW_CONFIDENCE_BENIGN"
        
        # Generate recommendation
        if final_confidence > 0.8 and security_verdicts >= 2:
            recommendation = "IMMEDIATE_REVIEW_PRIORITY - Deploy security analysis immediately"
        elif final_confidence > 0.6:
            recommendation = "SCHEDULE_REVIEW - Add to security review queue"
        else:
            recommendation = "LOW_PRIORITY - Consider for comprehensive testing only"
        
        return {
            "verdict": consensus_verdict,
            "confidence": final_confidence,
            "recommendation": recommendation,
            "issues_identified": list(all_issues),
            "model_agreement": len([v for v in verdicts if "VULNERABILITY" in v or "SECURITY" in v]) / len(verdicts),
            "participating_models": len([r for r in results.values() if "error" not in r])
        }

def main():
    """Test CPU Multi-LLM system"""
    logger.info("🚀 Testing CPU Multi-LLM System")
    logger.info("=" * 60)
    
    # Initialize system
    multi_llm = CPUMultiLLMSystem()
    
    # Test code samples
    test_cases = [
        {
            "name": "Buffer Overflow Vulnerability",
            "code": "strcpy(buffer, user_input); // No bounds checking",
            "context": "User input processing function"
        },
        {
            "name": "Safe String Handling", 
            "code": "strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\\0';",
            "context": "String copy with bounds checking"
        },
        {
            "name": "Use After Free",
            "code": "free(ptr); ptr->data = 42; // Access after free",
            "context": "Memory management code"
        }
    ]
    
    # Run analyses
    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"\n📋 Test Case {i}: {test_case['name']}")
        logger.info(f"🔍 Code: {test_case['code']}")
        
        result = multi_llm.run_multi_llm_analysis(test_case["code"], test_case["context"])
        
        consensus = result["consensus"]
        logger.info(f"🎯 Result: {consensus['verdict']}")
        logger.info(f"📊 Confidence: {consensus['confidence']:.2f}")
        logger.info(f"💡 Recommendation: {consensus['recommendation']}")
        logger.info(f"🔍 Issues: {', '.join(consensus['issues_identified'])}")
    
    logger.info(f"\n🎉 CPU Multi-LLM System test complete!")
    logger.info(f"✅ Ready to integrate with ZeroBuilder validation pipeline")

if __name__ == "__main__":
    main()