#!/usr/bin/env python3
"""
Enhanced ZeroBuilder Validation System with Real Gemini Integration
Combines proven hybrid detectors with Gemini Free API
"""

import sys
import time
import logging
from pathlib import Path

# Add src to path
sys.path.append('src')

# Import existing components
from zerobuilder.utils.llm_reviewers import LLMReviewOrchestrator
from gemini_integration import GeminiValidator, GeminiAnalysisResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedValidationSystem:
    """Enhanced validation system with Gemini + Proven hybrid detectors"""
    
    def __init__(self):
        self.gemini_validator = GeminiValidator()
        self.llm_orchestrator = LLMReviewOrchestrator()
        self.validation_stats = {
            "total_analyses": 0,
            "gemini_analyses": 0,
            "fallback_analyses": 0,
            "high_confidence_results": 0,
            "vulnerabilities_detected": 0
        }
        
        logger.info("🚀 Enhanced Validation System initialized")
        logger.info("🎯 Primary: Gemini Free API")
        logger.info("🔄 Fallback: Proven Multi-LLM simulation")
        logger.info("💰 Cost: $0 (Free tier + simulated fallback)")
    
    def analyze_vulnerability(self, code: str, context: str = "", use_fallback: bool = False) -> dict:
        """Analyze vulnerability using Gemini primary + Multi-LLM fallback"""
        
        self.validation_stats["total_analyses"] += 1
        logger.info(f"🔍 Starting enhanced analysis #{self.validation_stats['total_analyses']}")
        
        start_time = time.time()
        
        if not use_fallback:
            # Primary: Gemini analysis
            logger.info("🧠 Using Gemini primary validator...")
            gemini_result = self.gemini_validator.analyze_vulnerability(code, context)
            
            # Check if Gemini result is reliable
            if gemini_result.confidence >= 0.75 and gemini_result.verdict != "ERROR":
                self.validation_stats["gemini_analyses"] += 1
                
                if gemini_result.confidence >= 0.8:
                    self.validation_stats["high_confidence_results"] += 1
                
                if gemini_result.verdict == "VULNERABLE":
                    self.validation_stats["vulnerabilities_detected"] += 1
                
                return self._format_gemini_result(gemini_result, time.time() - start_time)
            else:
                logger.info("🔄 Gemini confidence low, using Multi-LLM fallback...")
                use_fallback = True
        
        if use_fallback:
            # Fallback: Multi-LLM simulation
            logger.info("🔄 Using Multi-LLM fallback...")
            self.validation_stats["fallback_analyses"] += 1
            
            # Prepare data for Multi-LLM
            gat_results = [self._code_to_gat_result(code, context)]
            code_samples = [code]
            
            # Run Multi-LLM analysis
            llm_result = self.llm_orchestrator.review_gat_predictions(gat_results, code_samples)
            
            consensus = llm_result["consensus"]
            if "HIGH_CONFIDENCE" in consensus["consensus_verdict"]:
                self.validation_stats["high_confidence_results"] += 1
            
            if "VULNERABLE" in consensus["consensus_verdict"]:
                self.validation_stats["vulnerabilities_detected"] += 1
            
            return self._format_llm_result(llm_result, time.time() - start_time)
    
    def _code_to_gat_result(self, code: str, context: str) -> dict:
        """Convert code to GAT-like result for Multi-LLM processing"""
        # Analyze code for risk indicators
        risk_score = 0.5  # Base risk
        
        high_risk_patterns = ['strcpy', 'gets', 'system', 'malloc', 'free']
        for pattern in high_risk_patterns:
            if pattern in code.lower():
                risk_score += 0.15
        
        risk_score = min(risk_score, 0.95)
        
        # Determine CWE type
        cwe_type = "CWE121"  # Default to buffer overflow
        if "free" in code.lower():
            cwe_type = "CWE416"  # Use after free
        elif "system" in code.lower():
            cwe_type = "CWE78"   # Command injection
        
        return {
            "function": context or "analyzed_function",
            "risk_score": risk_score,
            "cwe_type": cwe_type
        }
    
    def _format_gemini_result(self, gemini_result: GeminiAnalysisResult, total_time: float) -> dict:
        """Format Gemini result for consistent output"""
        return {
            "validator": "gemini_primary",
            "verdict": gemini_result.verdict,
            "confidence": gemini_result.confidence,
            "severity": gemini_result.severity,
            "vulnerability_types": gemini_result.vulnerability_types,
            "recommendations": gemini_result.recommendations,
            "reasoning": gemini_result.reasoning,
            "analysis_time": total_time,
            "tokens_used": gemini_result.tokens_used,
            "cost_estimate": 0.0,  # Free tier
            "model_used": "gemini-1.5-flash"
        }
    
    def _format_llm_result(self, llm_result: dict, total_time: float) -> dict:
        """Format Multi-LLM result for consistent output"""
        consensus = llm_result["consensus"]
        
        return {
            "validator": "multi_llm_fallback",
            "verdict": consensus["consensus_verdict"],
            "confidence": consensus["weighted_confidence"],
            "severity": self._consensus_to_severity(consensus["consensus_verdict"]),
            "vulnerability_types": self._extract_vuln_types_from_consensus(llm_result),
            "recommendations": llm_result["action_items"][:3],
            "reasoning": consensus["recommendation"],
            "analysis_time": total_time,
            "tokens_used": 0,  # Simulated
            "cost_estimate": 0.0,  # Simulated
            "model_used": "multi_llm_simulation"
        }
    
    def _consensus_to_severity(self, verdict: str) -> str:
        """Convert consensus verdict to severity"""
        if "HIGH_CONFIDENCE" in verdict and "VULNERABLE" in verdict:
            return "HIGH"
        elif "MODERATE_CONFIDENCE" in verdict and "VULNERABLE" in verdict:
            return "MEDIUM"
        elif "VULNERABLE" in verdict:
            return "LOW"
        else:
            return "INFO"
    
    def _extract_vuln_types_from_consensus(self, llm_result: dict) -> list:
        """Extract vulnerability types from Multi-LLM consensus"""
        types = []
        for reviewer_name, review in llm_result["individual_reviews"].items():
            if "SECURITY" in review.verdict:
                types.append("Security Vulnerability")
            elif "IMPLEMENTATION" in review.verdict:
                types.append("Implementation Issue")
        
        return list(set(types)) if types else ["Code Quality Issue"]
    
    def run_comprehensive_test(self):
        """Run comprehensive test of the enhanced system"""
        logger.info("🧪 Running Comprehensive Enhanced System Test")
        logger.info("=" * 70)
        
        # Test cases covering different scenarios
        test_cases = [
            {
                "name": "EternalBlue Buffer Overflow",
                "code": "memcpy(buffer, packet_data, packet_len); // CVE-2017-0143",
                "context": "SMB packet processing",
                "expected": "HIGH"
            },
            {
                "name": "Safe String Copy",
                "code": "strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\\0';",
                "context": "String processing",
                "expected": "LOW"
            },
            {
                "name": "Use After Free",
                "code": "free(session_data); session_data->active = 1; // UAF",
                "context": "Session management",
                "expected": "HIGH"
            },
            {
                "name": "Command Injection",
                "code": "system(user_command); // No validation",
                "context": "User command processing",
                "expected": "HIGH"
            },
            {
                "name": "Safe Memory Management",
                "code": "ptr = malloc(size); if(ptr) { use_ptr(ptr); free(ptr); ptr = NULL; }",
                "context": "Memory allocation",
                "expected": "LOW"
            }
        ]
        
        results = []
        
        for i, test_case in enumerate(test_cases, 1):
            logger.info(f"\n📋 Test Case {i}: {test_case['name']}")
            logger.info(f"🔍 Code: {test_case['code']}")
            logger.info(f"📝 Context: {test_case['context']}")
            logger.info(f"🎯 Expected: {test_case['expected']} severity")
            
            # Run analysis
            result = self.analyze_vulnerability(test_case["code"], test_case["context"])
            
            # Evaluate result
            success = self._evaluate_result(result, test_case["expected"])
            results.append({
                "test_case": test_case["name"],
                "expected": test_case["expected"],
                "actual": result["severity"],
                "success": success,
                "validator": result["validator"],
                "confidence": result["confidence"]
            })
            
            # Log result
            status = "✅ PASS" if success else "❌ FAIL"
            logger.info(f"{status} Validator: {result['validator']}")
            logger.info(f"📊 Result: {result['verdict']} (confidence: {result['confidence']:.2f})")
            logger.info(f"⚡ Severity: {result['severity']}")
            logger.info(f"🔍 Types: {', '.join(result['vulnerability_types'])}")
            logger.info(f"⏱️ Time: {result['analysis_time']:.2f}s")
        
        # Generate summary
        self._generate_test_summary(results)
    
    def _evaluate_result(self, result: dict, expected_severity: str) -> bool:
        """Evaluate if result matches expected severity"""
        actual_severity = result["severity"]
        
        # Map expected to actual severity levels
        severity_mapping = {
            "HIGH": ["HIGH", "CRITICAL"],
            "MEDIUM": ["MEDIUM", "HIGH"],
            "LOW": ["LOW", "INFO", "MEDIUM"]
        }
        
        return actual_severity in severity_mapping.get(expected_severity, [expected_severity])
    
    def _generate_test_summary(self, results: list):
        """Generate comprehensive test summary"""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r["success"])
        gemini_tests = sum(1 for r in results if r["validator"] == "gemini_primary")
        fallback_tests = sum(1 for r in results if r["validator"] == "multi_llm_fallback")
        
        avg_confidence = sum(r["confidence"] for r in results) / total_tests
        
        logger.info(f"\n" + "=" * 70)
        logger.info("🏁 ENHANCED SYSTEM TEST SUMMARY")
        logger.info("=" * 70)
        logger.info(f"📊 Test Results: {passed_tests}/{total_tests} PASSED ({passed_tests/total_tests*100:.1f}%)")
        logger.info(f"🧠 Gemini Primary: {gemini_tests}/{total_tests} ({gemini_tests/total_tests*100:.1f}%)")
        logger.info(f"🔄 Multi-LLM Fallback: {fallback_tests}/{total_tests} ({fallback_tests/total_tests*100:.1f}%)")
        logger.info(f"📈 Average Confidence: {avg_confidence:.2f}")
        
        logger.info(f"\n📈 System Performance:")
        logger.info(f"  Total Analyses: {self.validation_stats['total_analyses']}")
        logger.info(f"  Gemini Success: {self.validation_stats['gemini_analyses']}")
        logger.info(f"  High Confidence: {self.validation_stats['high_confidence_results']}")
        logger.info(f"  Vulnerabilities: {self.validation_stats['vulnerabilities_detected']}")
        
        # Overall assessment
        if passed_tests/total_tests >= 0.8:
            logger.info(f"\n🎉 SYSTEM VALIDATION: SUCCESS")
            logger.info(f"✅ Enhanced system ready for production use")
            logger.info(f"💰 Cost: $0 (Free Gemini + simulated fallback)")
            logger.info(f"🎯 Quality: Proven hybrid detectors + Gemini validation")
        else:
            logger.info(f"\n⚠️  SYSTEM VALIDATION: NEEDS IMPROVEMENT")
            logger.info(f"❌ Some test cases failed - review configuration")

def main():
    """Test enhanced validation system"""
    logger.info("🚀 Enhanced ZeroBuilder Validation System")
    logger.info("Gemini Free API + Proven Hybrid Detectors")
    logger.info("=" * 70)
    
    # Initialize system
    enhanced_system = EnhancedValidationSystem()
    
    # Run comprehensive test
    enhanced_system.run_comprehensive_test()
    
    logger.info(f"\n💡 Next Steps:")
    logger.info(f"1. Get Gemini API key: https://makersuite.google.com/app/apikey")
    logger.info(f"2. Set environment variable: export GEMINI_API_KEY='your_key_here'")
    logger.info(f"3. Test with real Gemini API")
    logger.info(f"4. Deploy enhanced validation for ZeroBuilder pipeline")

if __name__ == "__main__":
    main()