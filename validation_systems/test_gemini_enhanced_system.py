#!/usr/bin/env python3
"""
Standalone Test for Gemini Enhanced Validation System
Tests Gemini integration without importing problematic modules
"""

import time
import logging
from gemini_integration import GeminiValidator, GeminiAnalysisResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StandaloneEnhancedValidator:
    """Standalone validator for testing Gemini integration"""
    
    def __init__(self):
        self.gemini_validator = GeminiValidator()
        self.stats = {
            "total_tests": 0,
            "gemini_successes": 0,
            "vulnerabilities_detected": 0,
            "high_confidence_results": 0
        }
        
        logger.info("🚀 Standalone Enhanced Validator initialized")
        logger.info("🎯 Testing Gemini Free API integration")
    
    def analyze_code(self, code: str, context: str) -> dict:
        """Analyze code using Gemini validator"""
        self.stats["total_tests"] += 1
        
        logger.info(f"🔍 Analyzing: {code}")
        
        # Use Gemini validator
        start_time = time.time()
        result = self.gemini_validator.analyze_vulnerability(code, context)
        analysis_time = time.time() - start_time
        
        # Update stats
        if result.verdict != "ERROR":
            self.stats["gemini_successes"] += 1
        
        if result.verdict == "VULNERABLE":
            self.stats["vulnerabilities_detected"] += 1
        
        if result.confidence >= 0.8:
            self.stats["high_confidence_results"] += 1
        
        return {
            "code": code,
            "context": context,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "severity": result.severity,
            "vulnerability_types": result.vulnerability_types,
            "recommendations": result.recommendations[:2],  # Top 2
            "analysis_time": analysis_time,
            "reasoning": result.reasoning[:200] + "..." if len(result.reasoning) > 200 else result.reasoning
        }
    
    def run_comprehensive_test(self):
        """Run comprehensive test suite"""
        logger.info("🧪 Running Comprehensive Gemini Validation Test")
        logger.info("=" * 60)
        
        # Test cases covering ZeroBuilder's strategic objectives
        test_cases = [
            {
                "name": "SMB EternalBlue CVE-2017-0143",
                "code": "memcpy(buffer, packet_data, packet_len); // No bounds check",
                "context": "SMB v1 packet processing - EternalBlue vulnerability",
                "expected_vulnerable": True
            },
            {
                "name": "SMB Zerologon CVE-2020-1472", 
                "code": "if (user == NULL) return 1; // Grant access on null user",
                "context": "SMB authentication bypass - Zerologon pattern",
                "expected_vulnerable": True
            },
            {
                "name": "Kernel Use-After-Free",
                "code": "free(session_data); session_data->active = 1; // UAF",
                "context": "Linux kernel session management - race condition",
                "expected_vulnerable": True
            },
            {
                "name": "Kernel TOCTOU Race",
                "code": "if (access(file, R_OK) == 0) { fd = open(file, O_RDONLY); }",
                "context": "Time-of-check-time-of-use race condition",
                "expected_vulnerable": True
            },
            {
                "name": "Command Injection",
                "code": "system(user_command); // No input validation",
                "context": "User command execution without sanitization",
                "expected_vulnerable": True
            },
            {
                "name": "Safe String Handling",
                "code": "strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\\0';",
                "context": "Secure string copying with null termination",
                "expected_vulnerable": False
            },
            {
                "name": "Safe Memory Management",
                "code": "ptr = malloc(size); if(ptr) { use_ptr(ptr); free(ptr); ptr = NULL; }",
                "context": "Proper memory allocation and cleanup",
                "expected_vulnerable": False
            },
            {
                "name": "Input Validation",
                "code": "if (strlen(input) >= MAX_SIZE) return -1; strcpy(buffer, input);",
                "context": "String copy with length validation",
                "expected_vulnerable": False
            }
        ]
        
        results = []
        
        for i, test_case in enumerate(test_cases, 1):
            logger.info(f"\n📋 Test {i}: {test_case['name']}")
            
            # Run analysis
            result = self.analyze_code(test_case["code"], test_case["context"])
            
            # Evaluate result
            is_vulnerable = result["verdict"] in ["VULNERABLE", "UNCERTAIN"] and result["severity"] in ["HIGH", "CRITICAL", "MEDIUM"]
            correct_detection = (is_vulnerable and test_case["expected_vulnerable"]) or (not is_vulnerable and not test_case["expected_vulnerable"])
            
            results.append({
                "name": test_case["name"],
                "expected": test_case["expected_vulnerable"],
                "detected": is_vulnerable,
                "correct": correct_detection,
                "confidence": result["confidence"],
                "severity": result["severity"],
                "verdict": result["verdict"]
            })
            
            # Log result
            status = "✅ CORRECT" if correct_detection else "❌ INCORRECT"
            logger.info(f"{status} Expected: {'VULNERABLE' if test_case['expected_vulnerable'] else 'SAFE'}")
            logger.info(f"📊 Detected: {result['verdict']} (confidence: {result['confidence']:.2f})")
            logger.info(f"⚡ Severity: {result['severity']}")
            logger.info(f"🔍 Types: {', '.join(result['vulnerability_types']) if result['vulnerability_types'] else 'None'}")
            logger.info(f"💡 Recommendations: {', '.join(result['recommendations'])}")
            logger.info(f"⏱️ Analysis time: {result['analysis_time']:.2f}s")
        
        # Generate summary
        self._generate_summary(results)
    
    def _generate_summary(self, results: list):
        """Generate test summary and assessment"""
        total_tests = len(results)
        correct_detections = sum(1 for r in results if r["correct"])
        vulnerable_tests = sum(1 for r in results if r["expected"])
        detected_vulnerabilities = sum(1 for r in results if r["detected"] and r["expected"])
        false_positives = sum(1 for r in results if r["detected"] and not r["expected"])
        false_negatives = sum(1 for r in results if not r["detected"] and r["expected"])
        
        avg_confidence = sum(r["confidence"] for r in results) / total_tests
        high_confidence_count = sum(1 for r in results if r["confidence"] >= 0.8)
        
        logger.info(f"\n" + "=" * 60)
        logger.info("🏁 GEMINI VALIDATION SYSTEM ASSESSMENT")
        logger.info("=" * 60)
        
        # Overall accuracy
        accuracy = correct_detections / total_tests
        logger.info(f"📊 Overall Accuracy: {correct_detections}/{total_tests} ({accuracy*100:.1f}%)")
        
        # Vulnerability detection metrics
        if vulnerable_tests > 0:
            detection_rate = detected_vulnerabilities / vulnerable_tests
            logger.info(f"🎯 Vulnerability Detection: {detected_vulnerabilities}/{vulnerable_tests} ({detection_rate*100:.1f}%)")
        
        logger.info(f"❌ False Positives: {false_positives}")
        logger.info(f"❌ False Negatives: {false_negatives}")
        logger.info(f"📈 Average Confidence: {avg_confidence:.2f}")
        logger.info(f"🎯 High Confidence Results: {high_confidence_count}/{total_tests} ({high_confidence_count/total_tests*100:.1f}%)")
        
        # System performance
        logger.info(f"\n📈 System Statistics:")
        logger.info(f"  Total Tests: {self.stats['total_tests']}")
        logger.info(f"  Gemini Successes: {self.stats['gemini_successes']}")
        logger.info(f"  Vulnerabilities Detected: {self.stats['vulnerabilities_detected']}")
        logger.info(f"  High Confidence: {self.stats['high_confidence_results']}")
        
        # Strategic objective assessment
        logger.info(f"\n🎯 Strategic Objective Assessment:")
        
        # SMB vulnerabilities (first 2 test cases)
        smb_results = results[:2]
        smb_correct = sum(1 for r in smb_results if r["correct"])
        logger.info(f"  SMB Protocol Detection: {smb_correct}/{len(smb_results)} ({smb_correct/len(smb_results)*100:.1f}%)")
        
        # Kernel vulnerabilities (test cases 3-4)
        kernel_results = results[2:4]
        kernel_correct = sum(1 for r in kernel_results if r["correct"])
        logger.info(f"  Kernel Race Detection: {kernel_correct}/{len(kernel_results)} ({kernel_correct/len(kernel_results)*100:.1f}%)")
        
        # Overall assessment
        if accuracy >= 0.75 and detection_rate >= 0.75:
            logger.info(f"\n🎉 GEMINI INTEGRATION: SUCCESS")
            logger.info(f"✅ System meets quality requirements for primary validation")
            logger.info(f"💰 Cost: $0 (Free Tier) - Excellent budget preservation")
            logger.info(f"🚀 Ready for production deployment in ZeroBuilder")
        elif accuracy >= 0.6:
            logger.info(f"\n⚠️  GEMINI INTEGRATION: PARTIAL SUCCESS")
            logger.info(f"💡 System suitable for quality gate role (fallback validation)")
            logger.info(f"🔧 Consider tuning prompts or confidence thresholds")
        else:
            logger.info(f"\n❌ GEMINI INTEGRATION: NEEDS IMPROVEMENT")
            logger.info(f"🔧 Requires prompt engineering or alternative approach")
        
        # Next steps
        logger.info(f"\n💡 Next Steps:")
        if accuracy >= 0.75:
            logger.info(f"1. ✅ Deploy Gemini as primary validator")
            logger.info(f"2. ✅ Keep Multi-LLM simulation as fallback")
            logger.info(f"3. ✅ Integrate with ZeroBuilder validation pipeline")
            logger.info(f"4. 🔧 Get real Gemini API key for production use")
        else:
            logger.info(f"1. 🔧 Improve Gemini prompts and parsing")
            logger.info(f"2. 🔄 Use Gemini as quality gate (not primary)")
            logger.info(f"3. ✅ Continue with proven Multi-LLM simulation")

def main():
    """Main test runner"""
    logger.info("🚀 Gemini Enhanced Validation System Test")
    logger.info("Testing: Gemini Free API + ZeroBuilder Integration")
    logger.info("=" * 60)
    
    # Initialize validator
    validator = StandaloneEnhancedValidator()
    
    # Run comprehensive test
    validator.run_comprehensive_test()
    
    logger.info(f"\n🔑 To use real Gemini API:")
    logger.info(f"1. Get API key: https://makersuite.google.com/app/apikey")
    logger.info(f"2. Set environment: export GEMINI_API_KEY='your_key'")
    logger.info(f"3. Re-run test with real API")

if __name__ == "__main__":
    main()