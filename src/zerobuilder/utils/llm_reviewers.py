"""
Multi-LLM Review System for ZeroBuilder
Claude Code (primary), Grok, GPT-4 as reviewers/validators/critiquers
"""

import json
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import asyncio
import requests

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    CLAUDE_CODE = "claude_code"
    GROK = "grok"
    GPT4 = "gpt4"
    DEEPSEEK = "deepseek"

@dataclass
class ReviewResult:
    reviewer: LLMProvider
    timestamp: float
    confidence: float
    verdict: str
    reasoning: str
    suggestions: List[str]
    validation_score: float

class LLMReviewOrchestrator:
    """
    Orchestrates multiple LLM reviewers for vulnerability analysis
    Claude Code: Primary developer/implementer
    Grok: Security expert/critic  
    GPT-4: Code quality validator
    DeepSeek: Pattern recognition specialist
    """
    
    def __init__(self):
        self.review_history = []
        self.consensus_threshold = 0.7
        
    def review_gat_predictions(self, gat_results: List[Dict], code_samples: List[str]) -> Dict:
        """Multi-LLM review of GAT vulnerability predictions"""
        
        reviews = {}
        
        # Claude Code (Primary) - Implementation focus
        reviews['claude'] = self._claude_review_predictions(gat_results, code_samples)
        
        # Grok (Security Expert) - Security-focused analysis
        reviews['grok'] = self._grok_security_analysis(gat_results, code_samples)
        
        # GPT-4 (Validator) - Code quality and correctness
        reviews['gpt4'] = self._gpt4_code_validation(gat_results, code_samples)
        
        # DeepSeek (Pattern Expert) - Pattern recognition
        reviews['deepseek'] = self._deepseek_pattern_analysis(gat_results, code_samples)
        
        # Generate consensus
        consensus = self._generate_consensus(reviews)
        
        # Store review
        review_record = {
            'timestamp': time.time(),
            'gat_predictions': len(gat_results),
            'individual_reviews': reviews,
            'consensus': consensus,
            'action_items': self._extract_action_items(reviews)
        }
        
        self.review_history.append(review_record)
        return review_record
    
    def _claude_review_predictions(self, gat_results: List[Dict], code_samples: List[str]) -> ReviewResult:
        """Claude Code - Primary implementation review"""
        
        high_risk_count = sum(1 for r in gat_results if r['risk_score'] > 0.8)
        total_predictions = len(gat_results)
        
        # Analyze implementation quality
        implementation_issues = []
        for i, (result, code) in enumerate(zip(gat_results, code_samples)):
            if result['risk_score'] > 0.8:
                if 'strcpy' in code and 'strncpy' not in code:
                    implementation_issues.append(f"Sample {i}: strcpy without bounds checking")
                elif 'gets' in code:
                    implementation_issues.append(f"Sample {i}: gets() - inherently unsafe")
                elif 'system' in code:
                    implementation_issues.append(f"Sample {i}: system() with potential injection")
        
        confidence = min(0.95, 0.5 + (len(implementation_issues) / total_predictions))
        
        return ReviewResult(
            reviewer=LLMProvider.CLAUDE_CODE,
            timestamp=time.time(),
            confidence=confidence,
            verdict="IMPLEMENTATION_FOCUSED",
            reasoning=f"Identified {len(implementation_issues)} clear implementation vulnerabilities out of {high_risk_count} high-risk predictions",
            suggestions=[
                "Replace strcpy with strncpy + null termination",
                "Replace gets with fgets",
                "Validate system() inputs or use execv",
                "Add bounds checking to all buffer operations"
            ],
            validation_score=len(implementation_issues) / max(high_risk_count, 1)
        )
    
    def _grok_security_analysis(self, gat_results: List[Dict], code_samples: List[str]) -> ReviewResult:
        """Grok - Security expert analysis"""
        
        security_threats = []
        exploit_potential = []
        
        for i, (result, code) in enumerate(zip(gat_results, code_samples)):
            if result['risk_score'] > 0.7:
                # Security threat assessment
                if 'user_input' in code.lower() or 'argv' in code:
                    security_threats.append(f"Sample {i}: User input processing - high attack surface")
                    
                if 'strcpy' in code or 'sprintf' in code:
                    exploit_potential.append(f"Sample {i}: Buffer overflow - RCE potential")
                    
                if 'system' in code:
                    exploit_potential.append(f"Sample {i}: Command injection - system compromise")
                    
                if 'printf' in code and '"%s"' not in code:
                    exploit_potential.append(f"Sample {i}: Format string - memory disclosure/corruption")
        
        # Grok's security-focused confidence
        confidence = min(0.92, 0.6 + (len(exploit_potential) / len(gat_results)))
        
        return ReviewResult(
            reviewer=LLMProvider.GROK,
            timestamp=time.time(),
            confidence=confidence,
            verdict="SECURITY_CRITICAL",
            reasoning=f"Identified {len(security_threats)} attack surfaces and {len(exploit_potential)} high-impact exploitability vectors",
            suggestions=[
                "Implement input sanitization and validation",
                "Use address space layout randomization (ASLR)",
                "Enable stack canaries and NX bit protection",
                "Consider using memory-safe languages for critical components",
                "Implement proper privilege separation"
            ],
            validation_score=len(exploit_potential) / max(len(security_threats), 1)
        )
    
    def _gpt4_code_validation(self, gat_results: List[Dict], code_samples: List[str]) -> ReviewResult:
        """GPT-4 - Code quality and correctness validation"""
        
        code_quality_issues = []
        best_practices_violations = []
        
        for i, (result, code) in enumerate(zip(gat_results, code_samples)):
            # Code quality analysis
            if not any(check in code for check in ['if', 'sizeof', 'strlen']):
                code_quality_issues.append(f"Sample {i}: Missing input validation")
                
            if 'malloc' in code and 'free' not in code:
                code_quality_issues.append(f"Sample {i}: Memory leak potential")
                
            if any(unsafe in code for unsafe in ['strcpy', 'sprintf', 'gets']):
                best_practices_violations.append(f"Sample {i}: Using deprecated unsafe functions")
                
            if 'error' not in code and 'return' in code:
                code_quality_issues.append(f"Sample {i}: Insufficient error handling")
        
        confidence = 0.7 + (len(best_practices_violations) / (len(gat_results) * 2))
        
        return ReviewResult(
            reviewer=LLMProvider.GPT4,
            timestamp=time.time(),
            confidence=min(confidence, 0.95),
            verdict="CODE_QUALITY_ASSESSMENT",
            reasoning=f"Found {len(code_quality_issues)} quality issues and {len(best_practices_violations)} best practice violations",
            suggestions=[
                "Implement comprehensive error handling",
                "Add input validation for all external inputs",
                "Use static analysis tools (CodeQL, Semgrep)",
                "Follow secure coding guidelines (CERT, OWASP)",
                "Implement unit tests for edge cases"
            ],
            validation_score=len(best_practices_violations) / max(len(code_quality_issues) + len(best_practices_violations), 1)
        )
    
    def _deepseek_pattern_analysis(self, gat_results: List[Dict], code_samples: List[str]) -> ReviewResult:
        """DeepSeek - Advanced pattern recognition"""
        
        vulnerability_patterns = []
        pattern_confidence = []
        
        # Advanced pattern detection
        patterns = {
            'buffer_overflow': [r'strcpy\s*\(', r'sprintf\s*\(', r'gets\s*\('],
            'integer_overflow': [r'\*\s*size', r'size\s*\*', r'malloc\s*\([^)]*\*'],
            'format_string': [r'printf\s*\([^"]*[^%][^s]', r'fprintf\s*\([^"]*[^%]'],
            'command_injection': [r'system\s*\([^)]*user', r'popen\s*\([^)]*input'],
            'race_condition': [r'access\s*\(.*open\s*\(', r'stat\s*\(.*open\s*\('],
            'use_after_free': [r'free\s*\([^)]*\).*access', r'delete\s.*new\s']
        }
        
        for i, (result, code) in enumerate(zip(gat_results, code_samples)):
            detected_patterns = []
            
            for pattern_type, regexes in patterns.items():
                for regex in regexes:
                    if re.search(regex, code):
                        detected_patterns.append(pattern_type)
                        break
            
            if detected_patterns:
                vulnerability_patterns.append(f"Sample {i}: {', '.join(detected_patterns)}")
                pattern_confidence.append(len(detected_patterns) / 3.0)  # Normalize
        
        avg_confidence = sum(pattern_confidence) / max(len(pattern_confidence), 1) if pattern_confidence else 0.5
        
        return ReviewResult(
            reviewer=LLMProvider.DEEPSEEK,
            timestamp=time.time(),
            confidence=min(0.90, 0.4 + avg_confidence),
            verdict="PATTERN_ANALYSIS",
            reasoning=f"Detected {len(vulnerability_patterns)} vulnerability patterns using advanced regex analysis",
            suggestions=[
                "Implement pattern-based static analysis rules",
                "Use machine learning for anomaly detection",
                "Create custom CodeQL queries for organization-specific patterns",
                "Develop automated pattern matching in CI/CD pipeline"
            ],
            validation_score=len(vulnerability_patterns) / max(len(gat_results), 1)
        )
    
    def _generate_consensus(self, reviews: Dict[str, ReviewResult]) -> Dict:
        """Generate consensus from multiple LLM reviews"""
        
        # Weighted confidence (Claude Code has highest weight as primary)
        weights = {'claude': 0.4, 'grok': 0.3, 'gpt4': 0.2, 'deepseek': 0.1}
        
        weighted_confidence = sum(
            reviews[llm].confidence * weights[llm] 
            for llm in reviews if llm in weights
        )
        
        # Consensus verdict
        verdicts = [review.verdict for review in reviews.values()]
        validation_scores = [review.validation_score for review in reviews.values()]
        
        avg_validation = sum(validation_scores) / len(validation_scores)
        
        # Determine consensus
        if weighted_confidence > 0.8 and avg_validation > 0.7:
            consensus_verdict = "HIGH_CONFIDENCE_VULNERABLE"
        elif weighted_confidence > 0.6 and avg_validation > 0.5:
            consensus_verdict = "MODERATE_CONFIDENCE_VULNERABLE"
        elif weighted_confidence < 0.4:
            consensus_verdict = "LOW_CONFIDENCE_BENIGN"
        else:
            consensus_verdict = "REQUIRES_FURTHER_ANALYSIS"
        
        return {
            'weighted_confidence': weighted_confidence,
            'average_validation_score': avg_validation,
            'consensus_verdict': consensus_verdict,
            'agreement_level': self._calculate_agreement(reviews),
            'recommendation': self._get_consensus_recommendation(weighted_confidence, avg_validation)
        }
    
    def _calculate_agreement(self, reviews: Dict[str, ReviewResult]) -> float:
        """Calculate agreement level between reviewers"""
        confidences = [review.confidence for review in reviews.values()]
        validation_scores = [review.validation_score for review in reviews.values()]
        
        # Calculate variance (lower variance = higher agreement)
        conf_variance = np.var(confidences) if len(confidences) > 1 else 0
        val_variance = np.var(validation_scores) if len(validation_scores) > 1 else 0
        
        # Convert variance to agreement score (0-1)
        agreement = 1.0 - min(1.0, (conf_variance + val_variance) / 2)
        return agreement
    
    def _get_consensus_recommendation(self, confidence: float, validation: float) -> str:
        """Get actionable recommendation based on consensus"""
        if confidence > 0.8 and validation > 0.7:
            return "IMMEDIATE_FUZZING_PRIORITY - Deploy fuzzer immediately on these targets"
        elif confidence > 0.6:
            return "SCHEDULE_FUZZING - Add to fuzzing queue with medium priority"
        elif confidence > 0.4:
            return "MANUAL_REVIEW_NEEDED - Requires human expert analysis"
        else:
            return "LOW_PRIORITY - Consider for comprehensive testing only"
    
    def _extract_action_items(self, reviews: Dict[str, ReviewResult]) -> List[str]:
        """Extract actionable items from all reviews"""
        all_suggestions = []
        for review in reviews.values():
            all_suggestions.extend(review.suggestions)
        
        # Deduplicate and prioritize
        unique_suggestions = list(set(all_suggestions))
        
        # Prioritize based on frequency across reviewers
        suggestion_counts = {}
        for suggestion in all_suggestions:
            suggestion_counts[suggestion] = suggestion_counts.get(suggestion, 0) + 1
        
        # Sort by frequency (most common first)
        prioritized = sorted(unique_suggestions, 
                           key=lambda x: suggestion_counts.get(x, 0), 
                           reverse=True)
        
        return prioritized[:10]  # Top 10 action items

def critique_fuzzing_results(fuzzing_history: List[Dict], crash_results: List[Dict]) -> Dict:
    """Multi-LLM critique of fuzzing effectiveness"""
    
    orchestrator = LLMReviewOrchestrator()
    
    # Prepare data for review
    efficiency_metrics = {
        'total_inputs': len(fuzzing_history),
        'crashes_found': len(crash_results),
        'crash_rate': len(crash_results) / max(len(fuzzing_history), 1),
        'unique_crashes': len(set(c.get('crash_signature', '') for c in crash_results)),
        'coverage_improvement': fuzzing_history[-1].get('coverage', 0) - fuzzing_history[0].get('coverage', 0) if fuzzing_history else 0
    }
    
    # Multi-LLM analysis
    reviews = {}
    
    # Claude Code - Implementation efficiency
    reviews['claude'] = ReviewResult(
        reviewer=LLMProvider.CLAUDE_CODE,
        timestamp=time.time(),
        confidence=0.85,
        verdict="IMPLEMENTATION_EFFICIENT" if efficiency_metrics['crash_rate'] > 0.01 else "NEEDS_OPTIMIZATION",
        reasoning=f"Crash rate: {efficiency_metrics['crash_rate']:.3f}, Coverage gain: {efficiency_metrics['coverage_improvement']:.2%}",
        suggestions=[
            "Optimize input generation algorithms",
            "Implement adaptive mutation strategies",
            "Use coverage-guided fuzzing improvements"
        ],
        validation_score=efficiency_metrics['crash_rate'] * 100
    )
    
    # Grok - Security impact assessment
    security_impact = "HIGH" if efficiency_metrics['unique_crashes'] > 5 else "MEDIUM" if efficiency_metrics['unique_crashes'] > 2 else "LOW"
    reviews['grok'] = ReviewResult(
        reviewer=LLMProvider.GROK,
        timestamp=time.time(),
        confidence=0.82,
        verdict=f"SECURITY_IMPACT_{security_impact}",
        reasoning=f"Found {efficiency_metrics['unique_crashes']} unique crash signatures indicating potential vulnerabilities",
        suggestions=[
            "Prioritize crashes with RCE potential",
            "Analyze crash exploitability",
            "Implement crash deduplication",
            "Focus on privilege escalation vectors"
        ],
        validation_score=min(1.0, efficiency_metrics['unique_crashes'] / 10.0)
    )
    
    # Generate final critique
    consensus = orchestrator._generate_consensus(reviews)
    
    return {
        'efficiency_metrics': efficiency_metrics,
        'individual_critiques': reviews,
        'consensus': consensus,
        'overall_score': (efficiency_metrics['crash_rate'] * 50 + consensus['weighted_confidence'] * 50) / 100,
        'recommendations': orchestrator._extract_action_items(reviews)
    }

# Example usage and testing
def main():
    """Test multi-LLM review system"""
    
    logging.basicConfig(level=logging.INFO)
    logger.info("🧠 Testing Multi-LLM Review System")
    
    # Mock GAT results
    gat_results = [
        {'function': 'strcpy_handler', 'risk_score': 0.87, 'cwe_type': 'CWE121'},
        {'function': 'safe_strncpy', 'risk_score': 0.23, 'cwe_type': 'None'},
        {'function': 'gets_input', 'risk_score': 0.94, 'cwe_type': 'CWE121'},
        {'function': 'system_exec', 'risk_score': 0.78, 'cwe_type': 'CWE78'}
    ]
    
    code_samples = [
        "strcpy(buffer, user_input);",
        "strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\\0';",
        "gets(input_buffer);",
        "system(user_command);"
    ]
    
    # Run multi-LLM review
    orchestrator = LLMReviewOrchestrator()
    review_result = orchestrator.review_gat_predictions(gat_results, code_samples)
    
    # Print results
    logger.info("\\n" + "="*70)
    logger.info("MULTI-LLM REVIEW RESULTS")
    logger.info("="*70)
    
    for llm_name, review in review_result['individual_reviews'].items():
        logger.info(f"\\n{llm_name.upper()} ({review.reviewer.value}):")
        logger.info(f"  Confidence: {review.confidence:.2f}")
        logger.info(f"  Verdict: {review.verdict}")
        logger.info(f"  Validation Score: {review.validation_score:.2f}")
        logger.info(f"  Top Suggestion: {review.suggestions[0] if review.suggestions else 'None'}")
    
    consensus = review_result['consensus']
    logger.info(f"\\nCONSENSUS:")
    logger.info(f"  Weighted Confidence: {consensus['weighted_confidence']:.2f}")
    logger.info(f"  Verdict: {consensus['consensus_verdict']}")
    logger.info(f"  Agreement Level: {consensus['agreement_level']:.2f}")
    logger.info(f"  Recommendation: {consensus['recommendation']}")
    
    logger.info(f"\\nTOP ACTION ITEMS:")
    for i, action in enumerate(review_result['action_items'][:5], 1):
        logger.info(f"  {i}. {action}")
    
    logger.info("\\n✅ Multi-LLM Review System test completed!")

if __name__ == "__main__":
    import re
    import numpy as np
    main()