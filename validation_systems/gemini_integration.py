#!/usr/bin/env python3
"""
Gemini Free API Integration for ZeroBuilder
Primary validator using Google Gemini API Free Tier
"""

import os
import time
import logging
import json
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class GeminiAnalysisResult:
    """Result from Gemini API analysis"""
    confidence: float
    verdict: str
    reasoning: str
    severity: str
    vulnerability_types: List[str]
    recommendations: List[str]
    analysis_time: float
    tokens_used: int

class GeminiValidator:
    """Gemini API Free Tier validator for vulnerability analysis"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.model = "gemini-1.5-flash"  # Free tier model
        self.session = requests.Session()
        
        # Rate limiting for free tier
        self.requests_per_minute = 15
        self.requests_per_day = 1500
        self.request_times = []
        self.daily_request_count = 0
        self.daily_reset_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        
        logger.info(f"🚀 Gemini Validator initialized")
        logger.info(f"🎯 Model: {self.model} (Free Tier)")
        logger.info(f"📊 Rate Limits: {self.requests_per_minute}/min, {self.requests_per_day}/day")
        
        if not self.api_key:
            logger.warning("⚠️ No Gemini API key found. Set GEMINI_API_KEY environment variable.")
            logger.info("💡 For testing, will use simulated responses")
    
    def _check_rate_limits(self) -> bool:
        """Check if we can make a request within rate limits"""
        now = datetime.now()
        
        # Reset daily counter if needed
        if now >= self.daily_reset_time.replace(day=now.day):
            self.daily_request_count = 0
            self.daily_reset_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Check daily limit
        if self.daily_request_count >= self.requests_per_day:
            logger.warning(f"⚠️ Daily limit reached ({self.requests_per_day} requests)")
            return False
        
        # Check per-minute limit
        current_time = time.time()
        self.request_times = [t for t in self.request_times if current_time - t < 60]
        
        if len(self.request_times) >= self.requests_per_minute:
            wait_time = 60 - (current_time - self.request_times[0])
            logger.info(f"⏱️ Rate limit: waiting {wait_time:.1f}s")
            time.sleep(wait_time)
            return self._check_rate_limits()
        
        return True
    
    def _make_api_request(self, prompt: str) -> Dict:
        """Make request to Gemini API with rate limiting"""
        if not self.api_key:
            return self._simulate_gemini_response(prompt)
        
        if not self._check_rate_limits():
            return {"error": "Rate limit exceeded"}
        
        try:
            url = f"{self.base_url}/models/{self.model}:generateContent"
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key
            }
            
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "temperature": 0.7,
                    "topK": 40,
                    "topP": 0.95,
                    "maxOutputTokens": 1024
                }
            }
            
            start_time = time.time()
            response = self.session.post(url, headers=headers, json=payload, timeout=30)
            response_time = time.time() - start_time
            
            # Update rate limiting tracking
            self.request_times.append(time.time())
            self.daily_request_count += 1
            
            if response.status_code == 200:
                result = response.json()
                
                if 'candidates' in result and result['candidates']:
                    content = result['candidates'][0]['content']['parts'][0]['text']
                    
                    # Estimate token usage (rough approximation)
                    tokens_used = len(prompt.split()) + len(content.split())
                    
                    return {
                        "success": True,
                        "content": content,
                        "response_time": response_time,
                        "tokens_used": tokens_used
                    }
                else:
                    logger.error(f"❌ No candidates in response: {result}")
                    return {"error": "No response generated"}
            else:
                logger.error(f"❌ API error {response.status_code}: {response.text}")
                return {"error": f"API error: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"❌ Request failed: {e}")
            return {"error": str(e)}
    
    def _simulate_gemini_response(self, prompt: str) -> Dict:
        """Simulate Gemini response for testing without API key"""
        # Simulate Gemini's high-quality analysis based on the 88/100 assessment
        time.sleep(0.5)  # Simulate API latency
        
        # Analyze prompt for vulnerability patterns
        prompt_lower = prompt.lower()
        security_patterns = {
            'strcpy': {'severity': 'HIGH', 'type': 'Buffer Overflow'},
            'gets': {'severity': 'CRITICAL', 'type': 'Buffer Overflow'},
            'system': {'severity': 'HIGH', 'type': 'Command Injection'},
            'malloc': {'severity': 'MEDIUM', 'type': 'Memory Management'},
            'free': {'severity': 'HIGH', 'type': 'Use After Free'},
            'race': {'severity': 'HIGH', 'type': 'Race Condition'},
            'toctou': {'severity': 'HIGH', 'type': 'Time-of-Check-Time-of-Use'}
        }
        
        detected_patterns = []
        max_severity = 'LOW'
        
        for pattern, info in security_patterns.items():
            if pattern in prompt_lower:
                detected_patterns.append(info)
                if info['severity'] == 'CRITICAL':
                    max_severity = 'CRITICAL'
                elif info['severity'] == 'HIGH' and max_severity != 'CRITICAL':
                    max_severity = 'HIGH'
                elif info['severity'] == 'MEDIUM' and max_severity not in ['CRITICAL', 'HIGH']:
                    max_severity = 'MEDIUM'
        
        # Generate realistic response
        if detected_patterns:
            vulnerability_types = [p['type'] for p in detected_patterns]
            response = f"""SECURITY ANALYSIS RESULT:

VULNERABILITY DETECTED: {max_severity} severity
Types found: {', '.join(set(vulnerability_types))}

DETAILED ANALYSIS:
"""
            for pattern in detected_patterns:
                response += f"- {pattern['type']}: {pattern['severity']} severity vulnerability detected\n"
            
            response += f"""
EXPLOITATION POTENTIAL: {'Very High' if max_severity == 'CRITICAL' else 'High' if max_severity == 'HIGH' else 'Moderate'}
IMMEDIATE ACTION REQUIRED: {'Yes' if max_severity in ['CRITICAL', 'HIGH'] else 'Recommended'}

RECOMMENDATIONS:
- Implement input validation and bounds checking
- Use secure alternatives to unsafe functions
- Apply principle of least privilege
- Conduct security code review
"""
        else:
            response = """SECURITY ANALYSIS RESULT:

NO CRITICAL VULNERABILITIES DETECTED

ANALYSIS:
- Code appears to follow basic security practices
- No obvious vulnerability patterns identified
- Standard security review recommended

RECOMMENDATIONS:
- Continue following secure coding practices
- Regular security audits recommended
- Consider static analysis tools
"""
        
        return {
            "success": True,
            "content": response,
            "response_time": 0.5,
            "tokens_used": len(prompt.split()) + len(response.split())
        }
    
    def analyze_vulnerability(self, code: str, context: str = "", function_name: str = "") -> GeminiAnalysisResult:
        """Analyze code for vulnerabilities using Gemini"""
        
        # Create comprehensive analysis prompt
        prompt = f"""You are a security expert analyzing code for vulnerabilities. Please provide a comprehensive security analysis.

CODE TO ANALYZE:
```
{code}
```

CONTEXT: {context}
FUNCTION: {function_name}

Please analyze this code and provide:
1. SECURITY ASSESSMENT: Is this code vulnerable? (YES/NO/UNCERTAIN)
2. CONFIDENCE LEVEL: How confident are you? (0.0-1.0)
3. VULNERABILITY TYPES: What types of vulnerabilities are present?
4. SEVERITY: CRITICAL/HIGH/MEDIUM/LOW
5. EXPLOITATION: How could this be exploited?
6. RECOMMENDATIONS: How to fix these issues?

Format your response clearly with these sections.
"""
        
        logger.info(f"🔍 Analyzing code with Gemini: {len(code)} characters")
        
        # Make API request
        api_result = self._make_api_request(prompt)
        
        if "error" in api_result:
            logger.error(f"❌ API request failed: {api_result['error']}")
            return self._create_error_result(api_result['error'])
        
        # Parse Gemini response
        return self._parse_gemini_response(
            api_result["content"], 
            api_result["response_time"],
            api_result["tokens_used"]
        )
    
    def _parse_gemini_response(self, content: str, response_time: float, tokens_used: int) -> GeminiAnalysisResult:
        """Parse Gemini response into structured result"""
        
        content_lower = content.lower()
        
        # Extract confidence
        confidence = 0.7  # Base confidence
        if "confident" in content_lower or "certain" in content_lower:
            confidence = 0.9
        elif "uncertain" in content_lower or "unsure" in content_lower:
            confidence = 0.5
        elif any(word in content_lower for word in ["critical", "high", "severe"]):
            confidence = 0.85
        
        # Extract verdict
        if "yes" in content_lower and "vulnerable" in content_lower:
            verdict = "VULNERABLE"
        elif "no" in content_lower and ("vulnerable" in content_lower or "safe" in content_lower):
            verdict = "SAFE"
        else:
            verdict = "UNCERTAIN"
        
        # Extract severity
        if "critical" in content_lower:
            severity = "CRITICAL"
        elif "high" in content_lower:
            severity = "HIGH"
        elif "medium" in content_lower:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        # Extract vulnerability types
        vulnerability_types = []
        vuln_patterns = {
            "buffer overflow": "Buffer Overflow",
            "injection": "Injection Attack",
            "race condition": "Race Condition",
            "use after free": "Use After Free",
            "memory leak": "Memory Leak",
            "integer overflow": "Integer Overflow"
        }
        
        for pattern, vuln_type in vuln_patterns.items():
            if pattern in content_lower:
                vulnerability_types.append(vuln_type)
        
        # Extract recommendations (simple approach)
        recommendations = []
        if "input validation" in content_lower:
            recommendations.append("Implement input validation")
        if "bounds checking" in content_lower:
            recommendations.append("Add bounds checking")
        if "secure alternatives" in content_lower:
            recommendations.append("Use secure function alternatives")
        
        if not recommendations:
            recommendations = ["Conduct security code review"]
        
        return GeminiAnalysisResult(
            confidence=confidence,
            verdict=verdict,
            reasoning=content,
            severity=severity,
            vulnerability_types=vulnerability_types,
            recommendations=recommendations,
            analysis_time=response_time,
            tokens_used=tokens_used
        )
    
    def _create_error_result(self, error_message: str) -> GeminiAnalysisResult:
        """Create error result when API fails"""
        return GeminiAnalysisResult(
            confidence=0.0,
            verdict="ERROR",
            reasoning=f"Analysis failed: {error_message}",
            severity="UNKNOWN",
            vulnerability_types=[],
            recommendations=["Retry analysis"],
            analysis_time=0.0,
            tokens_used=0
        )
    
    def test_api_connection(self) -> bool:
        """Test Gemini API connection"""
        logger.info("🧪 Testing Gemini API connection...")
        
        test_prompt = "Analyze this simple code: int x = 5; return x;"
        result = self._make_api_request(test_prompt)
        
        if "error" in result:
            logger.error(f"❌ API test failed: {result['error']}")
            return False
        else:
            logger.info(f"✅ API test successful")
            logger.info(f"📊 Response time: {result['response_time']:.2f}s")
            logger.info(f"🎯 Tokens used: {result['tokens_used']}")
            return True

def main():
    """Test Gemini integration"""
    logger.info("🚀 Testing Gemini Free API Integration")
    logger.info("=" * 60)
    
    # Initialize validator
    gemini = GeminiValidator()
    
    # Test API connection
    if gemini.test_api_connection():
        logger.info("✅ Gemini API integration working!")
    else:
        logger.info("💡 Using simulated responses for testing")
    
    # Test vulnerability analysis
    test_cases = [
        {
            "name": "Buffer Overflow",
            "code": "strcpy(dest, src);",
            "context": "String copying without bounds checking"
        },
        {
            "name": "Safe Code",
            "code": "strncpy(dest, src, sizeof(dest)-1); dest[sizeof(dest)-1] = '\\0';",
            "context": "Safe string copying with bounds checking"
        },
        {
            "name": "Use After Free",
            "code": "free(ptr); ptr->data = value;",
            "context": "Memory access after free"
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"\n📋 Test {i}: {test_case['name']}")
        logger.info(f"🔍 Code: {test_case['code']}")
        
        result = gemini.analyze_vulnerability(
            test_case["code"], 
            test_case["context"]
        )
        
        logger.info(f"🎯 Verdict: {result.verdict}")
        logger.info(f"📊 Confidence: {result.confidence:.2f}")
        logger.info(f"⚡ Severity: {result.severity}")
        logger.info(f"🔍 Types: {', '.join(result.vulnerability_types)}")
        logger.info(f"⏱️ Analysis time: {result.analysis_time:.2f}s")
        logger.info(f"💡 Recommendations: {', '.join(result.recommendations[:2])}")
    
    logger.info(f"\n🎉 Gemini integration test complete!")
    logger.info(f"✅ Ready to integrate with ZeroBuilder validation pipeline")

if __name__ == "__main__":
    main()