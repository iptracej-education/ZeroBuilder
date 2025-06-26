"""
Test Enhanced Vulnerability Pattern Detection
"""

import logging
from src.vulnerability_patterns import VULNERABILITY_DB, VulnerabilityType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_vulnerability_patterns():
    """Test the vulnerability pattern database"""
    logger.info("🧪 Testing Vulnerability Pattern Database")
    
    # Test vulnerable function detection
    test_cases = [
        ("strcpy", ["unchecked_source", "user_input"]),
        ("strncpy", ["null_termination_check"]),
        ("malloc", ["missing_free"]),
        ("system", ["user_input", "shell_metacharacters"]),
        ("printf", ["user_controlled_format"]),
        ("gets", []),  # Always vulnerable
        ("safe_function", [])  # Unknown function
    ]
    
    logger.info("\n" + "="*60)
    logger.info("VULNERABILITY RISK ASSESSMENT RESULTS")
    logger.info("="*60)
    
    for func_name, context in test_cases:
        risk_score, vuln_type = VULNERABILITY_DB.get_vulnerability_risk(func_name, context)
        
        # Get mitigation suggestions
        suggestions = VULNERABILITY_DB.get_mitigation_suggestions(func_name)
        
        logger.info(f"\nFunction: {func_name}")
        logger.info(f"  Context: {context}")
        logger.info(f"  Risk Score: {risk_score:.2f}")
        logger.info(f"  Vulnerability Type: {vuln_type.value}")
        logger.info(f"  Risk Level: {'CRITICAL' if risk_score > 0.8 else 'HIGH' if risk_score > 0.6 else 'MEDIUM' if risk_score > 0.3 else 'LOW'}")
        
        if suggestions:
            logger.info(f"  Mitigations: {', '.join([s.safe_function for s in suggestions])}")
        else:
            logger.info("  Mitigations: None available")
    
    # Test code context analysis
    logger.info("\n" + "="*60)
    logger.info("CODE CONTEXT ANALYSIS RESULTS")
    logger.info("="*60)
    
    code_samples = [
        "strcpy(buffer, argv[1]);",  # Buffer overflow with user input
        "if (size < MAX_SIZE) strncpy(dest, src, size);",  # Bounds check
        "ptr = malloc(100); if (error) return -1;",  # Missing free
        "system(user_command);",  # Command injection
        "printf(\"%s\", message);",  # Safe format string
    ]
    
    for i, code in enumerate(code_samples, 1):
        context = VULNERABILITY_DB.analyze_code_context(code)
        logger.info(f"\nCode Sample {i}: {code}")
        logger.info(f"  Detected Context: {context}")
    
    logger.info("\n" + "="*60)
    logger.info("LIBRARY MITIGATION PATTERNS")
    logger.info("="*60)
    
    for lib_name, functions in VULNERABILITY_DB.library_mitigations.items():
        logger.info(f"\n{lib_name.upper()}:")
        logger.info(f"  Safe Functions: {', '.join(functions[:5])}{'...' if len(functions) > 5 else ''}")
    
    logger.info(f"\n✅ Database loaded: {len(VULNERABILITY_DB.vulnerable_patterns)} vulnerable patterns")
    logger.info(f"✅ Safe patterns: {len(VULNERABILITY_DB.safe_patterns)}")
    logger.info(f"✅ Mitigations: {len(VULNERABILITY_DB.mitigation_patterns)}")
    logger.info(f"✅ Library functions: {sum(len(funcs) for funcs in VULNERABILITY_DB.library_mitigations.values())}")

def demonstrate_signature_differences():
    """Demonstrate how different CWEs have different signatures"""
    logger.info("\n" + "="*60)
    logger.info("CWE SIGNATURE DIFFERENCES DEMONSTRATION")
    logger.info("="*60)
    
    # Simulate different vulnerability scenarios
    scenarios = [
        {
            "name": "Buffer Overflow (CWE121)",
            "functions": ["strcpy", "sprintf", "gets"],
            "context": ["unchecked_source", "user_input", "fixed_destination"]
        },
        {
            "name": "Use After Free (CWE416)", 
            "functions": ["malloc", "free", "access_after_free"],
            "context": ["already_freed", "missing_null_check"]
        },
        {
            "name": "Command Injection (CWE78)",
            "functions": ["system", "popen"],
            "context": ["user_input", "shell_metacharacters"]
        },
        {
            "name": "Safe Implementation",
            "functions": ["strncpy", "snprintf", "fgets"],
            "context": ["bounds_check", "null_check", "error_handling"]
        }
    ]
    
    for scenario in scenarios:
        logger.info(f"\n{scenario['name']}:")
        total_risk = 0
        vuln_types = set()
        
        for func in scenario['functions']:
            risk, vuln_type = VULNERABILITY_DB.get_vulnerability_risk(func, scenario['context'])
            total_risk += risk
            vuln_types.add(vuln_type.value)
            logger.info(f"  {func}: risk={risk:.2f}, type={vuln_type.value}")
        
        avg_risk = total_risk / len(scenario['functions'])
        logger.info(f"  OVERALL: avg_risk={avg_risk:.2f}, types={list(vuln_types)}")
        
        if avg_risk > 0.7:
            logger.info("  🚨 HIGH VULNERABILITY SIGNATURE DETECTED")
        elif avg_risk > 0.4:
            logger.info("  ⚠️  MEDIUM VULNERABILITY SIGNATURE")
        else:
            logger.info("  ✅ LOW RISK / SAFE SIGNATURE")

def main():
    """Test enhanced vulnerability detection concepts"""
    logger.info("🔬 Testing Enhanced Vulnerability Pattern Detection")
    
    try:
        test_vulnerability_patterns()
        demonstrate_signature_differences()
        
        logger.info("\n" + "="*60)
        logger.info("🎯 SUMMARY: Enhanced Pattern Detection Ready!")
        logger.info("📊 Key Improvements over Basic GAT:")
        logger.info("  ✅ Real vulnerability function detection (strcpy, malloc, etc.)")
        logger.info("  ✅ Context-aware risk assessment (user input, bounds checks)")  
        logger.info("  ✅ CWE-specific signature patterns")
        logger.info("  ✅ Mitigation pattern recognition")
        logger.info("  ✅ Library-specific safe alternatives")
        logger.info("="*60)
        
    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()