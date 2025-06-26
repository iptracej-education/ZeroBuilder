
import sys
import os
sys.path.append('src')

try:
    # Test basic imports
    from zerobuilder.detectors.smb_protocol_analyzer import SMBHybridDetector
    print("✅ SMB Hybrid Detector import successful")
    
    # Test test case loading
    if os.path.exists('test_cases/smb_new_testcases.c'):
        with open('test_cases/smb_new_testcases.c', 'r') as f:
            content = f.read()
        print(f"✅ Test cases loaded: {len(content)} characters")
    
    print("🎉 Basic functionality test PASSED")
    
except Exception as e:
    print(f"❌ Test failed: {e}")
    sys.exit(1)
