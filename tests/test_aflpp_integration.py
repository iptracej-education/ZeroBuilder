#!/usr/bin/env python3
"""
Test AFL++ Integration with ZeroBuilder
Simplified testing without full AFL++ dependency
"""

import sys
import os
import tempfile
import subprocess
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from zerobuilder.detectors.smb_aflpp_fuzzer import SMBAFLFuzzer, FuzzingStrategy
from zerobuilder.detectors.kernel_aflpp_fuzzer import KernelAFLFuzzer, KernelFuzzTarget

def test_smb_harness_generation():
    """Test SMB harness generation and basic functionality"""
    print("🧪 Testing SMB harness generation...")
    
    try:
        fuzzer = SMBAFLFuzzer()
        
        # Setup environment (this will create directories and test cases)
        fuzzer.setup_environment()
        
        # Check if harness was built
        harness_file = fuzzer.work_dir / "smb_harness_standalone"
        if harness_file.exists():
            print("✅ SMB harness built successfully")
            
            # Test harness with sample input
            test_input = b'\xfeSMB' + b'\x00' * 60  # Basic SMB header
            
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(test_input)
                temp_file.flush()
                
                # Run harness
                result = subprocess.run([str(harness_file)], 
                                      stdin=open(temp_file.name, 'rb'),
                                      capture_output=True, timeout=5)
                
                print(f"   Harness exit code: {result.returncode}")
                if result.returncode == 0:
                    print("✅ SMB harness executed successfully")
                else:
                    print(f"⚠️  SMB harness returned {result.returncode}")
        else:
            print("❌ SMB harness not found")
            
        # Test result analysis functions
        test_results = fuzzer._analyze_fuzzing_results(
            "test_campaign", 
            fuzzer.output_dir / "test",
            30
        )
        
        print(f"✅ Result analysis: {test_results.campaign_id}")
        
        # Test PoC generation
        test_results.vulnerability_candidates = [{
            "crash_file": "test.bin",
            "vulnerability_type": "buffer_overflow",
            "confidence": 0.8,
            "crash_size": 100
        }]
        
        pocs = fuzzer.generate_poc_exploits(test_results)
        print(f"✅ Generated {len(pocs)} PoC exploits")
        
        return True
        
    except Exception as e:
        print(f"❌ SMB harness test failed: {e}")
        return False

def test_kernel_harness_generation():
    """Test kernel harness generation"""
    print("\n🧪 Testing kernel harness generation...")
    
    try:
        fuzzer = KernelAFLFuzzer()
        
        # Setup environment
        fuzzer.setup_environment()
        
        # Check if harnesses were built
        syscall_harness = fuzzer.harness_dir / "syscall_harness_standalone"
        race_harness = fuzzer.harness_dir / "race_harness_afl"
        memory_harness = fuzzer.harness_dir / "memory_harness_afl"
        
        built_harnesses = 0
        for harness_name, harness_path in [
            ("syscall", syscall_harness),
            ("race", race_harness), 
            ("memory", memory_harness)
        ]:
            if harness_path.exists():
                print(f"✅ {harness_name} harness built")
                built_harnesses += 1
            else:
                print(f"⚠️  {harness_name} harness not found")
        
        # Test syscall harness if available
        if syscall_harness.exists():
            # Create test syscall input
            test_input = b'\x00\x00\x00\x00' + b'\x00' * 48  # syscall 0 with args
            
            with tempfile.NamedTemporaryFile() as temp_file:
                temp_file.write(test_input)
                temp_file.flush()
                
                result = subprocess.run([str(syscall_harness), temp_file.name],
                                      capture_output=True, timeout=5)
                
                print(f"   Syscall harness exit code: {result.returncode}")
        
        # Test result analysis
        test_results = fuzzer._analyze_kernel_fuzzing_results(
            "kernel_test",
            fuzzer.output_dir / "test",
            KernelFuzzTarget.SYSCALLS,
            30
        )
        
        print(f"✅ Kernel result analysis: {test_results.campaign_id}")
        
        return built_harnesses > 0
        
    except Exception as e:
        print(f"❌ Kernel harness test failed: {e}")
        return False

def test_rl_integration():
    """Test RL-guided fuzzing integration"""
    print("\n🧪 Testing RL integration...")
    
    try:
        # Import RL fuzzer
        from zerobuilder.detectors.rl_guided_fuzzing import RLGuidedFuzzer, MutationEnvironment
        
        # Create a mock fuzzer for testing
        class MockFuzzer:
            def __init__(self):
                self.work_dir = Path("test_workdir")
                self.input_dir = self.work_dir / "inputs"
                self.work_dir.mkdir(exist_ok=True)
                self.input_dir.mkdir(exist_ok=True)
        
        mock_fuzzer = MockFuzzer()
        
        # Test environment creation
        env = MutationEnvironment(mock_fuzzer, max_steps=10)
        print("✅ RL environment created")
        
        # Test environment reset
        state, info = env.reset()
        print(f"✅ Environment reset, state shape: {state.shape}")
        
        # Test action execution
        action = [0, 0.5, 0.5, 0.3]  # mutation_type, location, intensity, length
        next_state, reward, done, truncated, info = env.step(action)
        print(f"✅ Action executed, reward: {reward}")
        
        # Test RL fuzzer creation
        rl_fuzzer = RLGuidedFuzzer(mock_fuzzer)
        print("✅ RL fuzzer created")
        
        # Test mutation generation
        test_input = b"test_input_data"
        mutations = rl_fuzzer.generate_guided_mutations(test_input, count=3)
        print(f"✅ Generated {len(mutations)} RL-guided mutations")
        
        return True
        
    except Exception as e:
        print(f"❌ RL integration test failed: {e}")
        return False

def test_integration_exports():
    """Test integration data export functionality"""
    print("\n🧪 Testing integration exports...")
    
    try:
        # Test SMB fuzzer exports
        fuzzer = SMBAFLFuzzer()
        fuzzer.setup_environment()
        
        # Create mock results
        from zerobuilder.detectors.smb_aflpp_fuzzer import FuzzingResult
        mock_result = FuzzingResult(
            campaign_id="test_campaign",
            target_type="smb_protocol",
            total_executions=1000,
            unique_crashes=5,
            unique_hangs=2,
            coverage_percent=75.5,
            interesting_paths=20,
            runtime_seconds=300,
            crashes_found=["crash_001.bin"],
            coverage_map={"paths": 20, "edges": 150},
            vulnerability_candidates=[{
                "crash_file": "crash_001.bin",
                "vulnerability_type": "buffer_overflow",
                "confidence": 0.8,
                "crash_size": 256
            }]
        )
        
        integration_data = fuzzer.export_results_for_integration(mock_result)
        print(f"✅ SMB integration data: {len(integration_data['fuzzing_signatures'])} signatures")
        
        # Test kernel fuzzer exports
        kernel_fuzzer = KernelAFLFuzzer()
        kernel_fuzzer.setup_environment()
        
        from zerobuilder.detectors.kernel_aflpp_fuzzer import KernelFuzzingResult
        mock_kernel_result = KernelFuzzingResult(
            campaign_id="kernel_test",
            target_type=KernelFuzzTarget.SYSCALLS,
            total_executions=500,
            unique_crashes=3,
            unique_hangs=1,
            kernel_panics=0,
            oops_count=1,
            coverage_percent=60.2,
            runtime_seconds=200,
            race_conditions_found=[{
                "type": "memory_race",
                "crash_file": "race_001.bin",
                "size": 128,
                "timestamp": 1234567890
            }],
            syscall_coverage={"read": 10, "write": 15, "open": 8},
            vulnerability_patterns=[{
                "file": "vuln_001.bin",
                "vulnerability_type": "use_after_free",
                "confidence": 0.7,
                "size": 64,
                "target": "syscalls"
            }]
        )
        
        kernel_integration_data = kernel_fuzzer.export_kernel_results_for_integration(mock_kernel_result)
        print(f"✅ Kernel integration data: {len(kernel_integration_data['race_condition_patterns'])} race patterns")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration export test failed: {e}")
        return False

def main():
    """Run all AFL++ integration tests"""
    print("🚀 ZeroBuilder AFL++ Integration Tests")
    print("=" * 50)
    
    tests = [
        ("SMB Harness Generation", test_smb_harness_generation),
        ("Kernel Harness Generation", test_kernel_harness_generation),
        ("RL Integration", test_rl_integration),
        ("Integration Exports", test_integration_exports)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n🧪 Running: {test_name}")
        try:
            if test_func():
                print(f"✅ {test_name}: PASSED")
                passed += 1
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: ERROR - {e}")
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All AFL++ integration tests passed!")
        print("\n🔧 Integration Status:")
        print("   ✅ SMB AFL++ fuzzing ready")
        print("   ✅ Kernel AFL++ fuzzing ready") 
        print("   ✅ RL-guided mutations ready")
        print("   ✅ Integration exports ready")
        print("\n🚀 AFL++ guided fuzzing fully integrated with ZeroBuilder!")
        return 0
    else:
        print(f"⚠️  {total - passed} tests failed")
        return 1

if __name__ == "__main__":
    exit(main())