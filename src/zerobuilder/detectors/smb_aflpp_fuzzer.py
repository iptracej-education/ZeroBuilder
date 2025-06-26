#!/usr/bin/env python3
"""
SMB AFL++ Guided Fuzzing System
Real coverage-guided fuzzing for SMB protocol vulnerability discovery
"""

import os
import sys
import time
import subprocess
import tempfile
import threading
import signal
import json
import shutil
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import socket
import struct
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SMBCommand(Enum):
    """SMB commands for protocol message generation"""
    NEGOTIATE = 0x72
    SESSION_SETUP = 0x73
    TREE_CONNECT = 0x75
    CREATE = 0xA2
    CLOSE = 0x06
    READ = 0x2E
    WRITE = 0x2F
    LOGOFF = 0x74
    TREE_DISCONNECT = 0x71

class FuzzingStrategy(Enum):
    """AFL++ fuzzing strategies"""
    BASIC_COVERAGE = "basic"
    CMPLOG_GUIDED = "cmplog"
    REDQUEEN_MUTATOR = "redqueen"
    CUSTOM_MUTATOR = "custom"

@dataclass
class FuzzingResult:
    """Result of AFL++ fuzzing session"""
    campaign_id: str
    target_type: str
    total_executions: int
    unique_crashes: int
    unique_hangs: int
    coverage_percent: float
    interesting_paths: int
    runtime_seconds: int
    crashes_found: List[str]
    coverage_map: Dict[str, int]
    vulnerability_candidates: List[Dict[str, Any]]

@dataclass
class SMBMessage:
    """SMB protocol message structure"""
    command: SMBCommand
    flags: int
    message_id: int
    session_id: int
    tree_id: int
    payload: bytes
    
    def to_bytes(self) -> bytes:
        """Convert SMB message to wire format"""
        # SMB2 header (simplified)
        header = struct.pack('<4sHHIIQQQQ',
            b'\xfeSMB',  # Protocol identifier
            64,  # Header length
            0,   # Credit charge
            self.command.value,  # Command
            0,   # Flags
            self.message_id,     # Message ID
            0,   # Process ID
            self.tree_id,        # Tree ID
            self.session_id     # Session ID
        )
        return header + self.payload

class SMBAFLFuzzer:
    """AFL++ guided fuzzer for SMB protocol"""
    
    def __init__(self, afl_path: str = "/home/iptracej/Dev/ZeroBuilder/tools/AFLplusplus"):
        self.afl_path = Path(afl_path)
        self.afl_fuzz = self.afl_path / "afl-fuzz"
        self.afl_showmap = self.afl_path / "afl-showmap"
        self.afl_cc = self.afl_path / "afl-cc"
        
        # Fuzzing configuration
        self.work_dir = Path("fuzzing_workdir")
        self.input_dir = self.work_dir / "inputs"
        self.output_dir = self.work_dir / "outputs"
        self.crashes_dir = self.work_dir / "crashes"
        
        # SMB target configuration
        self.target_port = 44445  # Non-standard port for testing
        self.samba_proc = None
        self.fuzzing_proc = None
        
        # State tracking
        self.vulnerability_patterns = []
        self.coverage_data = {}
        self.crash_analysis = {}
        
    def setup_environment(self):
        """Setup AFL++ fuzzing environment"""
        logger.info("🔧 Setting up AFL++ fuzzing environment")
        
        # Create work directories
        self.work_dir.mkdir(exist_ok=True)
        self.input_dir.mkdir(exist_ok=True)
        self.output_dir.mkdir(exist_ok=True)
        self.crashes_dir.mkdir(exist_ok=True)
        
        # Verify AFL++ binaries
        if not self.afl_fuzz.exists():
            raise RuntimeError(f"AFL++ not found at {self.afl_fuzz}")
            
        # Generate initial test cases
        self._generate_initial_testcases()
        
        # Build SMB target harness
        self._build_smb_harness()
        
        logger.info("✅ AFL++ environment setup complete")
    
    def _generate_initial_testcases(self):
        """Generate initial SMB protocol test cases"""
        logger.info("📝 Generating initial SMB test cases")
        
        # Basic SMB messages for seeding
        test_cases = [
            # SMB2 Negotiate
            SMBMessage(SMBCommand.NEGOTIATE, 0, 1, 0, 0, 
                      b'\x24\x00\x05\x00\x00\x00\x00\x00' +  # Negotiate request
                      b'\x7f\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x02\x02\x10\x02' +
                      b'\x00\x03\x02\x03\x11\x03\x00\x00'),
            
            # SMB2 Session Setup
            SMBMessage(SMBCommand.SESSION_SETUP, 0, 2, 0, 0,
                      b'\x19\x00\x00\x01\x01\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'NTLMSSP\x00'),
            
            # SMB2 Tree Connect  
            SMBMessage(SMBCommand.TREE_CONNECT, 0, 3, 12345, 0,
                      b'\x09\x00\x00\x00\x48\x00\x00\x00' +
                      b'\\\\127.0.0.1\\IPC$\x00'),
            
            # SMB2 Create Request
            SMBMessage(SMBCommand.CREATE, 0, 4, 12345, 67890,
                      b'\x39\x00\x02\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x00\x00\x00\x00\x00\x00\x00\x00' +
                      b'\x18\x00\x00\x00\x00\x00\x00\x00' +
                      b'\\pipe\\spoolss\x00'),
        ]
        
        # Write test cases to input directory
        for i, msg in enumerate(test_cases):
            test_file = self.input_dir / f"smb_test_{i:03d}.bin"
            with open(test_file, 'wb') as f:
                f.write(msg.to_bytes())
        
        # Add mutated variants for better coverage
        self._generate_mutated_testcases(test_cases)
        
        logger.info(f"✅ Generated {len(list(self.input_dir.glob('*.bin')))} initial test cases")
    
    def _generate_mutated_testcases(self, base_cases: List[SMBMessage]):
        """Generate mutated variants of base test cases"""
        mutations = [
            # Length field mutations
            lambda data: data[:4] + struct.pack('<I', 0xFFFFFFFF) + data[8:],
            lambda data: data[:4] + struct.pack('<I', 0) + data[8:],
            
            # Command mutations
            lambda data: data[:12] + struct.pack('<H', 0xFFFF) + data[14:],
            lambda data: data[:12] + struct.pack('<H', 0x00) + data[14:],
            
            # Session ID mutations  
            lambda data: data[:44] + struct.pack('<Q', 0xFFFFFFFFFFFFFFFF) + data[52:],
            lambda data: data[:44] + struct.pack('<Q', 0) + data[52:],
            
            # Payload corruption
            lambda data: data[:-10] + b'\x00' * 10,
            lambda data: data + b'\x41' * 100,
        ]
        
        for i, msg in enumerate(base_cases):
            base_data = msg.to_bytes()
            for j, mutation in enumerate(mutations):
                try:
                    mutated_data = mutation(base_data)
                    test_file = self.input_dir / f"smb_mutated_{i:03d}_{j:03d}.bin"
                    with open(test_file, 'wb') as f:
                        f.write(mutated_data)
                except:
                    continue  # Skip failed mutations
    
    def _build_smb_harness(self):
        """Build instrumented SMB target harness"""
        logger.info("🔨 Building SMB fuzzing harness")
        
        # Create simple SMB server harness for fuzzing
        harness_code = '''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#define SMB_PORT 44445
#define MAX_PACKET_SIZE 65536

// Simple SMB message parsing (vulnerable on purpose for testing)
typedef struct {
    char protocol[4];
    short header_len;
    short credit_charge;
    int command;
    int flags;
    int flags2;
    long long message_id;
    long long process_id;
    long long tree_id;
    long long session_id;
    long long signature;
    long long signature2;
} __attribute__((packed)) smb_header_t;

void process_smb_packet(char *data, int len) {
    if (len < sizeof(smb_header_t)) return;
    
    smb_header_t *hdr = (smb_header_t *)data;
    
    // Check protocol
    if (memcmp(hdr->protocol, "\\xfeSMB", 4) != 0) return;
    
    // Simulate processing different commands
    switch (hdr->command) {
        case 0x72: // NEGOTIATE
            // Vulnerable path: no bounds checking
            if (len > 200) {
                char buffer[100];
                memcpy(buffer, data + sizeof(smb_header_t), len - sizeof(smb_header_t));
            }
            break;
            
        case 0x73: // SESSION_SETUP
            // Use-after-free simulation
            if (hdr->session_id == 0xFFFFFFFFFFFFFFFF) {
                free(data);
                printf("Session: %llx\\n", hdr->session_id); // UAF
            }
            break;
            
        case 0x75: // TREE_CONNECT
            // Integer overflow
            if (hdr->tree_id > 0x7FFFFFFFFFFFFFFF) {
                char *buf = malloc(hdr->tree_id + 100);
                if (buf) free(buf);
            }
            break;
            
        case 0xA2: // CREATE
            // Double free
            if (hdr->message_id == 0x41414141) {
                char *ptr = malloc(100);
                free(ptr);
                free(ptr); // Double free
            }
            break;
    }
}

#ifdef AFL_HARNESS
// AFL++ persistent mode harness
int main() {
    char *data;
    int len;
    
    __AFL_INIT();
    
    while (__AFL_LOOP(10000)) {
        data = malloc(MAX_PACKET_SIZE);
        len = read(0, data, MAX_PACKET_SIZE);
        if (len > 0) {
            process_smb_packet(data, len);
        }
        free(data);
    }
    
    return 0;
}
#else
// Standalone server mode
int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    char buffer[MAX_PACKET_SIZE];
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(SMB_PORT);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    
    printf("SMB fuzzing target listening on port %d\\n", SMB_PORT);
    
    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        int len = recv(client_fd, buffer, MAX_PACKET_SIZE, 0);
        if (len > 0) {
            process_smb_packet(buffer, len);
        }
        close(client_fd);
    }
    
    return 0;
}
#endif
'''
        
        # Write harness code
        harness_file = self.work_dir / "smb_harness.c"
        with open(harness_file, 'w') as f:
            f.write(harness_code)
        
        # Build with instrumentation
        try:
            # Build standalone version for testing (fallback if AFL++ compiler fails)
            subprocess.run([
                "gcc", "-O2", "-g", str(harness_file), 
                "-o", str(self.work_dir / "smb_harness_standalone")
            ], check=True)
            
            # Try to build AFL++ version (optional)
            try:
                subprocess.run([
                    str(self.afl_cc), "-DAFL_HARNESS", "-O2", "-g", 
                    str(harness_file), "-o", str(self.work_dir / "smb_harness_afl")
                ], check=True)
                logger.info("✅ AFL++ harness built successfully")
            except:
                # Copy standalone as AFL version if AFL++ build fails
                shutil.copy(str(self.work_dir / "smb_harness_standalone"),
                          str(self.work_dir / "smb_harness_afl"))
                logger.warning("AFL++ compiler failed, using fallback harness")
            
            logger.info("✅ SMB harness built successfully")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build SMB harness: {e}")
            raise
    
    def run_fuzzing_campaign(self, 
                           strategy: FuzzingStrategy = FuzzingStrategy.CMPLOG_GUIDED,
                           duration_minutes: int = 60,
                           memory_limit: str = "2G") -> FuzzingResult:
        """Run AFL++ fuzzing campaign against SMB target"""
        
        logger.info(f"🚀 Starting AFL++ SMB fuzzing campaign ({strategy.value}, {duration_minutes}min)")
        
        campaign_id = f"smb_fuzz_{int(time.time())}"
        campaign_output = self.output_dir / campaign_id
        campaign_output.mkdir(exist_ok=True)
        
        # Prepare AFL++ command
        afl_cmd = [
            str(self.afl_fuzz),
            "-i", str(self.input_dir),
            "-o", str(campaign_output),
            "-m", memory_limit,
            "-t", "5000+",  # 5 second timeout with auto-scaling
        ]
        
        # Add strategy-specific options
        if strategy == FuzzingStrategy.CMPLOG_GUIDED:
            afl_cmd.extend(["-c", str(self.work_dir / "smb_harness_afl")])
        elif strategy == FuzzingStrategy.REDQUEEN_MUTATOR:
            afl_cmd.extend(["-L", "0"])  # Enable RedQueen
        elif strategy == FuzzingStrategy.CUSTOM_MUTATOR:
            afl_cmd.extend(["-P", "explore"])  # Power schedule
        
        # Add target executable
        afl_cmd.append(str(self.work_dir / "smb_harness_afl"))
        
        # Start fuzzing
        start_time = time.time()
        
        try:
            logger.info(f"Running: {' '.join(afl_cmd)}")
            
            # Run AFL++ with timeout
            fuzzing_proc = subprocess.Popen(
                afl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
            
            # Monitor fuzzing progress
            def timeout_handler():
                time.sleep(duration_minutes * 60)
                try:
                    os.killpg(os.getpgid(fuzzing_proc.pid), signal.SIGTERM)
                except:
                    pass
            
            timeout_thread = threading.Thread(target=timeout_handler)
            timeout_thread.daemon = True
            timeout_thread.start()
            
            # Wait for completion
            fuzzing_proc.wait()
            
        except KeyboardInterrupt:
            logger.info("Fuzzing interrupted by user")
            try:
                os.killpg(os.getpgid(fuzzing_proc.pid), signal.SIGTERM)
            except:
                pass
        
        runtime_seconds = int(time.time() - start_time)
        
        # Analyze results
        results = self._analyze_fuzzing_results(campaign_id, campaign_output, runtime_seconds)
        
        logger.info(f"✅ Fuzzing campaign complete: {results.unique_crashes} crashes, {results.coverage_percent:.1f}% coverage")
        
        return results
    
    def _analyze_fuzzing_results(self, campaign_id: str, output_dir: Path, runtime: int) -> FuzzingResult:
        """Analyze AFL++ fuzzing results"""
        
        logger.info("📊 Analyzing fuzzing results")
        
        # Parse AFL++ stats
        stats_file = output_dir / "default" / "fuzzer_stats"
        stats = {}
        
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                for line in f:
                    if ':' in line:
                        key, value = line.strip().split(':', 1)
                        stats[key.strip()] = value.strip()
        
        # Count crashes and unique findings
        crashes_dir = output_dir / "default" / "crashes"
        hangs_dir = output_dir / "default" / "hangs"
        queue_dir = output_dir / "default" / "queue"
        
        crashes = list(crashes_dir.glob("*")) if crashes_dir.exists() else []
        hangs = list(hangs_dir.glob("*")) if hangs_dir.exists() else []
        queue_items = list(queue_dir.glob("*")) if queue_dir.exists() else []
        
        # Analyze coverage
        coverage_data = self._extract_coverage_data(output_dir)
        
        # Identify vulnerability candidates
        vuln_candidates = self._analyze_crash_patterns(crashes)
        
        return FuzzingResult(
            campaign_id=campaign_id,
            target_type="smb_protocol",
            total_executions=int(stats.get("execs_done", 0)),
            unique_crashes=len([c for c in crashes if not c.name.startswith("README")]),
            unique_hangs=len([h for h in hangs if not h.name.startswith("README")]),
            coverage_percent=float(stats.get("bitmap_cvg", "0.0").replace("%", "")),
            interesting_paths=len(queue_items),
            runtime_seconds=runtime,
            crashes_found=[str(c) for c in crashes[:10]],  # First 10 crashes
            coverage_map=coverage_data,
            vulnerability_candidates=vuln_candidates
        )
    
    def _extract_coverage_data(self, output_dir: Path) -> Dict[str, int]:
        """Extract coverage information from AFL++ output"""
        
        coverage_data = {}
        plot_data = output_dir / "default" / "plot_data"
        
        if plot_data.exists():
            try:
                with open(plot_data, 'r') as f:
                    lines = f.readlines()
                    if lines:
                        # Parse last line for current coverage
                        last_line = lines[-1].strip().split(',')
                        if len(last_line) >= 4:
                            coverage_data = {
                                "total_paths": int(last_line[1]),
                                "unique_crashes": int(last_line[2]),
                                "unique_hangs": int(last_line[3]),
                                "execution_count": int(last_line[4]) if len(last_line) > 4 else 0
                            }
            except:
                logger.warning("Could not parse coverage data")
        
        return coverage_data
    
    def _analyze_crash_patterns(self, crash_files: List[Path]) -> List[Dict[str, Any]]:
        """Analyze crash patterns for vulnerability classification"""
        
        vulnerability_candidates = []
        
        for crash_file in crash_files:
            if crash_file.name.startswith("README"):
                continue
                
            try:
                # Read crash input
                with open(crash_file, 'rb') as f:
                    crash_data = f.read()
                
                # Basic pattern analysis
                vuln_type = "unknown"
                confidence = 0.5
                
                # Check for specific vulnerability patterns
                if len(crash_data) > 1000:
                    vuln_type = "buffer_overflow"
                    confidence = 0.8
                elif b'\xff' * 8 in crash_data:
                    vuln_type = "integer_overflow"
                    confidence = 0.7
                elif b'\x41' * 20 in crash_data:
                    vuln_type = "memory_corruption"
                    confidence = 0.6
                
                vulnerability_candidates.append({
                    "crash_file": str(crash_file),
                    "vulnerability_type": vuln_type,
                    "confidence": confidence,
                    "crash_size": len(crash_data),
                    "analysis_timestamp": time.time()
                })
                
            except Exception as e:
                logger.warning(f"Could not analyze crash {crash_file}: {e}")
        
        return vulnerability_candidates[:20]  # Return top 20 candidates
    
    def generate_poc_exploits(self, fuzzing_result: FuzzingResult) -> List[Dict[str, Any]]:
        """Generate proof-of-concept exploits from crash findings"""
        
        logger.info("🔥 Generating PoC exploits from crashes")
        
        exploits = []
        
        for vuln_candidate in fuzzing_result.vulnerability_candidates:
            try:
                crash_file = Path(vuln_candidate["crash_file"])
                
                with open(crash_file, 'rb') as f:
                    crash_data = f.read()
                
                # Generate basic PoC
                poc_code = self._generate_smb_poc(crash_data, vuln_candidate["vulnerability_type"])
                
                exploits.append({
                    "vulnerability_type": vuln_candidate["vulnerability_type"],
                    "confidence": vuln_candidate["confidence"],
                    "poc_code": poc_code,
                    "crash_trigger": crash_data.hex(),
                    "description": f"SMB {vuln_candidate['vulnerability_type']} exploit",
                    "severity": "HIGH" if vuln_candidate["confidence"] > 0.7 else "MEDIUM"
                })
                
            except Exception as e:
                logger.warning(f"Could not generate PoC for {vuln_candidate}: {e}")
        
        return exploits
    
    def _generate_smb_poc(self, crash_data: bytes, vuln_type: str) -> str:
        """Generate SMB PoC exploit code"""
        
        poc_template = f'''#!/usr/bin/env python3
"""
SMB {vuln_type.upper()} Proof-of-Concept
Generated by ZeroBuilder AFL++ fuzzer
"""

import socket
import struct

def trigger_vulnerability():
    # Connect to SMB target
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 44445))
    
    # Crash-triggering payload
    payload = bytes.fromhex("{crash_data.hex()}")
    
    print(f"Sending {{len(payload)}} bytes to trigger {vuln_type}")
    sock.send(payload)
    
    # Check response
    try:
        response = sock.recv(1024)
        print(f"Received response: {{len(response)}} bytes")
    except:
        print("Target crashed or no response")
    
    sock.close()

if __name__ == "__main__":
    trigger_vulnerability()
'''
        
        return poc_template
    
    def export_results_for_integration(self, fuzzing_result: FuzzingResult) -> Dict[str, Any]:
        """Export fuzzing results for integration with ZeroBuilder detectors"""
        
        integration_data = {
            "fuzzing_signatures": [],
            "coverage_patterns": [],
            "vulnerability_indicators": [],
            "afl_integration_ready": True
        }
        
        # Export crash patterns as detection signatures
        for vuln in fuzzing_result.vulnerability_candidates:
            integration_data["fuzzing_signatures"].append({
                "pattern": f"afl_smb_{vuln['vulnerability_type']}",
                "confidence": vuln["confidence"],
                "detection_rule": f"SMB AFL++ detected {vuln['vulnerability_type']}",
                "crash_characteristics": {
                    "size": vuln["crash_size"],
                    "type": vuln["vulnerability_type"]
                }
            })
        
        # Export coverage information
        if fuzzing_result.coverage_map:
            integration_data["coverage_patterns"] = [
                {
                    "coverage_metric": key,
                    "value": value,
                    "campaign_id": fuzzing_result.campaign_id
                }
                for key, value in fuzzing_result.coverage_map.items()
            ]
        
        # Export vulnerability indicators
        integration_data["vulnerability_indicators"] = [
            {
                "indicator_type": "crash_count",
                "value": fuzzing_result.unique_crashes,
                "threshold": 5,
                "severity": "HIGH" if fuzzing_result.unique_crashes > 10 else "MEDIUM"
            },
            {
                "indicator_type": "coverage_achieved", 
                "value": fuzzing_result.coverage_percent,
                "threshold": 70.0,
                "severity": "INFO"
            }
        ]
        
        return integration_data

def main():
    """Run AFL++ SMB fuzzing demonstration"""
    
    print("🚀 ZeroBuilder AFL++ SMB Fuzzing System")
    print("Real coverage-guided vulnerability discovery")
    print("=" * 60)
    
    # Initialize fuzzer
    fuzzer = SMBAFLFuzzer()
    
    try:
        # Setup environment
        fuzzer.setup_environment()
        
        # Run fuzzing campaigns with different strategies
        strategies = [
            (FuzzingStrategy.BASIC_COVERAGE, 10),  # 10 minute basic run
            (FuzzingStrategy.CMPLOG_GUIDED, 15),  # 15 minute guided run
        ]
        
        all_results = []
        
        for strategy, duration in strategies:
            print(f"\n🎯 Running {strategy.value} fuzzing for {duration} minutes...")
            
            result = fuzzer.run_fuzzing_campaign(
                strategy=strategy,
                duration_minutes=duration,
                memory_limit="2G"
            )
            
            all_results.append(result)
            
            print(f"📊 Results: {result.unique_crashes} crashes, {result.coverage_percent:.1f}% coverage")
            
            # Generate PoCs for interesting findings
            if result.unique_crashes > 0:
                exploits = fuzzer.generate_poc_exploits(result)
                print(f"🔥 Generated {len(exploits)} PoC exploits")
        
        # Export integration data
        if all_results:
            integration_data = fuzzer.export_results_for_integration(all_results[0])
            
            print(f"\n🔧 Integration Results:")
            print(f"   Fuzzing signatures: {len(integration_data['fuzzing_signatures'])}")
            print(f"   Coverage patterns: {len(integration_data['coverage_patterns'])}")
            print(f"   Vulnerability indicators: {len(integration_data['vulnerability_indicators'])}")
        
        print(f"\n✅ AFL++ SMB fuzzing complete!")
        print(f"   Total campaigns: {len(all_results)}")
        print(f"   Total crashes found: {sum(r.unique_crashes for r in all_results)}")
        print(f"   Best coverage: {max(r.coverage_percent for r in all_results):.1f}%")
        
    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())