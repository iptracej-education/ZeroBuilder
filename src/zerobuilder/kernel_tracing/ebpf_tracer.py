#!/usr/bin/env python3
"""
ZeroBuilder Step 2: eBPF Tracer
Advanced kernel event capture with BPF programs for race detection
"""

import os
import sys
import time
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class BPFEvent:
    """eBPF captured kernel event"""
    timestamp: int
    pid: int
    tid: int
    cpu: int
    comm: str  # Process name
    event_type: str
    syscall_name: Optional[str] = None
    return_value: Optional[int] = None
    args: Optional[Dict] = None
    stack_trace: Optional[List[str]] = None

@dataclass
class RaceCondition:
    """Detected race condition between two events"""
    event1: BPFEvent
    event2: BPFEvent
    race_type: str  # 'TOCTOU', 'UAF', 'double_free', etc.
    confidence: float
    description: str
    risk_level: str

class eBPFTracer:
    """eBPF-based kernel tracing for advanced race detection"""
    
    def __init__(self):
        self.events: List[BPFEvent] = []
        self.race_conditions: List[RaceCondition] = []
        self.simulation_mode = True  # Start in simulation until BPF is available
        
        # Check if BPF is available
        self._check_bpf_availability()
        
        logger.info(f"🔧 eBPF Tracer initialized")
        if self.simulation_mode:
            logger.info("💡 Running in simulation mode - install bcc-tools for real eBPF")
        else:
            logger.info("✅ eBPF available and ready")
    
    def _check_bpf_availability(self) -> bool:
        """Check if eBPF/BCC is available on this system"""
        try:
            # Try to import BCC (BPF Compiler Collection)
            # This would normally be: from bcc import BPF
            # But we'll simulate for now since it requires special setup
            
            # Check if bpftrace or bcc-tools are available
            import shutil
            if shutil.which('bpftrace') or shutil.which('trace-bpfcc'):
                logger.info("✅ BPF tools detected")
                # For now, keep simulation mode until proper setup
                self.simulation_mode = True
                return True
            else:
                logger.info("💡 BPF tools not found - running in simulation")
                self.simulation_mode = True
                return False
                
        except ImportError:
            logger.info("💡 BCC not installed - running in simulation")
            self.simulation_mode = True
            return False
    
    def create_syscall_tracer(self, target_syscalls: List[str] = None) -> str:
        """Create eBPF program for syscall tracing"""
        if target_syscalls is None:
            target_syscalls = ["open", "openat", "close", "read", "write", "mmap", "munmap"]
        
        # eBPF C program for syscall tracing
        bpf_program = f"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct syscall_event {{
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 cpu;
    char comm[16];
    char syscall[32];
    s64 ret;
    u64 args[6];
}};

BPF_PERF_OUTPUT(syscall_events);
BPF_HASH(start_times, u32, u64);

// Syscall enter tracepoints
{"".join([f'''
TRACEPOINT_PROBE(syscalls, sys_enter_{syscall}) {{
    struct syscall_event event = {{}};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = tid;
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    strcpy(event.syscall, "{syscall}_enter");
    
    // Store start time for duration calculation
    u64 ts = bpf_ktime_get_ns();
    start_times.update(&tid, &ts);
    
    syscall_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}

TRACEPOINT_PROBE(syscalls, sys_exit_{syscall}) {{
    struct syscall_event event = {{}};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 tid = bpf_get_current_pid_tgid();
    
    event.timestamp = bpf_ktime_get_ns();
    event.pid = pid;
    event.tid = tid;
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    strcpy(event.syscall, "{syscall}_exit");
    event.ret = args->ret;
    
    // Calculate duration
    u64 *start_ts = start_times.lookup(&tid);
    if (start_ts) {{
        u64 duration = event.timestamp - *start_ts;
        start_times.delete(&tid);
    }}
    
    syscall_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}}
''' for syscall in target_syscalls])}
        """
        
        logger.info(f"🔧 Generated eBPF program for syscalls: {target_syscalls}")
        return bpf_program
    
    def create_memory_tracer(self) -> str:
        """Create eBPF program for memory operation tracing"""
        bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>
#include <linux/sched.h>

struct memory_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    char comm[16];
    char operation[16];
    u64 address;
    u64 size;
    u32 cpu;
};

BPF_PERF_OUTPUT(memory_events);

// Track memory allocations and frees
int trace_kmalloc(struct pt_regs *ctx, size_t size) {
    struct memory_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    strcpy(event.operation, "kmalloc");
    event.size = size;
    
    memory_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_kfree(struct pt_regs *ctx, void *ptr) {
    struct memory_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = bpf_get_current_pid_tgid();
    event.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    strcpy(event.operation, "kfree");
    event.address = (u64)ptr;
    
    memory_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
        """
        
        logger.info("🔧 Generated eBPF program for memory operations")
        return bpf_program
    
    def start_tracing(self, duration_seconds: int = 10) -> bool:
        """Start eBPF tracing for specified duration"""
        if self.simulation_mode:
            return self._simulate_tracing(duration_seconds)
        
        try:
            # This would normally use BCC to compile and load the eBPF program
            # from bcc import BPF
            # self.bpf = BPF(text=self.create_syscall_tracer())
            # self.bpf["syscall_events"].open_perf_buffer(self._handle_syscall_event)
            
            logger.info(f"🚀 Starting eBPF tracing for {duration_seconds} seconds...")
            
            # In real implementation, this would start the BPF program
            # and collect events in real-time
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to start eBPF tracing: {e}")
            return False
    
    def _handle_syscall_event(self, cpu, data, size):
        """Handle syscall events from eBPF program"""
        # This would be called by BCC for each event
        # event = ctypes.cast(data, ctypes.POINTER(SyscallEvent)).contents
        pass
    
    def analyze_race_conditions(self) -> List[RaceCondition]:
        """Analyze collected events for race conditions"""
        race_conditions = []
        
        # Group events by process and analyze for race patterns
        process_events = {}
        for event in self.events:
            if event.pid not in process_events:
                process_events[event.pid] = []
            process_events[event.pid].append(event)
        
        # Analyze each process for internal races
        for pid, events in process_events.items():
            races = self._detect_process_races(events)
            race_conditions.extend(races)
        
        # Analyze cross-process races
        cross_races = self._detect_cross_process_races(process_events)
        race_conditions.extend(cross_races)
        
        self.race_conditions = race_conditions
        return race_conditions
    
    def _detect_process_races(self, events: List[BPFEvent]) -> List[RaceCondition]:
        """Detect race conditions within a single process"""
        races = []
        
        # Sort events by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        # Look for specific race patterns
        for i in range(len(events) - 1):
            event1 = events[i]
            event2 = events[i + 1]
            
            # TOCTOU pattern: check followed by use
            if (event1.syscall_name in ["access", "stat", "open"] and
                event2.syscall_name in ["open", "read", "write"] and
                abs(event1.timestamp - event2.timestamp) < 1000000):  # Within 1ms
                
                race = RaceCondition(
                    event1=event1,
                    event2=event2,
                    race_type="TOCTOU",
                    confidence=0.7,
                    description=f"Time-of-check-time-of-use race between {event1.syscall_name} and {event2.syscall_name}",
                    risk_level="HIGH"
                )
                races.append(race)
        
        return races
    
    def _detect_cross_process_races(self, process_events: Dict[int, List[BPFEvent]]) -> List[RaceCondition]:
        """Detect race conditions between processes"""
        races = []
        
        # Look for concurrent access to same resources
        all_events = []
        for events in process_events.values():
            all_events.extend(events)
        
        all_events.sort(key=lambda e: e.timestamp)
        
        # Check for concurrent file operations
        for i in range(len(all_events) - 1):
            event1 = all_events[i]
            event2 = all_events[i + 1]
            
            if (event1.pid != event2.pid and
                event1.syscall_name in ["open", "write", "close"] and
                event2.syscall_name in ["open", "write", "close"] and
                abs(event1.timestamp - event2.timestamp) < 1000000):  # Within 1ms
                
                race = RaceCondition(
                    event1=event1,
                    event2=event2,
                    race_type="CONCURRENT_ACCESS",
                    confidence=0.6,
                    description=f"Concurrent file access race between PID {event1.pid} and {event2.pid}",
                    risk_level="MEDIUM"
                )
                races.append(race)
        
        return races
    
    def generate_race_report(self) -> Dict:
        """Generate comprehensive race condition report"""
        if not self.race_conditions:
            self.analyze_race_conditions()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "total_events": len(self.events),
            "total_races": len(self.race_conditions),
            "race_types": {},
            "risk_levels": {},
            "detailed_races": []
        }
        
        # Categorize races by type and risk
        for race in self.race_conditions:
            # Count by type
            if race.race_type not in report["race_types"]:
                report["race_types"][race.race_type] = 0
            report["race_types"][race.race_type] += 1
            
            # Count by risk level
            if race.risk_level not in report["risk_levels"]:
                report["risk_levels"][race.risk_level] = 0
            report["risk_levels"][race.risk_level] += 1
            
            # Add detailed information
            race_detail = {
                "race_type": race.race_type,
                "confidence": race.confidence,
                "risk_level": race.risk_level,
                "description": race.description,
                "event1": {
                    "pid": race.event1.pid,
                    "syscall": race.event1.syscall_name,
                    "timestamp": race.event1.timestamp
                },
                "event2": {
                    "pid": race.event2.pid,
                    "syscall": race.event2.syscall_name,
                    "timestamp": race.event2.timestamp
                },
                "time_difference_ns": abs(race.event1.timestamp - race.event2.timestamp)
            }
            report["detailed_races"].append(race_detail)
        
        return report
    
    def _simulate_tracing(self, duration: int) -> bool:
        """Simulate eBPF tracing for testing"""
        import random
        
        logger.info(f"🚀 [SIMULATION] Starting eBPF tracing for {duration} seconds...")
        
        base_time = int(time.time() * 1000000000)  # nanoseconds
        syscalls = ["open", "read", "write", "close", "mmap", "munmap"]
        processes = ["bash", "python", "gcc", "make", "test"]
        
        # Generate realistic events
        for i in range(200):
            event = BPFEvent(
                timestamp=base_time + i * 1000000 + random.randint(0, 500000),
                pid=random.choice([1000, 1001, 1002, 1003]),
                tid=random.choice([1000, 1001, 1002, 1003, 1004]),
                cpu=random.randint(0, 3),
                comm=random.choice(processes),
                event_type="syscall",
                syscall_name=random.choice(syscalls),
                return_value=random.choice([0, -1, 1, 4096])
            )
            self.events.append(event)
        
        # Simulate some race conditions
        self._inject_simulated_races()
        
        logger.info(f"📊 [SIMULATION] Generated {len(self.events)} eBPF events")
        return True
    
    def _inject_simulated_races(self):
        """Inject some realistic race conditions for testing"""
        base_time = int(time.time() * 1000000000)
        
        # TOCTOU race simulation
        toctou_event1 = BPFEvent(
            timestamp=base_time + 1000000,
            pid=1001,
            tid=1001,
            cpu=0,
            comm="test_app",
            event_type="syscall",
            syscall_name="access",
            return_value=0
        )
        
        toctou_event2 = BPFEvent(
            timestamp=base_time + 1050000,  # 50μs later
            pid=1001,
            tid=1001,
            cpu=0,
            comm="test_app",
            event_type="syscall",
            syscall_name="open",
            return_value=3
        )
        
        self.events.extend([toctou_event1, toctou_event2])
        
        # Concurrent access race simulation
        concurrent1 = BPFEvent(
            timestamp=base_time + 2000000,
            pid=1002,
            tid=1002,
            cpu=1,
            comm="proc1",
            event_type="syscall",
            syscall_name="write",
            return_value=1024
        )
        
        concurrent2 = BPFEvent(
            timestamp=base_time + 2010000,  # 10μs later
            pid=1003,
            tid=1003,
            cpu=2,
            comm="proc2",
            event_type="syscall",
            syscall_name="write",
            return_value=512
        )
        
        self.events.extend([concurrent1, concurrent2])

def main():
    """Test eBPF integration"""
    logger.info("🚀 Testing ZeroBuilder eBPF integration")
    logger.info("=" * 60)
    
    # Initialize eBPF tracer
    tracer = eBPFTracer()
    
    # Create tracing programs
    logger.info("\n🔧 Creating eBPF programs...")
    syscall_program = tracer.create_syscall_tracer()
    memory_program = tracer.create_memory_tracer()
    
    logger.info(f"📝 Syscall program: {len(syscall_program)} characters")
    logger.info(f"📝 Memory program: {len(memory_program)} characters")
    
    # Start tracing
    logger.info("\n🚀 Starting eBPF tracing...")
    if not tracer.start_tracing(duration_seconds=5):
        logger.error("❌ Failed to start tracing")
        return
    
    # Analyze race conditions
    logger.info("\n🔍 Analyzing race conditions...")
    races = tracer.analyze_race_conditions()
    
    # Generate report
    logger.info("\n📋 Generating eBPF race report...")
    report = tracer.generate_race_report()
    
    logger.info(f"\n" + "=" * 60)
    logger.info("📊 EBPF RACE DETECTION RESULTS")
    logger.info("=" * 60)
    logger.info(f"Total Events: {report['total_events']}")
    logger.info(f"Race Conditions Found: {report['total_races']}")
    
    if report['race_types']:
        logger.info(f"\n🔍 Race Types:")
        for race_type, count in report['race_types'].items():
            logger.info(f"  {race_type}: {count}")
    
    if report['risk_levels']:
        logger.info(f"\n⚠️ Risk Levels:")
        for risk_level, count in report['risk_levels'].items():
            logger.info(f"  {risk_level}: {count}")
    
    if report['detailed_races']:
        logger.info(f"\n📋 Detailed Race Analysis:")
        for i, race in enumerate(report['detailed_races'][:3], 1):
            logger.info(f"  {i}. {race['race_type']} ({race['risk_level']})")
            logger.info(f"     Description: {race['description']}")
            logger.info(f"     Confidence: {race['confidence']:.2f}")
            logger.info(f"     Time Diff: {race['time_difference_ns']/1000:.1f}μs")
    
    logger.info(f"\n✅ eBPF integration test complete!")
    
    if tracer.simulation_mode:
        logger.info(f"💡 Running in simulation mode")
        logger.info(f"🔧 Install bcc-tools and run as root for real eBPF tracing")
    else:
        logger.info(f"🎯 Real eBPF data available - production ready!")

if __name__ == "__main__":
    main()