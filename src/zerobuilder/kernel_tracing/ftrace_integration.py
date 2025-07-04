#!/usr/bin/env python3
"""
ZeroBuilder Step 2: ftrace Integration
Lightweight kernel function tracing for race condition detection
"""

import os
import sys
import time
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import threading
import queue

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FtraceEvent:
    """Single ftrace event with timing and context"""
    timestamp: float
    pid: int
    cpu: int
    function: str
    call_type: str  # 'entry' or 'exit'
    duration: Optional[float] = None
    caller: Optional[str] = None
    args: Optional[str] = None

@dataclass
class SyscallTrace:
    """Complete syscall trace with entry/exit timing"""
    syscall_name: str
    pid: int
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    return_value: Optional[int] = None
    args: Optional[str] = None

class FtraceManager:
    """Manage ftrace for kernel function and syscall tracing"""
    
    def __init__(self, debug_fs_path: str = "/sys/kernel/debug"):
        self.debug_fs_path = Path(debug_fs_path)
        self.tracing_path = self.debug_fs_path / "tracing"
        self.is_tracing = False
        self.trace_buffer = queue.Queue()
        self.current_tracer = None
        
        # Event collections
        self.syscall_traces: List[SyscallTrace] = []
        self.function_events: List[FtraceEvent] = []
        self.race_candidates: List[Tuple[SyscallTrace, SyscallTrace]] = []
        
        logger.info(f"🔧 FtraceManager initialized")
        logger.info(f"📂 Tracing path: {self.tracing_path}")
        
        # Check if ftrace is available
        if not self._check_ftrace_availability():
            logger.warning("⚠️ ftrace not available - running in simulation mode")
            self.simulation_mode = True
        else:
            self.simulation_mode = False
            logger.info("✅ ftrace available and ready")
    
    def _check_ftrace_availability(self) -> bool:
        """Check if ftrace is available on this system"""
        try:
            # Check if we can access tracing directory
            if not self.tracing_path.exists():
                return False
            
            # Check if we have write permissions (need root)
            test_file = self.tracing_path / "current_tracer"
            if not test_file.exists():
                return False
            
            # Try to read current tracer (should work even without root)
            with open(test_file, 'r') as f:
                current = f.read().strip()
                logger.info(f"📊 Current tracer: {current}")
            
            return True
            
        except PermissionError:
            logger.warning("⚠️ Permission denied - need root for ftrace")
            return False
        except Exception as e:
            logger.warning(f"⚠️ ftrace check failed: {e}")
            return False
    
    def setup_syscall_tracing(self, target_syscalls: List[str] = None) -> bool:
        """Setup syscall tracing for race detection"""
        if self.simulation_mode:
            return self._simulate_syscall_setup(target_syscalls)
        
        try:
            # Default syscalls prone to race conditions
            if target_syscalls is None:
                target_syscalls = [
                    "sys_open", "sys_openat", "sys_close",
                    "sys_read", "sys_write", "sys_mmap", "sys_munmap",
                    "sys_fork", "sys_clone", "sys_exit",
                    "sys_kill", "sys_signal"
                ]
            
            logger.info(f"🔧 Setting up syscall tracing for: {target_syscalls}")
            
            # Enable syscall events
            events_path = self.tracing_path / "events" / "syscalls"
            if events_path.exists():
                # Enable specific syscall enter/exit events
                for syscall in target_syscalls:
                    enter_event = events_path / f"sys_enter_{syscall.replace('sys_', '')}"
                    exit_event = events_path / f"sys_exit_{syscall.replace('sys_', '')}"
                    
                    if enter_event.exists():
                        self._write_tracing_file(enter_event / "enable", "1")
                    if exit_event.exists():
                        self._write_tracing_file(exit_event / "enable", "1")
            
            # Set function graph tracer for detailed timing
            self._write_tracing_file(self.tracing_path / "current_tracer", "function_graph")
            
            # Configure buffer size for longer traces
            self._write_tracing_file(self.tracing_path / "buffer_size_kb", "8192")
            
            logger.info("✅ Syscall tracing setup complete")
            return True
            
        except Exception as e:
            logger.error(f"❌ Syscall tracing setup failed: {e}")
            return False
    
    def setup_function_tracing(self, target_functions: List[str] = None) -> bool:
        """Setup function tracing for specific kernel functions"""
        if self.simulation_mode:
            return self._simulate_function_setup(target_functions)
        
        try:
            # Default functions related to race-prone operations
            if target_functions is None:
                target_functions = [
                    "do_sys_open", "filp_close", "do_fork",
                    "mmput", "get_task_mm", "find_vma",
                    "signal_deliver", "do_exit"
                ]
            
            logger.info(f"🔧 Setting up function tracing for: {target_functions}")
            
            # Set function tracer
            self._write_tracing_file(self.tracing_path / "current_tracer", "function")
            
            # Set function filter to only trace target functions
            filter_content = "\n".join(target_functions)
            self._write_tracing_file(self.tracing_path / "set_ftrace_filter", filter_content)
            
            logger.info("✅ Function tracing setup complete")
            return True
            
        except Exception as e:
            logger.error(f"❌ Function tracing setup failed: {e}")
            return False
    
    def start_tracing(self) -> bool:
        """Start ftrace data collection"""
        if self.simulation_mode:
            return self._simulate_start_tracing()
        
        try:
            # Clear previous traces
            self._write_tracing_file(self.tracing_path / "trace", "")
            
            # Enable tracing
            self._write_tracing_file(self.tracing_path / "tracing_on", "1")
            
            self.is_tracing = True
            logger.info("🚀 ftrace tracing started")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to start tracing: {e}")
            return False
    
    def stop_tracing(self) -> bool:
        """Stop ftrace data collection"""
        if self.simulation_mode:
            return self._simulate_stop_tracing()
        
        try:
            # Disable tracing
            self._write_tracing_file(self.tracing_path / "tracing_on", "0")
            
            self.is_tracing = False
            logger.info("⏹️ ftrace tracing stopped")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to stop tracing: {e}")
            return False
    
    def collect_trace_data(self) -> List[FtraceEvent]:
        """Collect and parse ftrace data"""
        if self.simulation_mode:
            return self._simulate_trace_data()
        
        try:
            trace_file = self.tracing_path / "trace"
            
            events = []
            with open(trace_file, 'r') as f:
                for line in f:
                    event = self._parse_ftrace_line(line.strip())
                    if event:
                        events.append(event)
            
            self.function_events.extend(events)
            logger.info(f"📊 Collected {len(events)} ftrace events")
            return events
            
        except Exception as e:
            logger.error(f"❌ Failed to collect trace data: {e}")
            return []
    
    def _parse_ftrace_line(self, line: str) -> Optional[FtraceEvent]:
        """Parse single ftrace output line"""
        try:
            # Example ftrace line format:
            # process-1234  [001] 123456.789012: function_name
            # process-1234  [001] 123456.789012: function_name() {
            # process-1234  [001] 123456.789012:         child_function();
            # process-1234  [001] 123456.789012: } /* function_name */
            
            if not line or line.startswith('#'):
                return None
            
            parts = line.split()
            if len(parts) < 4:
                return None
            
            # Extract basic info
            process_info = parts[0]  # process-1234
            cpu_info = parts[1]      # [001]
            timestamp = parts[2].rstrip(':')  # 123456.789012:
            function_info = ' '.join(parts[3:])  # function_name() { or }
            
            # Parse process name and PID
            if '-' in process_info:
                process_name, pid_str = process_info.rsplit('-', 1)
                pid = int(pid_str)
            else:
                pid = 0
            
            # Parse CPU number
            cpu = int(cpu_info.strip('[]'))
            
            # Parse timestamp
            ts = float(timestamp)
            
            # Determine call type and function name
            if function_info.endswith('{'):
                call_type = 'entry'
                function = function_info.replace('()', '').replace(' {', '').strip()
            elif function_info.startswith('}'):
                call_type = 'exit'
                # Extract function name from comment
                if '/*' in function_info and '*/' in function_info:
                    function = function_info.split('/*')[1].split('*/')[0].strip()
                else:
                    function = 'unknown'
            else:
                call_type = 'call'
                function = function_info.strip()
            
            return FtraceEvent(
                timestamp=ts,
                pid=pid,
                cpu=cpu,
                function=function,
                call_type=call_type
            )
            
        except Exception as e:
            logger.debug(f"Failed to parse ftrace line: {line} - {e}")
            return None
    
    def _write_tracing_file(self, file_path: Path, content: str) -> bool:
        """Write to ftrace control file"""
        try:
            with open(file_path, 'w') as f:
                f.write(content)
            return True
        except PermissionError:
            logger.error(f"❌ Permission denied writing to {file_path} - need root")
            return False
        except Exception as e:
            logger.error(f"❌ Failed to write to {file_path}: {e}")
            return False
    
    def analyze_race_patterns(self) -> List[Tuple[FtraceEvent, FtraceEvent]]:
        """Analyze collected events for race condition patterns"""
        race_candidates = []
        
        # Group events by function for race analysis
        function_events = {}
        for event in self.function_events:
            if event.function not in function_events:
                function_events[event.function] = []
            function_events[event.function].append(event)
        
        # Look for potential races
        for func_name, events in function_events.items():
            if len(events) < 2:
                continue
            
            # Sort by timestamp
            events.sort(key=lambda e: e.timestamp)
            
            # Look for overlapping execution from different PIDs
            for i in range(len(events) - 1):
                event1 = events[i]
                event2 = events[i + 1]
                
                # Check for race conditions
                if (event1.pid != event2.pid and 
                    abs(event1.timestamp - event2.timestamp) < 0.001):  # Within 1ms
                    
                    race_candidates.append((event1, event2))
                    logger.info(f"🔍 Potential race detected: {func_name} "
                              f"PID {event1.pid} vs PID {event2.pid}")
        
        return race_candidates
    
    def generate_race_report(self) -> Dict:
        """Generate comprehensive race condition analysis report"""
        races = self.analyze_race_patterns()
        
        report = {
            "total_events": len(self.function_events),
            "race_candidates": len(races),
            "functions_traced": len(set(e.function for e in self.function_events)),
            "time_span": 0,
            "detailed_races": []
        }
        
        if self.function_events:
            start_time = min(e.timestamp for e in self.function_events)
            end_time = max(e.timestamp for e in self.function_events)
            report["time_span"] = end_time - start_time
        
        # Add detailed race information
        for event1, event2 in races:
            race_detail = {
                "function": event1.function,
                "pid1": event1.pid,
                "pid2": event2.pid,
                "time_difference": abs(event1.timestamp - event2.timestamp),
                "risk_level": self._assess_race_risk(event1, event2)
            }
            report["detailed_races"].append(race_detail)
        
        return report
    
    def _assess_race_risk(self, event1: FtraceEvent, event2: FtraceEvent) -> str:
        """Assess risk level of potential race condition"""
        time_diff = abs(event1.timestamp - event2.timestamp)
        
        # Critical race-prone functions
        critical_functions = {
            "do_sys_open", "filp_close", "mmput", "get_task_mm", 
            "find_vma", "do_fork", "do_exit"
        }
        
        if event1.function in critical_functions:
            if time_diff < 0.0001:  # < 0.1ms
                return "CRITICAL"
            elif time_diff < 0.001:  # < 1ms
                return "HIGH"
            else:
                return "MEDIUM"
        else:
            return "LOW"
    
    # Simulation methods for testing without root access
    def _simulate_syscall_setup(self, target_syscalls: List[str]) -> bool:
        """Simulate syscall tracing setup"""
        logger.info(f"🔧 [SIMULATION] Setting up syscall tracing for: {target_syscalls}")
        return True
    
    def _simulate_function_setup(self, target_functions: List[str]) -> bool:
        """Simulate function tracing setup"""
        logger.info(f"🔧 [SIMULATION] Setting up function tracing for: {target_functions}")
        return True
    
    def _simulate_start_tracing(self) -> bool:
        """Simulate starting tracing"""
        self.is_tracing = True
        logger.info("🚀 [SIMULATION] ftrace tracing started")
        return True
    
    def _simulate_stop_tracing(self) -> bool:
        """Simulate stopping tracing"""
        self.is_tracing = False
        logger.info("⏹️ [SIMULATION] ftrace tracing stopped")
        return True
    
    def _simulate_trace_data(self) -> List[FtraceEvent]:
        """Generate simulated trace data for testing"""
        import random
        
        # Generate realistic trace events
        events = []
        base_time = time.time()
        
        functions = ["do_sys_open", "filp_close", "do_fork", "mmput", "find_vma"]
        
        for i in range(100):
            event = FtraceEvent(
                timestamp=base_time + i * 0.001 + random.uniform(0, 0.0005),
                pid=random.choice([1234, 1235, 1236]),
                cpu=random.randint(0, 3),
                function=random.choice(functions),
                call_type=random.choice(['entry', 'exit', 'call'])
            )
            events.append(event)
        
        self.function_events.extend(events)
        logger.info(f"📊 [SIMULATION] Generated {len(events)} simulated events")
        return events

def main():
    """Test ftrace integration"""
    logger.info("🚀 Testing ZeroBuilder ftrace integration")
    logger.info("=" * 60)
    
    # Initialize ftrace manager
    tracer = FtraceManager()
    
    # Setup tracing
    logger.info("\n🔧 Setting up syscall and function tracing...")
    syscall_ok = tracer.setup_syscall_tracing()
    function_ok = tracer.setup_function_tracing()
    
    if not (syscall_ok and function_ok):
        logger.error("❌ Tracing setup failed")
        return
    
    # Start tracing
    logger.info("\n🚀 Starting tracing for 5 seconds...")
    if not tracer.start_tracing():
        logger.error("❌ Failed to start tracing")
        return
    
    # Let it trace for a few seconds
    time.sleep(5)
    
    # Stop tracing
    logger.info("\n⏹️ Stopping tracing...")
    tracer.stop_tracing()
    
    # Collect and analyze data
    logger.info("\n📊 Collecting trace data...")
    events = tracer.collect_trace_data()
    
    logger.info("\n🔍 Analyzing for race patterns...")
    races = tracer.analyze_race_patterns()
    
    # Generate report
    logger.info("\n📋 Generating race condition report...")
    report = tracer.generate_race_report()
    
    logger.info(f"\n" + "=" * 60)
    logger.info("📊 FTRACE ANALYSIS RESULTS")
    logger.info("=" * 60)
    logger.info(f"Total Events Collected: {report['total_events']}")
    logger.info(f"Functions Traced: {report['functions_traced']}")
    logger.info(f"Race Candidates Found: {report['race_candidates']}")
    logger.info(f"Trace Duration: {report['time_span']:.3f} seconds")
    
    if report['detailed_races']:
        logger.info(f"\n🔍 Race Condition Details:")
        for i, race in enumerate(report['detailed_races'][:5], 1):
            logger.info(f"  {i}. Function: {race['function']}")
            logger.info(f"     PIDs: {race['pid1']} vs {race['pid2']}")
            logger.info(f"     Time Diff: {race['time_difference']:.6f}s")
            logger.info(f"     Risk Level: {race['risk_level']}")
    
    logger.info(f"\n✅ ftrace integration test complete!")
    
    if tracer.simulation_mode:
        logger.info(f"💡 Running in simulation mode - use 'sudo' for real tracing")
    else:
        logger.info(f"🎯 Real ftrace data collected - ready for production use!")

if __name__ == "__main__":
    main()