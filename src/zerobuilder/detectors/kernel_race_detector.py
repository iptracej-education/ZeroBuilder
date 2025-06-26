"""
Kernel Race Condition Temporal Detector
Combines dynamic analysis, temporal graphs, and ML for kernel race detection
"""

import asyncio
import json
import time
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv
from torch_geometric.data import Data
import logging
import re

logger = logging.getLogger(__name__)

class RaceType(Enum):
    """Types of kernel race conditions"""
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    TOCTOU = "time_of_check_time_of_use"
    REFERENCE_COUNTING = "reference_counting"
    MEMORY_ORDERING = "memory_ordering"
    SIGNAL_RACE = "signal_race"
    DEVICE_RACE = "device_race"
    SOCKET_RACE = "socket_race"

@dataclass
class KernelEvent:
    """Kernel execution event from ftrace/dynamic analysis"""
    timestamp: float
    thread_id: int
    function_name: str
    event_type: str  # entry, exit, memory_access, lock, unlock
    memory_address: Optional[int] = None
    lock_address: Optional[int] = None
    call_stack: Optional[List[str]] = None
    cpu_id: Optional[int] = None

@dataclass
class RacePattern:
    """Known kernel race condition pattern"""
    pattern_id: str
    cve_reference: str
    race_type: RaceType
    vulnerable_functions: List[str]
    temporal_signature: Dict
    risk_score: float

class HappensBeforeGraph:
    """
    Represents happens-before relationships in kernel execution
    Used to detect race conditions through temporal analysis
    """
    
    def __init__(self):
        self.events = []
        self.edges = []  # (event1_idx, event2_idx, relationship_type)
        self.memory_accesses = {}  # memory_addr -> [event_indices]
        self.lock_operations = {}  # lock_addr -> [event_indices]
        
    def add_event(self, event: KernelEvent) -> int:
        """Add kernel event and return its index"""
        event_idx = len(self.events)
        self.events.append(event)
        
        # Track memory accesses
        if event.memory_address:
            if event.memory_address not in self.memory_accesses:
                self.memory_accesses[event.memory_address] = []
            self.memory_accesses[event.memory_address].append(event_idx)
        
        # Track lock operations
        if event.lock_address:
            if event.lock_address not in self.lock_operations:
                self.lock_operations[event.lock_address] = []
            self.lock_operations[event.lock_address].append(event_idx)
        
        return event_idx
    
    def add_happens_before_edge(self, event1_idx: int, event2_idx: int, 
                               relationship: str = "temporal"):
        """Add happens-before relationship between events"""
        self.edges.append((event1_idx, event2_idx, relationship))
    
    def build_temporal_edges(self):
        """Build temporal happens-before edges based on timestamps and threads"""
        # Same thread temporal ordering
        thread_events = {}
        for i, event in enumerate(self.events):
            if event.thread_id not in thread_events:
                thread_events[event.thread_id] = []
            thread_events[event.thread_id].append(i)
        
        for thread_id, event_indices in thread_events.items():
            # Sort by timestamp
            event_indices.sort(key=lambda i: self.events[i].timestamp)
            # Add sequential happens-before edges
            for i in range(len(event_indices) - 1):
                self.add_happens_before_edge(
                    event_indices[i], event_indices[i + 1], "same_thread"
                )
    
    def build_synchronization_edges(self):
        """Build happens-before edges based on synchronization primitives"""
        # Lock-based synchronization
        for lock_addr, event_indices in self.lock_operations.items():
            lock_events = [(i, self.events[i]) for i in event_indices]
            lock_events.sort(key=lambda x: x[1].timestamp)
            
            # Track lock/unlock pairs
            lock_stack = []
            for event_idx, event in lock_events:
                if event.event_type == "lock":
                    lock_stack.append(event_idx)
                elif event.event_type == "unlock" and lock_stack:
                    lock_event_idx = lock_stack.pop()
                    # Everything in critical section happens-before unlock
                    self.add_happens_before_edge(lock_event_idx, event_idx, "critical_section")
    
    def detect_race_conditions(self) -> List[Dict]:
        """Detect potential race conditions in the happens-before graph"""
        races = []
        
        # Check for concurrent memory accesses
        for memory_addr, event_indices in self.memory_accesses.items():
            if len(event_indices) < 2:
                continue
                
            # Check all pairs of memory accesses
            for i in range(len(event_indices)):
                for j in range(i + 1, len(event_indices)):
                    idx1, idx2 = event_indices[i], event_indices[j]
                    
                    if self._are_concurrent(idx1, idx2):
                        race = self._analyze_memory_race(idx1, idx2, memory_addr)
                        if race:
                            races.append(race)
        
        return races
    
    def _are_concurrent(self, event1_idx: int, event2_idx: int) -> bool:
        """Check if two events are potentially concurrent (no happens-before relationship)"""
        # Simple check: different threads and no direct happens-before path
        event1 = self.events[event1_idx]
        event2 = self.events[event2_idx]
        
        # Same thread events are not concurrent
        if event1.thread_id == event2.thread_id:
            return False
        
        # Check if there's a happens-before path (simplified)
        return not self._has_happens_before_path(event1_idx, event2_idx)
    
    def _has_happens_before_path(self, start_idx: int, end_idx: int) -> bool:
        """Check if there's a happens-before path from start to end"""
        # Simplified BFS to check reachability
        visited = set()
        queue = [start_idx]
        
        while queue:
            current = queue.pop(0)
            if current == end_idx:
                return True
            
            if current in visited:
                continue
            visited.add(current)
            
            # Add neighbors (events that happen-after current)
            for edge in self.edges:
                if edge[0] == current and edge[1] not in visited:
                    queue.append(edge[1])
        
        return False
    
    def _analyze_memory_race(self, event1_idx: int, event2_idx: int, 
                           memory_addr: int) -> Optional[Dict]:
        """Analyze specific memory race between two events"""
        event1 = self.events[event1_idx]
        event2 = self.events[event2_idx]
        
        # Determine race type based on event patterns
        race_type = None
        risk_score = 0.0
        
        # Check for use-after-free pattern
        if ("free" in event1.function_name.lower() and 
            any(op in event2.function_name.lower() for op in ["access", "read", "write"])):
            race_type = RaceType.USE_AFTER_FREE
            risk_score = 0.9
        
        # Check for double-free pattern
        elif ("free" in event1.function_name.lower() and 
              "free" in event2.function_name.lower()):
            race_type = RaceType.DOUBLE_FREE
            risk_score = 0.85
        
        # Check for TOCTOU pattern
        elif ("check" in event1.function_name.lower() and 
              "use" in event2.function_name.lower()):
            race_type = RaceType.TOCTOU
            risk_score = 0.75
        
        if race_type:
            return {
                "race_type": race_type,
                "risk_score": risk_score,
                "event1": {"idx": event1_idx, "function": event1.function_name, 
                          "timestamp": event1.timestamp, "thread": event1.thread_id},
                "event2": {"idx": event2_idx, "function": event2.function_name,
                          "timestamp": event2.timestamp, "thread": event2.thread_id},
                "memory_address": memory_addr,
                "time_gap": abs(event2.timestamp - event1.timestamp)
            }
        
        return None

class TemporalGraphNeuralNetwork(nn.Module):
    """
    Temporal Graph Neural Network for kernel race detection
    Specifically designed for temporal relationships in kernel execution
    """
    
    def __init__(self, node_features: int = 128, hidden_dim: int = 256, 
                 num_race_types: int = 8, dropout: float = 0.1):
        super(TemporalGraphNeuralNetwork, self).__init__()
        
        # Temporal feature extraction
        self.temporal_encoder = nn.LSTM(node_features, hidden_dim // 2, 
                                       batch_first=True, bidirectional=True)
        
        # Graph convolution layers
        self.gcn1 = GCNConv(node_features, hidden_dim)
        self.gcn2 = GCNConv(hidden_dim, hidden_dim)
        
        # Temporal attention
        self.temporal_attention = nn.MultiheadAttention(hidden_dim, num_heads=8)
        
        # Race type classifier
        self.race_classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_race_types)
        )
        
        # Binary race detector
        self.race_detector = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 2)  # race/no_race
        )
    
    def forward(self, x, edge_index, temporal_sequences=None):
        # Graph convolution
        h1 = F.relu(self.gcn1(x, edge_index))
        h2 = F.relu(self.gcn2(h1, edge_index))
        
        # Temporal processing if sequences provided
        if temporal_sequences is not None:
            temporal_out, (hidden, cell) = self.temporal_encoder(temporal_sequences)
            temporal_features = hidden[-1]  # Last hidden state
        else:
            temporal_features = torch.zeros_like(h2)
        
        # Combine graph and temporal features
        combined_features = torch.cat([h2, temporal_features], dim=1)
        
        # Classification
        race_binary = self.race_detector(combined_features)
        race_type = self.race_classifier(combined_features)
        
        return race_binary, race_type

class KernelRaceDetector:
    """
    Main kernel race detector combining dynamic analysis and temporal ML
    """
    
    def __init__(self, use_ftrace: bool = True):
        self.use_ftrace = use_ftrace
        self.known_race_patterns = self._load_race_patterns()
        self.tgnn_model = TemporalGraphNeuralNetwork()
        self.event_buffer = []
        
    def _load_race_patterns(self) -> List[RacePattern]:
        """Load known kernel race patterns"""
        return [
            # Use-after-free in BTRFS (CVE-2019-19448)
            RacePattern(
                pattern_id="btrfs_uaf",
                cve_reference="CVE-2019-19448",
                race_type=RaceType.USE_AFTER_FREE,
                vulnerable_functions=["btrfs_put_super", "btrfs_statfs"],
                temporal_signature={"free_before_use": True, "refcount_race": True},
                risk_score=0.92
            ),
            
            # TOCTOU in TTY (CVE-2020-29661)
            RacePattern(
                pattern_id="tty_toctou",
                cve_reference="CVE-2020-29661",
                race_type=RaceType.TOCTOU,
                vulnerable_functions=["tty_check_change", "tty_perform_flush"],
                temporal_signature={"check_use_gap": True, "permission_race": True},
                risk_score=0.85
            ),
            
            # VMA cache race (CVE-2018-17182)
            RacePattern(
                pattern_id="vmacache_race",
                cve_reference="CVE-2018-17182",
                race_type=RaceType.MEMORY_ORDERING,
                vulnerable_functions=["vmacache_find", "vmacache_update"],
                temporal_signature={"cache_coherency": True, "memory_ordering": True},
                risk_score=0.78
            ),
            
            # Signal handler race (CVE-2019-18683)
            RacePattern(
                pattern_id="signal_race",
                cve_reference="CVE-2019-18683",
                race_type=RaceType.SIGNAL_RACE,
                vulnerable_functions=["do_signal", "get_signal"],
                temporal_signature={"signal_delivery": True, "handler_race": True},
                risk_score=0.83
            )
        ]
    
    def start_kernel_tracing(self, target_functions: List[str] = None) -> bool:
        """Start kernel tracing with ftrace"""
        if not self.use_ftrace:
            return True
            
        try:
            # Enable function graph tracing
            subprocess.run([
                "sudo", "sh", "-c", 
                "echo function_graph > /sys/kernel/debug/tracing/current_tracer"
            ], check=True)
            
            # Enable syscall events
            subprocess.run([
                "sudo", "sh", "-c",
                "echo 1 > /sys/kernel/debug/tracing/events/syscalls/enable"
            ], check=True)
            
            # Set up specific function probes if specified
            if target_functions:
                for func in target_functions:
                    subprocess.run([
                        "sudo", "sh", "-c",
                        f"echo 'p:{func}_probe {func}' >> /sys/kernel/debug/tracing/kprobe_events"
                    ], check=True)
            
            logger.info("✅ Kernel tracing started successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to start kernel tracing: {e}")
            return False
    
    def collect_kernel_events(self, duration: float = 10.0) -> List[KernelEvent]:
        """Collect kernel events from ftrace"""
        events = []
        
        if not self.use_ftrace:
            # Return synthetic events for testing
            return self._generate_synthetic_events()
        
        try:
            # Start collecting trace data
            process = subprocess.Popen([
                "sudo", "cat", "/sys/kernel/debug/tracing/trace_pipe"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            start_time = time.time()
            
            while time.time() - start_time < duration:
                line = process.stdout.readline()
                if line:
                    event = self._parse_ftrace_line(line)
                    if event:
                        events.append(event)
            
            process.terminate()
            
        except Exception as e:
            logger.error(f"❌ Error collecting kernel events: {e}")
        
        return events
    
    def _generate_synthetic_events(self) -> List[KernelEvent]:
        """Generate synthetic kernel events for testing"""
        events = []
        base_time = time.time()
        
        # Simulate use-after-free race condition
        events.extend([
            KernelEvent(
                timestamp=base_time,
                thread_id=1001,
                function_name="kmalloc",
                event_type="memory_alloc",
                memory_address=0xffff8800deadbeef
            ),
            KernelEvent(
                timestamp=base_time + 0.001,
                thread_id=1001,
                function_name="kernel_file_release_race",
                event_type="function_entry",
                memory_address=0xffff8800deadbeef
            ),
            KernelEvent(
                timestamp=base_time + 0.002,
                thread_id=1002,
                function_name="atomic_dec",
                event_type="memory_access",
                memory_address=0xffff8800deadbeef
            ),
            KernelEvent(
                timestamp=base_time + 0.003,
                thread_id=1001,
                function_name="kfree",
                event_type="memory_free",
                memory_address=0xffff8800deadbeef
            ),
            KernelEvent(
                timestamp=base_time + 0.004,
                thread_id=1002,
                function_name="use_after_free_access",
                event_type="memory_access",
                memory_address=0xffff8800deadbeef  # Use after free!
            )
        ])
        
        return events
    
    def _parse_ftrace_line(self, line: str) -> Optional[KernelEvent]:
        """Parse ftrace output line into KernelEvent"""
        # Simplified ftrace parsing (real implementation would be more robust)
        parts = line.strip().split()
        if len(parts) < 4:
            return None
        
        try:
            # Extract basic information
            comm_pid = parts[0]
            timestamp = float(parts[2].rstrip(':'))
            function_info = ' '.join(parts[3:])
            
            # Extract PID
            pid_match = re.search(r'-(\d+)', comm_pid)
            thread_id = int(pid_match.group(1)) if pid_match else 0
            
            # Extract function name
            func_match = re.search(r'(\w+)\s*\(', function_info)
            function_name = func_match.group(1) if func_match else "unknown"
            
            return KernelEvent(
                timestamp=timestamp,
                thread_id=thread_id,
                function_name=function_name,
                event_type="function_call"
            )
            
        except (ValueError, IndexError):
            return None
    
    def analyze_kernel_races(self, events: List[KernelEvent]) -> Dict:
        """Analyze kernel events for race conditions"""
        logger.info(f"🔍 Analyzing {len(events)} kernel events for race conditions...")
        
        # Build happens-before graph
        hb_graph = HappensBeforeGraph()
        
        for event in events:
            hb_graph.add_event(event)
        
        # Build temporal and synchronization edges
        hb_graph.build_temporal_edges()
        hb_graph.build_synchronization_edges()
        
        # Detect races using graph analysis
        detected_races = hb_graph.detect_race_conditions()
        
        # Analyze with temporal neural network
        tgnn_analysis = self._analyze_with_tgnn(events, hb_graph)
        
        # Combine results
        analysis_result = {
            "timestamp": time.time(),
            "total_events": len(events),
            "detected_races": detected_races,
            "tgnn_analysis": tgnn_analysis,
            "risk_assessment": self._calculate_race_risk(detected_races),
            "recommendations": self._generate_race_recommendations(detected_races)
        }
        
        return analysis_result
    
    def _analyze_with_tgnn(self, events: List[KernelEvent], hb_graph: HappensBeforeGraph) -> Dict:
        """Analyze events using Temporal Graph Neural Network"""
        # Create node features for events
        node_features = []
        for event in events:
            # Create feature vector for each event
            feature = torch.zeros(128)
            
            # Encode function name (simplified)
            func_hash = hash(event.function_name) % 100
            feature[func_hash] = 1.0
            
            # Encode event type
            type_map = {"memory_alloc": 1, "memory_free": 2, "memory_access": 3, "function_call": 4}
            if event.event_type in type_map:
                feature[100 + type_map[event.event_type]] = 1.0
            
            # Encode timestamp (normalized)
            feature[110] = event.timestamp % 1.0
            
            node_features.append(feature)
        
        if not node_features:
            return {"race_probability": 0.0, "race_types": []}
        
        # Convert to tensor
        x = torch.stack(node_features)
        
        # Create edge index from happens-before graph
        edge_list = [(e[0], e[1]) for e in hb_graph.edges]
        if edge_list:
            edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.empty((2, 0), dtype=torch.long)
        
        # Run TGNN analysis
        with torch.no_grad():
            race_binary, race_type = self.tgnn_model(x, edge_index)
            race_prob = torch.softmax(race_binary, dim=1)[:, 1].mean().item()
            race_type_probs = torch.softmax(race_type, dim=1).mean(dim=0)
        
        return {
            "race_probability": race_prob,
            "race_type_probabilities": race_type_probs.tolist(),
            "confidence": max(race_type_probs).item()
        }
    
    def _calculate_race_risk(self, detected_races: List[Dict]) -> float:
        """Calculate overall race condition risk"""
        if not detected_races:
            return 0.0
        
        total_risk = sum(race["risk_score"] for race in detected_races)
        max_risk = max(race["risk_score"] for race in detected_races)
        
        # Weighted combination
        return min(1.0, 0.7 * max_risk + 0.3 * (total_risk / len(detected_races)))
    
    def _generate_race_recommendations(self, detected_races: List[Dict]) -> List[str]:
        """Generate recommendations for detected race conditions"""
        recommendations = []
        
        if not detected_races:
            return ["✅ No race conditions detected"]
        
        race_types = set(race["race_type"] for race in detected_races)
        
        if RaceType.USE_AFTER_FREE in race_types:
            recommendations.extend([
                "🚨 CRITICAL: Use-after-free race detected",
                "🔒 Implement proper reference counting",
                "🛡️ Add memory safety checks"
            ])
        
        if RaceType.TOCTOU in race_types:
            recommendations.extend([
                "⚠️ TOCTOU race detected",
                "🔐 Use atomic operations for check-and-use",
                "🚫 Minimize time gap between check and use"
            ])
        
        recommendations.append(f"📊 Total races detected: {len(detected_races)}")
        
        return recommendations

# Test function
def test_kernel_race_detector():
    """Test the kernel race detector"""
    print("🧪 Testing Kernel Race Detector...")
    
    detector = KernelRaceDetector(use_ftrace=False)  # Use synthetic events
    
    # Collect synthetic events
    events = detector.collect_kernel_events(duration=1.0)
    print(f"📊 Collected {len(events)} kernel events")
    
    # Analyze for races
    result = detector.analyze_kernel_races(events)
    
    print(f"📈 Kernel Race Analysis Results:")
    print(f"   Total Events: {result['total_events']}")
    print(f"   Detected Races: {len(result['detected_races'])}")
    print(f"   Risk Assessment: {result['risk_assessment']:.4f}")
    print(f"   TGNN Race Probability: {result['tgnn_analysis']['race_probability']:.4f}")
    
    if result['detected_races']:
        print(f"🚨 Race Details:")
        for race in result['detected_races']:
            print(f"   - {race['race_type'].value}: Risk {race['risk_score']:.2f}")
            print(f"     Functions: {race['event1']['function']} → {race['event2']['function']}")
    
    return result

if __name__ == "__main__":
    test_kernel_race_detector()