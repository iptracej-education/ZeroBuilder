#!/usr/bin/env python3
"""
ZeroBuilder Step 2: Happens-Before Graph Analyzer
Build temporal relationships between kernel events for race detection
"""

import time
import logging
import networkx as nx
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
import json

from .ftrace_integration import FtraceEvent
from .ebpf_tracer import BPFEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class HappensBeforeRelation:
    """Represents a happens-before relationship between two events"""
    event_a: str  # Event ID
    event_b: str  # Event ID
    relation_type: str  # 'program_order', 'synchronization', 'transitive'
    confidence: float
    evidence: List[str] = field(default_factory=list)

@dataclass
class RaceViolation:
    """Represents a violation of happens-before ordering (potential race)"""
    event1: str
    event2: str
    resource: str  # What resource they're racing for
    violation_type: str  # 'data_race', 'toctou', 'use_after_free'
    severity: str  # 'critical', 'high', 'medium', 'low'
    explanation: str
    confidence: float

class HappensBeforeAnalyzer:
    """Analyze kernel events to build happens-before graphs and detect races"""
    
    def __init__(self):
        self.events: Dict[str, Dict] = {}  # event_id -> event data
        self.happens_before_graph = nx.DiGraph()
        self.relations: List[HappensBeforeRelation] = []
        self.race_violations: List[RaceViolation] = []
        
        # Resource tracking for race detection
        self.file_operations: Dict[str, List[str]] = {}  # file -> [event_ids]
        self.memory_operations: Dict[str, List[str]] = {}  # address -> [event_ids]
        self.process_threads: Dict[int, List[str]] = {}  # pid -> [event_ids]
        
        logger.info("🔧 Happens-Before Analyzer initialized")
    
    def add_ftrace_events(self, ftrace_events: List[FtraceEvent]) -> int:
        """Add ftrace events to the analysis"""
        added = 0
        
        for event in ftrace_events:
            event_id = f"ftrace_{event.pid}_{event.timestamp}_{len(self.events)}"
            
            event_data = {
                "id": event_id,
                "type": "ftrace",
                "timestamp": event.timestamp,
                "pid": event.pid,
                "cpu": event.cpu,
                "function": event.function,
                "call_type": event.call_type,
                "source": "ftrace"
            }
            
            self.events[event_id] = event_data
            self.happens_before_graph.add_node(event_id, **event_data)
            
            # Track by process
            if event.pid not in self.process_threads:
                self.process_threads[event.pid] = []
            self.process_threads[event.pid].append(event_id)
            
            added += 1
        
        logger.info(f"📊 Added {added} ftrace events to happens-before analysis")
        return added
    
    def add_bpf_events(self, bpf_events: List[BPFEvent]) -> int:
        """Add eBPF events to the analysis"""
        added = 0
        
        for event in bpf_events:
            event_id = f"bpf_{event.pid}_{event.timestamp}_{len(self.events)}"
            
            event_data = {
                "id": event_id,
                "type": "bpf",
                "timestamp": event.timestamp,
                "pid": event.pid,
                "tid": event.tid,
                "cpu": event.cpu,
                "comm": event.comm,
                "event_type": event.event_type,
                "syscall_name": event.syscall_name,
                "return_value": event.return_value,
                "source": "ebpf"
            }
            
            self.events[event_id] = event_data
            self.happens_before_graph.add_node(event_id, **event_data)
            
            # Track by process/thread
            if event.pid not in self.process_threads:
                self.process_threads[event.pid] = []
            self.process_threads[event.pid].append(event_id)
            
            # Track file operations for race detection
            if event.syscall_name in ["open", "openat", "read", "write", "close"]:
                # Simplified - in real implementation we'd extract file path from args
                file_key = f"file_{event.pid}_{event.syscall_name}"
                if file_key not in self.file_operations:
                    self.file_operations[file_key] = []
                self.file_operations[file_key].append(event_id)
            
            added += 1
        
        logger.info(f"📊 Added {added} eBPF events to happens-before analysis")
        return added
    
    def build_happens_before_relations(self) -> List[HappensBeforeRelation]:
        """Build happens-before relationships between events"""
        self.relations = []
        
        # 1. Program order relations (within same thread)
        self._build_program_order_relations()
        
        # 2. Synchronization relations (across threads/processes)
        self._build_synchronization_relations()
        
        # 3. Transitive relations (happens-before is transitive)
        self._build_transitive_relations()
        
        # Add relations to graph
        for relation in self.relations:
            self.happens_before_graph.add_edge(
                relation.event_a, 
                relation.event_b,
                relation_type=relation.relation_type,
                confidence=relation.confidence
            )
        
        logger.info(f"🔗 Built {len(self.relations)} happens-before relations")
        return self.relations
    
    def _build_program_order_relations(self):
        """Build program order relations within each thread"""
        for pid, event_ids in self.process_threads.items():
            if len(event_ids) < 2:
                continue
            
            # Sort events by timestamp within thread
            sorted_events = sorted(event_ids, key=lambda eid: self.events[eid]["timestamp"])
            
            # Each event happens-before the next in program order
            for i in range(len(sorted_events) - 1):
                event_a = sorted_events[i]
                event_b = sorted_events[i + 1]
                
                relation = HappensBeforeRelation(
                    event_a=event_a,
                    event_b=event_b,
                    relation_type="program_order",
                    confidence=1.0,
                    evidence=[f"Same thread PID {pid}, sequential execution"]
                )
                self.relations.append(relation)
    
    def _build_synchronization_relations(self):
        """Build synchronization relations across threads"""
        # Look for synchronization patterns
        
        # File-based synchronization (simplified)
        for file_key, event_ids in self.file_operations.items():
            if len(event_ids) < 2:
                continue
            
            # Sort by timestamp
            sorted_events = sorted(event_ids, key=lambda eid: self.events[eid]["timestamp"])
            
            # File operations are typically synchronized
            for i in range(len(sorted_events) - 1):
                event_a = sorted_events[i]
                event_b = sorted_events[i + 1]
                
                # Different processes accessing same file
                if self.events[event_a]["pid"] != self.events[event_b]["pid"]:
                    relation = HappensBeforeRelation(
                        event_a=event_a,
                        event_b=event_b,
                        relation_type="synchronization",
                        confidence=0.8,  # Not guaranteed synchronization
                        evidence=[f"File operation synchronization on {file_key}"]
                    )
                    self.relations.append(relation)
        
        # System call ordering (kernel serialization)
        syscall_events = [eid for eid in self.events.keys() 
                         if self.events[eid].get("syscall_name")]
        
        # Group by syscall type
        syscall_groups = {}
        for event_id in syscall_events:
            syscall = self.events[event_id]["syscall_name"]
            if syscall not in syscall_groups:
                syscall_groups[syscall] = []
            syscall_groups[syscall].append(event_id)
        
        # Some syscalls are serialized by the kernel
        serialized_syscalls = ["open", "close", "mmap", "munmap"]
        
        for syscall in serialized_syscalls:
            if syscall not in syscall_groups:
                continue
            
            events = sorted(syscall_groups[syscall], 
                          key=lambda eid: self.events[eid]["timestamp"])
            
            for i in range(len(events) - 1):
                event_a = events[i]
                event_b = events[i + 1]
                
                relation = HappensBeforeRelation(
                    event_a=event_a,
                    event_b=event_b,
                    relation_type="synchronization",
                    confidence=0.9,
                    evidence=[f"Kernel serialization of {syscall} syscalls"]
                )
                self.relations.append(relation)
    
    def _build_transitive_relations(self):
        """Build transitive happens-before relations"""
        # Happens-before is transitive: if A->B and B->C, then A->C
        
        # Build adjacency for efficient transitive closure
        direct_relations = {}
        for relation in self.relations:
            if relation.event_a not in direct_relations:
                direct_relations[relation.event_a] = []
            direct_relations[relation.event_a].append(relation.event_b)
        
        # Find transitive relations (limited depth to avoid explosion)
        max_depth = 3
        transitive_relations = []
        
        for start_event in direct_relations:
            visited = set()
            self._find_transitive_paths(start_event, direct_relations, visited, 
                                      [], transitive_relations, max_depth)
        
        # Add significant transitive relations
        for path in transitive_relations:
            if len(path) >= 3:  # At least A->B->C
                relation = HappensBeforeRelation(
                    event_a=path[0],
                    event_b=path[-1],
                    relation_type="transitive",
                    confidence=0.6,  # Lower confidence for transitive
                    evidence=[f"Transitive path: {' -> '.join(path[:3])}..."]
                )
                self.relations.append(relation)
    
    def _find_transitive_paths(self, current: str, graph: Dict, visited: Set, 
                             path: List, results: List, max_depth: int):
        """Recursively find transitive paths"""
        if len(path) >= max_depth or current in visited:
            return
        
        visited.add(current)
        path.append(current)
        
        if len(path) >= 3:  # Found a transitive path
            results.append(path.copy())
        
        # Continue exploring
        if current in graph:
            for next_event in graph[current]:
                self._find_transitive_paths(next_event, graph, visited, 
                                          path, results, max_depth)
        
        path.pop()
        visited.remove(current)
    
    def detect_race_violations(self) -> List[RaceViolation]:
        """Detect race condition violations in the happens-before graph"""
        self.race_violations = []
        
        # 1. Data race detection
        self._detect_data_races()
        
        # 2. TOCTOU race detection
        self._detect_toctou_races()
        
        # 3. Use-after-free detection
        self._detect_uaf_races()
        
        logger.info(f"🔍 Detected {len(self.race_violations)} race violations")
        return self.race_violations
    
    def _detect_data_races(self):
        """Detect data races (concurrent access to shared data)"""
        # Look for concurrent operations on same resources
        for resource, event_ids in self.file_operations.items():
            if len(event_ids) < 2:
                continue
            
            # Check for concurrent access without happens-before relation
            for i in range(len(event_ids)):
                for j in range(i + 1, len(event_ids)):
                    event1_id = event_ids[i]
                    event2_id = event_ids[j]
                    
                    event1 = self.events[event1_id]
                    event2 = self.events[event2_id]
                    
                    # Different processes
                    if event1["pid"] == event2["pid"]:
                        continue
                    
                    # Check if there's a happens-before relation
                    if (self.happens_before_graph.has_edge(event1_id, event2_id) or
                        self.happens_before_graph.has_edge(event2_id, event1_id)):
                        continue  # Properly ordered
                    
                    # Check for write operations (more dangerous)
                    is_write_race = (
                        event1.get("syscall_name") in ["write", "open"] or
                        event2.get("syscall_name") in ["write", "open"]
                    )
                    
                    # Close in time (potential race)
                    time_diff = abs(event1["timestamp"] - event2["timestamp"])
                    if time_diff < 0.001:  # Within 1ms
                        violation = RaceViolation(
                            event1=event1_id,
                            event2=event2_id,
                            resource=resource,
                            violation_type="data_race",
                            severity="high" if is_write_race else "medium",
                            explanation=f"Concurrent access to {resource} without synchronization",
                            confidence=0.7 if is_write_race else 0.5
                        )
                        self.race_violations.append(violation)
    
    def _detect_toctou_races(self):
        """Detect Time-of-Check-Time-of-Use races"""
        # Look for check-then-use patterns
        check_syscalls = ["access", "stat", "lstat"]
        use_syscalls = ["open", "openat", "read", "write"]
        
        for pid, event_ids in self.process_threads.items():
            events = [self.events[eid] for eid in event_ids]
            events.sort(key=lambda e: e["timestamp"])
            
            for i in range(len(events) - 1):
                check_event = events[i]
                use_event = events[i + 1]
                
                # Check syscall followed by use syscall
                if (check_event.get("syscall_name") in check_syscalls and
                    use_event.get("syscall_name") in use_syscalls):
                    
                    time_gap = use_event["timestamp"] - check_event["timestamp"]
                    
                    # TOCTOU window (between check and use)
                    if 0.0001 < time_gap < 0.01:  # 0.1ms to 10ms window
                        violation = RaceViolation(
                            event1=check_event["id"],
                            event2=use_event["id"],
                            resource=f"file_operation_pid_{pid}",
                            violation_type="toctou",
                            severity="high",
                            explanation=f"TOCTOU race: {check_event['syscall_name']} followed by {use_event['syscall_name']} with {time_gap:.4f}s gap",
                            confidence=0.8
                        )
                        self.race_violations.append(violation)
    
    def _detect_uaf_races(self):
        """Detect Use-After-Free races"""
        # Look for free followed by use patterns
        for pid, event_ids in self.process_threads.items():
            events = [self.events[eid] for eid in event_ids]
            events.sort(key=lambda e: e["timestamp"])
            
            for i in range(len(events) - 1):
                free_event = events[i]
                use_event = events[i + 1]
                
                # Free followed by potential use
                if (free_event.get("function") in ["kfree", "vfree", "free"] or
                    free_event.get("syscall_name") == "close"):
                    
                    # Look for subsequent access
                    if (use_event.get("function") and "access" in use_event.get("function", "") or
                        use_event.get("syscall_name") in ["read", "write"]):
                        
                        time_gap = use_event["timestamp"] - free_event["timestamp"]
                        
                        if time_gap < 0.01:  # Within 10ms
                            violation = RaceViolation(
                                event1=free_event["id"],
                                event2=use_event["id"],
                                resource=f"memory_or_fd_{pid}",
                                violation_type="use_after_free",
                                severity="critical",
                                explanation=f"Potential use-after-free: {free_event.get('function', free_event.get('syscall_name'))} followed by {use_event.get('function', use_event.get('syscall_name'))}",
                                confidence=0.6
                            )
                            self.race_violations.append(violation)
    
    def generate_analysis_report(self) -> Dict:
        """Generate comprehensive happens-before analysis report"""
        if not self.relations:
            self.build_happens_before_relations()
        
        if not self.race_violations:
            self.detect_race_violations()
        
        # Graph analysis
        graph_metrics = {
            "nodes": self.happens_before_graph.number_of_nodes(),
            "edges": self.happens_before_graph.number_of_edges(),
            "weakly_connected_components": nx.number_weakly_connected_components(self.happens_before_graph),
            "is_dag": nx.is_directed_acyclic_graph(self.happens_before_graph)
        }
        
        # Relation analysis
        relation_types = {}
        for relation in self.relations:
            if relation.relation_type not in relation_types:
                relation_types[relation.relation_type] = 0
            relation_types[relation.relation_type] += 1
        
        # Violation analysis
        violation_types = {}
        severity_counts = {}
        for violation in self.race_violations:
            # Count by type
            if violation.violation_type not in violation_types:
                violation_types[violation.violation_type] = 0
            violation_types[violation.violation_type] += 1
            
            # Count by severity
            if violation.severity not in severity_counts:
                severity_counts[violation.severity] = 0
            severity_counts[violation.severity] += 1
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "analysis_summary": {
                "total_events": len(self.events),
                "total_relations": len(self.relations),
                "total_violations": len(self.race_violations),
                "processes_analyzed": len(self.process_threads),
                "resources_tracked": len(self.file_operations) + len(self.memory_operations)
            },
            "graph_metrics": graph_metrics,
            "relation_breakdown": relation_types,
            "violation_breakdown": violation_types,
            "severity_breakdown": severity_counts,
            "critical_violations": [
                {
                    "violation_type": v.violation_type,
                    "severity": v.severity,
                    "confidence": v.confidence,
                    "explanation": v.explanation,
                    "resource": v.resource
                }
                for v in self.race_violations 
                if v.severity in ["critical", "high"]
            ][:10]  # Top 10 critical violations
        }
        
        return report
    
    def export_graph(self, output_path: str = "happens_before_graph.json") -> bool:
        """Export happens-before graph for visualization"""
        try:
            # Convert graph to JSON-serializable format
            graph_data = {
                "nodes": [
                    {
                        "id": node,
                        **self.happens_before_graph.nodes[node]
                    }
                    for node in self.happens_before_graph.nodes()
                ],
                "edges": [
                    {
                        "source": edge[0],
                        "target": edge[1],
                        **self.happens_before_graph.edges[edge]
                    }
                    for edge in self.happens_before_graph.edges()
                ],
                "violations": [
                    {
                        "event1": v.event1,
                        "event2": v.event2,
                        "type": v.violation_type,
                        "severity": v.severity,
                        "confidence": v.confidence,
                        "explanation": v.explanation
                    }
                    for v in self.race_violations
                ]
            }
            
            with open(output_path, 'w') as f:
                json.dump(graph_data, f, indent=2, default=str)
            
            logger.info(f"📁 Exported happens-before graph to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to export graph: {e}")
            return False

def main():
    """Test happens-before analysis"""
    logger.info("🚀 Testing ZeroBuilder Happens-Before Analysis")
    logger.info("=" * 60)
    
    # Initialize analyzer
    analyzer = HappensBeforeAnalyzer()
    
    # Create some test events
    from .ftrace_integration import FtraceManager
    from .ebpf_tracer import eBPFTracer
    
    logger.info("\n🔧 Generating test events...")
    
    # Get ftrace events (simulated)
    ftrace_mgr = FtraceManager()
    ftrace_mgr.setup_function_tracing()
    ftrace_mgr.start_tracing()
    time.sleep(1)
    ftrace_mgr.stop_tracing()
    ftrace_events = ftrace_mgr.collect_trace_data()
    
    # Get eBPF events (simulated)
    ebpf_tracer = eBPFTracer()
    ebpf_tracer.start_tracing(2)
    
    # Add events to analyzer
    logger.info("\n📊 Adding events to happens-before analyzer...")
    analyzer.add_ftrace_events(ftrace_events)
    analyzer.add_bpf_events(ebpf_tracer.events)
    
    # Build happens-before relations
    logger.info("\n🔗 Building happens-before relations...")
    relations = analyzer.build_happens_before_relations()
    
    # Detect race violations
    logger.info("\n🔍 Detecting race violations...")
    violations = analyzer.detect_race_violations()
    
    # Generate report
    logger.info("\n📋 Generating analysis report...")
    report = analyzer.generate_analysis_report()
    
    # Export graph
    logger.info("\n📁 Exporting happens-before graph...")
    analyzer.export_graph("test_happens_before_graph.json")
    
    logger.info(f"\n" + "=" * 60)
    logger.info("📊 HAPPENS-BEFORE ANALYSIS RESULTS")
    logger.info("=" * 60)
    
    summary = report["analysis_summary"]
    logger.info(f"Total Events: {summary['total_events']}")
    logger.info(f"Happens-Before Relations: {summary['total_relations']}")
    logger.info(f"Race Violations: {summary['total_violations']}")
    logger.info(f"Processes Analyzed: {summary['processes_analyzed']}")
    
    if report["relation_breakdown"]:
        logger.info(f"\n🔗 Relation Types:")
        for rel_type, count in report["relation_breakdown"].items():
            logger.info(f"  {rel_type}: {count}")
    
    if report["violation_breakdown"]:
        logger.info(f"\n⚠️ Violation Types:")
        for viol_type, count in report["violation_breakdown"].items():
            logger.info(f"  {viol_type}: {count}")
    
    if report["severity_breakdown"]:
        logger.info(f"\n🚨 Severity Levels:")
        for severity, count in report["severity_breakdown"].items():
            logger.info(f"  {severity}: {count}")
    
    if report["critical_violations"]:
        logger.info(f"\n🔥 Critical Violations:")
        for i, violation in enumerate(report["critical_violations"][:3], 1):
            logger.info(f"  {i}. {violation['violation_type'].upper()} ({violation['severity']})")
            logger.info(f"     Confidence: {violation['confidence']:.2f}")
            logger.info(f"     {violation['explanation']}")
    
    graph_metrics = report["graph_metrics"]
    logger.info(f"\n📈 Graph Properties:")
    logger.info(f"  Nodes: {graph_metrics['nodes']}")
    logger.info(f"  Edges: {graph_metrics['edges']}")
    logger.info(f"  Is DAG: {graph_metrics['is_dag']}")
    logger.info(f"  Connected Components: {graph_metrics['weakly_connected_components']}")
    
    logger.info(f"\n✅ Happens-before analysis complete!")
    logger.info(f"🎯 Ready for integration with enhanced kernel race detector")

if __name__ == "__main__":
    main()