#!/usr/bin/env python3
"""
Linux Kernel Race Condition Discovery System
Advanced temporal analysis and happens-before graph construction for unknown race discovery
"""

import time
import threading
import queue
import random
import networkx as nx
import numpy as np
from typing import Dict, List, Tuple, Set, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KernelSubsystem(Enum):
    """Major Linux kernel subsystems prone to race conditions"""
    MEMORY_MANAGEMENT = "mm"
    FILE_SYSTEM = "fs" 
    NETWORK = "net"
    DEVICE_DRIVERS = "drivers"
    PROCESS_SCHEDULER = "kernel/sched"
    SIGNAL_HANDLING = "kernel/signal"
    MODULE_LOADER = "kernel/module"
    IPC = "ipc"
    SECURITY = "security"
    CRYPTO = "crypto"

class RaceType(Enum):
    """Types of race conditions in kernel code"""
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    TOCTOU = "time_of_check_time_of_use"
    DATA_RACE = "data_race"
    DEADLOCK = "deadlock"
    LIVELOCK = "livelock"
    MEMORY_ORDERING = "memory_ordering"
    REFERENCE_COUNTING = "reference_counting"
    SIGNAL_HANDLING = "signal_handling"
    INTERRUPT_CONTEXT = "interrupt_context"

class KernelOperation(Enum):
    """Kernel operations that can participate in races"""
    KMALLOC = "kmalloc"
    KFREE = "kfree"
    MUTEX_LOCK = "mutex_lock"
    MUTEX_UNLOCK = "mutex_unlock"
    SPIN_LOCK = "spin_lock"
    SPIN_UNLOCK = "spin_unlock"
    ATOMIC_INC = "atomic_inc"
    ATOMIC_DEC = "atomic_dec"
    COPY_FROM_USER = "copy_from_user"
    COPY_TO_USER = "copy_to_user"
    GET_USER = "get_user"
    PUT_USER = "put_user"
    IRQ_SAVE = "irq_save"
    IRQ_RESTORE = "irq_restore"
    SCHEDULE = "schedule"
    WAKE_UP = "wake_up"
    SIGNAL_PENDING = "signal_pending"
    FILE_OPERATIONS = "file_ops"

@dataclass
class KernelEvent:
    """Represents a kernel event in execution trace"""
    timestamp: float
    thread_id: int
    cpu_id: int
    operation: KernelOperation
    subsystem: KernelSubsystem
    memory_address: Optional[int] = None
    object_id: Optional[str] = None
    lock_id: Optional[str] = None
    return_value: Optional[int] = None
    context: str = "kernel"  # kernel, interrupt, user
    call_stack: List[str] = field(default_factory=list)

@dataclass
class HappensBeforeRelation:
    """Represents happens-before relationship between events"""
    event1: KernelEvent
    event2: KernelEvent
    relation_type: str  # "sync", "async", "memory", "lock"
    strength: float  # 0.0 to 1.0, confidence in relation

@dataclass
class RaceCondition:
    """Detected race condition with detailed analysis"""
    race_type: RaceType
    subsystem: KernelSubsystem
    conflicting_events: List[KernelEvent]
    happens_before_violations: List[HappensBeforeRelation]
    risk_level: str
    exploitability: str
    evidence: List[str]
    affected_code_patterns: List[str]
    mitigation_suggestions: List[str]
    temporal_window_ms: float
    probability_score: float

class KernelRaceDiscovery:
    """Advanced system for discovering unknown kernel race conditions"""
    
    def __init__(self):
        self.execution_traces = []
        self.happens_before_graph = nx.DiGraph()
        self.discovered_races = []
        self.subsystem_analysis = {}
        self.known_race_patterns = self._load_known_patterns()
        self.temporal_analyzer = TemporalAnalyzer()
        
    def _load_known_patterns(self) -> Dict[RaceType, List[str]]:
        """Load known race condition patterns for comparison"""
        return {
            RaceType.USE_AFTER_FREE: [
                "kfree.*followed.*by.*access",
                "reference.*count.*zero.*access",
                "object.*freed.*still.*referenced",
                "dangling.*pointer.*dereference"
            ],
            RaceType.DOUBLE_FREE: [
                "kfree.*called.*twice",
                "double.*free.*same.*object",
                "freed.*memory.*freed.*again"
            ],
            RaceType.TOCTOU: [
                "check.*use.*time.*gap",
                "access.*validation.*race",
                "file.*permissions.*check.*use",
                "capability.*check.*use.*gap"
            ],
            RaceType.DATA_RACE: [
                "concurrent.*write.*same.*location",
                "unsynchronized.*shared.*variable",
                "atomic.*operation.*missing"
            ],
            RaceType.DEADLOCK: [
                "lock.*ordering.*violation",
                "circular.*wait.*dependency",
                "nested.*lock.*deadlock"
            ],
            RaceType.REFERENCE_COUNTING: [
                "refcount.*increment.*decrement.*race",
                "get.*put.*reference.*race",
                "object.*lifetime.*race"
            ],
            RaceType.SIGNAL_HANDLING: [
                "signal.*delivery.*race",
                "signal.*mask.*race",
                "sigpending.*check.*race"
            ]
        }
    
    def generate_kernel_execution_traces(self, num_traces: int = 1000) -> List[List[KernelEvent]]:
        """Generate synthetic but realistic kernel execution traces"""
        traces = []
        
        # Common kernel execution patterns
        patterns = [
            self._generate_memory_allocation_trace,
            self._generate_file_operation_trace,
            self._generate_network_packet_trace,
            self._generate_signal_handling_trace,
            self._generate_module_loading_trace,
            self._generate_device_driver_trace
        ]
        
        for i in range(num_traces):
            pattern = random.choice(patterns)
            trace = pattern(trace_id=i)
            traces.append(trace)
            
        logger.info(f"Generated {len(traces)} kernel execution traces")
        return traces
    
    def _generate_memory_allocation_trace(self, trace_id: int) -> List[KernelEvent]:
        """Generate memory allocation/deallocation trace with potential races"""
        events = []
        base_time = time.time()
        
        # Simulate kmalloc/kfree operations with potential UAF
        for i in range(random.randint(5, 15)):
            # Allocation
            alloc_event = KernelEvent(
                timestamp=base_time + i * 0.001 + random.uniform(0, 0.0005),
                thread_id=random.randint(1, 4),
                cpu_id=random.randint(0, 3),
                operation=KernelOperation.KMALLOC,
                subsystem=KernelSubsystem.MEMORY_MANAGEMENT,
                memory_address=0x12340000 + i * 0x1000,
                object_id=f"obj_{trace_id}_{i}",
                call_stack=[f"mm/slab.c:kmalloc", f"subsystem_alloc_{i}"]
            )
            events.append(alloc_event)
            
            # Some operations on the allocated memory
            if random.random() > 0.3:
                access_event = KernelEvent(
                    timestamp=alloc_event.timestamp + random.uniform(0.0001, 0.001),
                    thread_id=alloc_event.thread_id,
                    cpu_id=alloc_event.cpu_id,
                    operation=KernelOperation.COPY_TO_USER,
                    subsystem=alloc_event.subsystem,
                    memory_address=alloc_event.memory_address,
                    object_id=alloc_event.object_id,
                    call_stack=[f"mm/memory.c:copy_to_user", "user_access"]
                )
                events.append(access_event)
            
            # Deallocation - potentially racy
            if random.random() > 0.2:
                free_event = KernelEvent(
                    timestamp=alloc_event.timestamp + random.uniform(0.002, 0.01),
                    thread_id=random.randint(1, 4),  # Different thread = potential race
                    cpu_id=random.randint(0, 3),
                    operation=KernelOperation.KFREE,
                    subsystem=KernelSubsystem.MEMORY_MANAGEMENT,
                    memory_address=alloc_event.memory_address,
                    object_id=alloc_event.object_id,
                    call_stack=[f"mm/slab.c:kfree", f"subsystem_free_{i}"]
                )
                events.append(free_event)
                
                # Potential use-after-free
                if random.random() > 0.7:
                    uaf_event = KernelEvent(
                        timestamp=free_event.timestamp + random.uniform(0.0001, 0.002),
                        thread_id=random.randint(1, 4),
                        cpu_id=random.randint(0, 3),
                        operation=KernelOperation.COPY_FROM_USER,
                        subsystem=alloc_event.subsystem,
                        memory_address=alloc_event.memory_address,
                        object_id=alloc_event.object_id,
                        call_stack=["use_after_free_access", "vulnerable_function"]
                    )
                    events.append(uaf_event)
        
        return sorted(events, key=lambda x: x.timestamp)
    
    def _generate_file_operation_trace(self, trace_id: int) -> List[KernelEvent]:
        """Generate file system operation trace with TOCTOU potential"""
        events = []
        base_time = time.time()
        
        # TOCTOU pattern: check permissions, then use
        check_event = KernelEvent(
            timestamp=base_time,
            thread_id=1,
            cpu_id=0,
            operation=KernelOperation.FILE_OPERATIONS,
            subsystem=KernelSubsystem.FILE_SYSTEM,
            object_id=f"file_{trace_id}",
            call_stack=["fs/namei.c:permission", "security_check"]
        )
        events.append(check_event)
        
        # Gap where file permissions could change
        use_event = KernelEvent(
            timestamp=base_time + random.uniform(0.001, 0.01),  # Time gap
            thread_id=check_event.thread_id,
            cpu_id=check_event.cpu_id,
            operation=KernelOperation.FILE_OPERATIONS,
            subsystem=KernelSubsystem.FILE_SYSTEM,
            object_id=check_event.object_id,
            call_stack=["fs/read_write.c:vfs_read", "file_access"]
        )
        events.append(use_event)
        
        return events
    
    def _generate_signal_handling_trace(self, trace_id: int) -> List[KernelEvent]:
        """Generate signal handling trace with race potential"""
        events = []
        base_time = time.time()
        
        # Signal pending check
        check_signal = KernelEvent(
            timestamp=base_time,
            thread_id=1,
            cpu_id=0,
            operation=KernelOperation.SIGNAL_PENDING,
            subsystem=KernelSubsystem.SIGNAL_HANDLING,
            object_id=f"task_{trace_id}",
            call_stack=["kernel/signal.c:signal_pending", "syscall_entry"]
        )
        events.append(check_signal)
        
        # Signal delivery from different context
        deliver_signal = KernelEvent(
            timestamp=base_time + random.uniform(0.0001, 0.001),
            thread_id=2,  # Different thread/context
            cpu_id=1,
            operation=KernelOperation.SIGNAL_PENDING,
            subsystem=KernelSubsystem.SIGNAL_HANDLING,
            object_id=check_signal.object_id,
            context="interrupt",
            call_stack=["kernel/signal.c:send_signal", "signal_delivery"]
        )
        events.append(deliver_signal)
        
        return events
    
    def _generate_network_packet_trace(self, trace_id: int) -> List[KernelEvent]:
        """Generate network packet processing with potential races"""
        events = []
        base_time = time.time()
        
        # Network packet allocation and processing
        for i in range(random.randint(3, 8)):
            alloc_skb = KernelEvent(
                timestamp=base_time + i * 0.0001,
                thread_id=random.randint(1, 2),
                cpu_id=random.randint(0, 1),
                operation=KernelOperation.KMALLOC,
                subsystem=KernelSubsystem.NETWORK,
                object_id=f"skb_{trace_id}_{i}",
                call_stack=["net/core/skbuff.c:alloc_skb", "packet_alloc"]
            )
            events.append(alloc_skb)
            
            # Process packet
            process_event = KernelEvent(
                timestamp=alloc_skb.timestamp + 0.00005,
                thread_id=alloc_skb.thread_id,
                cpu_id=alloc_skb.cpu_id,
                operation=KernelOperation.COPY_FROM_USER,
                subsystem=KernelSubsystem.NETWORK,
                object_id=alloc_skb.object_id,
                call_stack=["net/core/dev.c:netif_receive_skb", "packet_process"]
            )
            events.append(process_event)
            
            # Free packet (potentially racy)
            if random.random() > 0.3:
                free_skb = KernelEvent(
                    timestamp=alloc_skb.timestamp + random.uniform(0.0001, 0.001),
                    thread_id=random.randint(1, 3),  # Potentially different thread
                    cpu_id=random.randint(0, 1),
                    operation=KernelOperation.KFREE,
                    subsystem=KernelSubsystem.NETWORK,
                    object_id=alloc_skb.object_id,
                    call_stack=["net/core/skbuff.c:kfree_skb", "packet_free"]
                )
                events.append(free_skb)
        
        return sorted(events, key=lambda x: x.timestamp)
    
    def _generate_module_loading_trace(self, trace_id: int) -> List[KernelEvent]:
        """Generate module loading/unloading with races"""
        events = []
        base_time = time.time()
        
        # Module reference counting race
        for i in range(3):
            get_ref = KernelEvent(
                timestamp=base_time + i * 0.001,
                thread_id=i + 1,
                cpu_id=i % 2,
                operation=KernelOperation.ATOMIC_INC,
                subsystem=KernelSubsystem.MODULE_LOADER,
                object_id=f"module_{trace_id}",
                call_stack=["kernel/module.c:try_module_get", f"get_ref_{i}"]
            )
            events.append(get_ref)
            
            put_ref = KernelEvent(
                timestamp=base_time + i * 0.001 + 0.0005,
                thread_id=i + 1,
                cpu_id=i % 2,
                operation=KernelOperation.ATOMIC_DEC,
                subsystem=KernelSubsystem.MODULE_LOADER,
                object_id=f"module_{trace_id}",
                call_stack=["kernel/module.c:module_put", f"put_ref_{i}"]
            )
            events.append(put_ref)
        
        return sorted(events, key=lambda x: x.timestamp)
    
    def _generate_device_driver_trace(self, trace_id: int) -> List[KernelEvent]:
        """Generate device driver operations with interrupt context races"""
        events = []
        base_time = time.time()
        
        # Driver operation in process context
        driver_op = KernelEvent(
            timestamp=base_time,
            thread_id=1,
            cpu_id=0,
            operation=KernelOperation.SPIN_LOCK,
            subsystem=KernelSubsystem.DEVICE_DRIVERS,
            lock_id=f"driver_lock_{trace_id}",
            call_stack=["drivers/char/driver.c:driver_ioctl", "process_context"]
        )
        events.append(driver_op)
        
        # Interrupt handler accessing same resource
        irq_handler = KernelEvent(
            timestamp=base_time + random.uniform(0.0001, 0.001),
            thread_id=0,  # IRQ context
            cpu_id=1,
            operation=KernelOperation.SPIN_LOCK,
            subsystem=KernelSubsystem.DEVICE_DRIVERS,
            lock_id=driver_op.lock_id,
            context="interrupt",
            call_stack=["drivers/char/driver.c:driver_irq", "interrupt_context"]
        )
        events.append(irq_handler)
        
        return events
    
    def build_happens_before_graph(self, traces: List[List[KernelEvent]]) -> nx.DiGraph:
        """Build happens-before graph from execution traces"""
        logger.info("Building happens-before graph from execution traces")
        
        graph = nx.DiGraph()
        relations = []
        
        for trace in traces:
            # Add events as nodes
            for event in trace:
                graph.add_node(id(event), event=event)
            
            # Analyze happens-before relations within trace
            for i, event1 in enumerate(trace):
                for j, event2 in enumerate(trace[i+1:], i+1):
                    relation = self._analyze_happens_before_relation(event1, event2)
                    if relation:
                        graph.add_edge(id(event1), id(event2), relation=relation)
                        relations.append(relation)
        
        # Cross-trace analysis for races
        for trace1 in traces:
            for trace2 in traces:
                if trace1 != trace2:
                    self._analyze_cross_trace_relations(trace1, trace2, graph)
        
        logger.info(f"Built happens-before graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
        return graph
    
    def _analyze_happens_before_relation(self, event1: KernelEvent, event2: KernelEvent) -> Optional[HappensBeforeRelation]:
        """Analyze if there's a happens-before relation between two events"""
        
        # Same thread, sequential ordering
        if event1.thread_id == event2.thread_id and event1.timestamp < event2.timestamp:
            return HappensBeforeRelation(event1, event2, "sequential", 1.0)
        
        # Lock synchronization
        if (event1.operation == KernelOperation.MUTEX_UNLOCK and 
            event2.operation == KernelOperation.MUTEX_LOCK and
            event1.lock_id == event2.lock_id):
            return HappensBeforeRelation(event1, event2, "lock", 0.9)
        
        # Memory dependencies
        if (event1.memory_address and event2.memory_address and
            event1.memory_address == event2.memory_address and
            event1.operation in [KernelOperation.KFREE] and
            event2.operation in [KernelOperation.COPY_FROM_USER, KernelOperation.COPY_TO_USER]):
            return HappensBeforeRelation(event1, event2, "memory", 0.8)
        
        # Interrupt context relations
        if (event1.context == "interrupt" and event2.context == "kernel" and
            abs(event1.timestamp - event2.timestamp) < 0.001):
            return HappensBeforeRelation(event1, event2, "interrupt", 0.7)
        
        return None
    
    def _analyze_cross_trace_relations(self, trace1: List[KernelEvent], trace2: List[KernelEvent], graph: nx.DiGraph):
        """Analyze happens-before relations across different traces"""
        for event1 in trace1:
            for event2 in trace2:
                # Shared object access
                if (event1.object_id and event2.object_id and 
                    event1.object_id == event2.object_id and
                    abs(event1.timestamp - event2.timestamp) < 0.01):
                    
                    relation = HappensBeforeRelation(event1, event2, "shared_object", 0.6)
                    graph.add_edge(id(event1), id(event2), relation=relation)
    
    def detect_race_conditions(self, traces: List[List[KernelEvent]]) -> List[RaceCondition]:
        """Detect race conditions using temporal analysis"""
        logger.info("Detecting race conditions in execution traces")
        
        races = []
        
        # Build happens-before graph
        hb_graph = self.build_happens_before_graph(traces)
        
        # Analyze for different types of races
        races.extend(self._detect_use_after_free_races(traces, hb_graph))
        races.extend(self._detect_toctou_races(traces, hb_graph))
        races.extend(self._detect_data_races(traces, hb_graph))
        races.extend(self._detect_deadlock_potential(traces, hb_graph))
        races.extend(self._detect_reference_counting_races(traces, hb_graph))
        races.extend(self._detect_signal_races(traces, hb_graph))
        
        logger.info(f"Detected {len(races)} potential race conditions")
        return races
    
    def _detect_use_after_free_races(self, traces: List[List[KernelEvent]], hb_graph: nx.DiGraph) -> List[RaceCondition]:
        """Detect use-after-free race conditions"""
        races = []
        
        for trace in traces:
            # Find free operations
            free_events = [e for e in trace if e.operation == KernelOperation.KFREE]
            
            for free_event in free_events:
                # Find subsequent accesses to same memory
                for other_trace in traces:
                    access_events = [e for e in other_trace 
                                   if e.memory_address == free_event.memory_address and
                                   e.timestamp > free_event.timestamp and
                                   e.operation in [KernelOperation.COPY_FROM_USER, KernelOperation.COPY_TO_USER]]
                    
                    for access_event in access_events:
                        # Check if there's no happens-before relation
                        if not nx.has_path(hb_graph, id(free_event), id(access_event)):
                            race = RaceCondition(
                                race_type=RaceType.USE_AFTER_FREE,
                                subsystem=free_event.subsystem,
                                conflicting_events=[free_event, access_event],
                                happens_before_violations=[],
                                risk_level="CRITICAL",
                                exploitability="HIGH",
                                evidence=[
                                    f"Memory freed at {free_event.timestamp}",
                                    f"Memory accessed at {access_event.timestamp}",
                                    f"Time gap: {(access_event.timestamp - free_event.timestamp)*1000:.2f}ms",
                                    f"Different threads: {free_event.thread_id} vs {access_event.thread_id}"
                                ],
                                affected_code_patterns=[
                                    "kfree.*followed.*by.*access",
                                    f"object_{free_event.object_id}.*use_after_free"
                                ],
                                mitigation_suggestions=[
                                    "Add reference counting",
                                    "Use RCU protection",
                                    "Add memory barriers"
                                ],
                                temporal_window_ms=(access_event.timestamp - free_event.timestamp) * 1000,
                                probability_score=0.9 if access_event.thread_id != free_event.thread_id else 0.7
                            )
                            races.append(race)
        
        return races
    
    def _detect_toctou_races(self, traces: List[List[KernelEvent]], hb_graph: nx.DiGraph) -> List[RaceCondition]:
        """Detect time-of-check-time-of-use races"""
        races = []
        
        for trace in traces:
            # Look for check-use patterns in file operations
            file_events = [e for e in trace if e.subsystem == KernelSubsystem.FILE_SYSTEM]
            
            for i, check_event in enumerate(file_events[:-1]):
                use_event = file_events[i+1]
                
                # TOCTOU pattern: check followed by use with time gap
                if (check_event.object_id == use_event.object_id and
                    use_event.timestamp - check_event.timestamp > 0.001):  # 1ms gap
                    
                    race = RaceCondition(
                        race_type=RaceType.TOCTOU,
                        subsystem=KernelSubsystem.FILE_SYSTEM,
                        conflicting_events=[check_event, use_event],
                        happens_before_violations=[],
                        risk_level="HIGH",
                        exploitability="MEDIUM",
                        evidence=[
                            f"Permission check at {check_event.timestamp}",
                            f"File access at {use_event.timestamp}",
                            f"Time gap: {(use_event.timestamp - check_event.timestamp)*1000:.2f}ms"
                        ],
                        affected_code_patterns=[
                            "permission.*check.*followed.*by.*access",
                            f"file_{check_event.object_id}.*toctou"
                        ],
                        mitigation_suggestions=[
                            "Use file descriptor instead of path",
                            "Atomic check-and-use operations",
                            "File locking"
                        ],
                        temporal_window_ms=(use_event.timestamp - check_event.timestamp) * 1000,
                        probability_score=0.8
                    )
                    races.append(race)
        
        return races
    
    def _detect_data_races(self, traces: List[List[KernelEvent]], hb_graph: nx.DiGraph) -> List[RaceCondition]:
        """Detect data races on shared variables"""
        races = []
        
        # Group events by memory address
        memory_accesses = defaultdict(list)
        for trace in traces:
            for event in trace:
                if event.memory_address:
                    memory_accesses[event.memory_address].append(event)
        
        for addr, events in memory_accesses.items():
            if len(events) < 2:
                continue
            
            # Look for concurrent writes or write-read without synchronization
            for i, event1 in enumerate(events):
                for event2 in events[i+1:]:
                    if (abs(event1.timestamp - event2.timestamp) < 0.001 and  # Concurrent
                        event1.thread_id != event2.thread_id and  # Different threads
                        not nx.has_path(hb_graph, id(event1), id(event2))):  # No happens-before
                        
                        race = RaceCondition(
                            race_type=RaceType.DATA_RACE,
                            subsystem=event1.subsystem,
                            conflicting_events=[event1, event2],
                            happens_before_violations=[],
                            risk_level="MEDIUM",
                            exploitability="LOW",
                            evidence=[
                                f"Concurrent access to {hex(addr)}",
                                f"Thread {event1.thread_id} vs Thread {event2.thread_id}",
                                f"Time difference: {abs(event1.timestamp - event2.timestamp)*1000:.2f}ms"
                            ],
                            affected_code_patterns=[
                                "concurrent.*write.*same.*location",
                                f"addr_{hex(addr)}.*data_race"
                            ],
                            mitigation_suggestions=[
                                "Add atomic operations",
                                "Use proper locking",
                                "Memory barriers"
                            ],
                            temporal_window_ms=abs(event1.timestamp - event2.timestamp) * 1000,
                            probability_score=0.6
                        )
                        races.append(race)
        
        return races
    
    def _detect_deadlock_potential(self, traces: List[List[KernelEvent]], hb_graph: nx.DiGraph) -> List[RaceCondition]:
        """Detect potential deadlock scenarios"""
        races = []
        
        # Track lock acquisition patterns
        lock_patterns = defaultdict(list)
        for trace in traces:
            thread_locks = []
            for event in trace:
                if event.operation == KernelOperation.MUTEX_LOCK and event.lock_id:
                    thread_locks.append((event.thread_id, event.lock_id, event.timestamp))
            
            if len(thread_locks) > 1:
                lock_patterns[trace[0].thread_id if trace else 0] = thread_locks
        
        # Check for lock ordering violations
        for thread1, locks1 in lock_patterns.items():
            for thread2, locks2 in lock_patterns.items():
                if thread1 >= thread2:
                    continue
                
                # Check for AB-BA pattern
                for t1, lock_a, ts1 in locks1:
                    for t1_2, lock_b, ts2 in locks1:
                        if ts1 < ts2:  # A before B in thread 1
                            # Look for B before A in thread 2
                            for t2, lock_b2, ts3 in locks2:
                                for t2_2, lock_a2, ts4 in locks2:
                                    if (ts3 < ts4 and lock_b == lock_b2 and 
                                        lock_a == lock_a2):  # B before A in thread 2
                                        
                                        # Potential deadlock
                                        race = RaceCondition(
                                            race_type=RaceType.DEADLOCK,
                                            subsystem=KernelSubsystem.MEMORY_MANAGEMENT,  # Generic
                                            conflicting_events=[],
                                            happens_before_violations=[],
                                            risk_level="HIGH",
                                            exploitability="MEDIUM",
                                            evidence=[
                                                f"Thread {thread1}: {lock_a} -> {lock_b}",
                                                f"Thread {thread2}: {lock_b2} -> {lock_a2}",
                                                "Lock ordering violation detected"
                                            ],
                                            affected_code_patterns=[
                                                f"lock_ordering_{lock_a}_{lock_b}",
                                                "AB_BA_deadlock_pattern"
                                            ],
                                            mitigation_suggestions=[
                                                "Consistent lock ordering",
                                                "Deadlock detection",
                                                "Lock-free algorithms"
                                            ],
                                            temporal_window_ms=max(ts2-ts1, ts4-ts3) * 1000,
                                            probability_score=0.7
                                        )
                                        races.append(race)
        
        return races
    
    def _detect_reference_counting_races(self, traces: List[List[KernelEvent]], hb_graph: nx.DiGraph) -> List[RaceCondition]:
        """Detect reference counting races"""
        races = []
        
        for trace in traces:
            ref_events = [e for e in trace if e.operation in [KernelOperation.ATOMIC_INC, KernelOperation.ATOMIC_DEC]]
            
            # Group by object
            obj_refs = defaultdict(list)
            for event in ref_events:
                obj_refs[event.object_id].append(event)
            
            for obj_id, events in obj_refs.items():
                # Look for dec-inc races or double-dec
                for i, event1 in enumerate(events):
                    for event2 in events[i+1:]:
                        if (event1.operation == KernelOperation.ATOMIC_DEC and
                            event2.operation == KernelOperation.ATOMIC_DEC and
                            abs(event1.timestamp - event2.timestamp) < 0.001):
                            
                            race = RaceCondition(
                                race_type=RaceType.REFERENCE_COUNTING,
                                subsystem=event1.subsystem,
                                conflicting_events=[event1, event2],
                                happens_before_violations=[],
                                risk_level="HIGH",
                                exploitability="MEDIUM",
                                evidence=[
                                    f"Double reference decrement on {obj_id}",
                                    f"Time gap: {abs(event1.timestamp - event2.timestamp)*1000:.2f}ms"
                                ],
                                affected_code_patterns=[
                                    f"refcount_race_{obj_id}",
                                    "atomic_dec.*atomic_dec"
                                ],
                                mitigation_suggestions=[
                                    "Atomic reference counting",
                                    "RCU protection",
                                    "Proper synchronization"
                                ],
                                temporal_window_ms=abs(event1.timestamp - event2.timestamp) * 1000,
                                probability_score=0.8
                            )
                            races.append(race)
        
        return races
    
    def _detect_signal_races(self, traces: List[List[KernelEvent]], hb_graph: nx.DiGraph) -> List[RaceCondition]:
        """Detect signal handling races"""
        races = []
        
        for trace in traces:
            signal_events = [e for e in trace if e.operation == KernelOperation.SIGNAL_PENDING]
            
            if len(signal_events) > 1:
                for i, event1 in enumerate(signal_events[:-1]):
                    event2 = signal_events[i+1]
                    
                    if (event1.object_id == event2.object_id and
                        event1.thread_id != event2.thread_id and
                        abs(event1.timestamp - event2.timestamp) < 0.001):
                        
                        race = RaceCondition(
                            race_type=RaceType.SIGNAL_HANDLING,
                            subsystem=KernelSubsystem.SIGNAL_HANDLING,
                            conflicting_events=[event1, event2],
                            happens_before_violations=[],
                            risk_level="MEDIUM",
                            exploitability="LOW",
                            evidence=[
                                f"Concurrent signal operations on {event1.object_id}",
                                f"Context: {event1.context} vs {event2.context}"
                            ],
                            affected_code_patterns=[
                                f"signal_race_{event1.object_id}",
                                "signal_pending.*concurrent"
                            ],
                            mitigation_suggestions=[
                                "Signal masking",
                                "Atomic signal operations",
                                "Proper signal synchronization"
                            ],
                            temporal_window_ms=abs(event1.timestamp - event2.timestamp) * 1000,
                            probability_score=0.5
                        )
                        races.append(race)
        
        return races
    
    def analyze_subsystem_vulnerabilities(self, races: List[RaceCondition]) -> Dict:
        """Analyze race conditions by kernel subsystem"""
        subsystem_analysis = defaultdict(lambda: {
            'race_count': 0,
            'critical_races': 0,
            'high_races': 0,
            'race_types': defaultdict(int),
            'risk_score': 0.0
        })
        
        for race in races:
            sub = race.subsystem.value
            subsystem_analysis[sub]['race_count'] += 1
            
            if race.risk_level == "CRITICAL":
                subsystem_analysis[sub]['critical_races'] += 1
            elif race.risk_level == "HIGH":
                subsystem_analysis[sub]['high_races'] += 1
            
            subsystem_analysis[sub]['race_types'][race.race_type.value] += 1
            subsystem_analysis[sub]['risk_score'] += race.probability_score
        
        # Calculate average risk scores
        for sub_data in subsystem_analysis.values():
            if sub_data['race_count'] > 0:
                sub_data['risk_score'] /= sub_data['race_count']
        
        return dict(subsystem_analysis)
    
    def export_for_detector_integration(self, races: List[RaceCondition]) -> List[Dict]:
        """Export race condition findings for integration with kernel detector"""
        findings = []
        
        for race in races:
            finding = {
                "race_type": race.race_type.value,
                "subsystem": race.subsystem.value,
                "risk_level": race.risk_level,
                "exploitability": race.exploitability,
                "detection_signatures": [],
                "code_patterns": race.affected_code_patterns,
                "temporal_window_ms": race.temporal_window_ms,
                "probability_score": race.probability_score,
                "evidence": race.evidence,
                "mitigation_suggestions": race.mitigation_suggestions
            }
            
            # Generate detection signatures
            for pattern in race.affected_code_patterns:
                finding["detection_signatures"].append(f"kernel.*{pattern}")
                finding["detection_signatures"].append(f"{race.subsystem.value}.*{race.race_type.value}")
                finding["detection_signatures"].append(f"race.*{race.race_type.value}.*{race.subsystem.value}")
            
            findings.append(finding)
        
        return findings

class TemporalAnalyzer:
    """Advanced temporal analysis for race condition detection"""
    
    def __init__(self):
        self.time_windows = [0.001, 0.01, 0.1, 1.0]  # Different time scales
        
    def analyze_temporal_patterns(self, events: List[KernelEvent]) -> Dict:
        """Analyze temporal patterns in kernel events"""
        patterns = {
            'burst_events': [],
            'periodic_patterns': [],
            'anomalous_gaps': []
        }
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        
        # Detect event bursts
        for window in self.time_windows:
            bursts = self._detect_event_bursts(sorted_events, window)
            patterns['burst_events'].extend(bursts)
        
        return patterns
    
    def _detect_event_bursts(self, events: List[KernelEvent], window: float) -> List[Dict]:
        """Detect bursts of events within time windows"""
        bursts = []
        i = 0
        
        while i < len(events):
            window_events = [events[i]]
            j = i + 1
            
            while j < len(events) and events[j].timestamp - events[i].timestamp <= window:
                window_events.append(events[j])
                j += 1
            
            if len(window_events) > 5:  # Burst threshold
                bursts.append({
                    'start_time': events[i].timestamp,
                    'duration': window,
                    'event_count': len(window_events),
                    'subsystems': list(set(e.subsystem.value for e in window_events)),
                    'operations': list(set(e.operation.value for e in window_events))
                })
            
            i = j if j > i + 1 else i + 1
        
        return bursts

def main():
    """Run comprehensive Linux kernel race condition discovery"""
    print("🔍 Linux Kernel Race Condition Discovery System")
    print("Advanced temporal analysis for unknown race discovery")
    print("=" * 70)
    
    discovery = KernelRaceDiscovery()
    
    # Phase 1: Generate execution traces
    print("\n📊 Phase 1: Generating Kernel Execution Traces")
    traces = discovery.generate_kernel_execution_traces(500)  # 500 traces for demo
    
    total_events = sum(len(trace) for trace in traces)
    print(f"✅ Generated {len(traces)} traces with {total_events} total events")
    
    # Phase 2: Race condition detection
    print("\n🔬 Phase 2: Race Condition Detection")
    start_time = time.time()
    races = discovery.detect_race_conditions(traces)
    detection_time = time.time() - start_time
    
    print(f"✅ Detected {len(races)} potential race conditions in {detection_time:.2f}s")
    
    # Phase 3: Analysis by subsystem
    print("\n📈 Phase 3: Subsystem Vulnerability Analysis")
    subsystem_analysis = discovery.analyze_subsystem_vulnerabilities(races)
    
    print(f"🎯 Races by Subsystem:")
    for subsystem, data in subsystem_analysis.items():
        if data['race_count'] > 0:
            print(f"   {subsystem}: {data['race_count']} races (Critical: {data['critical_races']}, High: {data['high_races']})")
    
    # Show race type distribution
    race_types = defaultdict(int)
    risk_levels = defaultdict(int)
    
    for race in races:
        race_types[race.race_type.value] += 1
        risk_levels[race.risk_level] += 1
    
    print(f"\n🔴 Race Types Discovered:")
    for race_type, count in race_types.items():
        print(f"   {race_type.replace('_', ' ').title()}: {count}")
    
    print(f"\n⚠️  Risk Level Distribution:")
    for risk_level, count in risk_levels.items():
        print(f"   {risk_level}: {count}")
    
    # Phase 4: Integration preparation
    print(f"\n🔧 Phase 4: Kernel Detector Integration")
    integration_findings = discovery.export_for_detector_integration(races)
    
    critical_findings = [f for f in integration_findings if f['risk_level'] == 'CRITICAL']
    high_findings = [f for f in integration_findings if f['risk_level'] == 'HIGH']
    
    print(f"✅ Exported {len(integration_findings)} findings for detector integration")
    print(f"   Critical: {len(critical_findings)}, High: {len(high_findings)}")
    
    if critical_findings:
        print(f"\n📋 Sample Critical Findings:")
        for finding in critical_findings[:2]:
            print(f"   Race: {finding['race_type']} in {finding['subsystem']}")
            print(f"   Probability: {finding['probability_score']:.2f}")
            print(f"   Signatures: {finding['detection_signatures'][:2]}")
    
    print(f"\n🎉 Kernel Race Discovery Complete!")
    print(f"⚡ Ready for Multi-LLM validation and GAT integration")
    
    return discovery, races, subsystem_analysis

if __name__ == "__main__":
    main()