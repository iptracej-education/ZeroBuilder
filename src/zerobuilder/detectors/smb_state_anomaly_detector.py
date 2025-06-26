#!/usr/bin/env python3
"""
SMB State Machine Anomaly Detector for Unknown Vulnerability Discovery
Uses ML to detect unusual state transitions that may indicate vulnerabilities
"""

import numpy as np
import pickle
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SMBState(Enum):
    """SMB protocol states"""
    INITIAL = "initial"
    NEGOTIATED = "negotiated"
    AUTHENTICATED = "authenticated"
    TREE_CONNECTED = "tree_connected"
    FILE_OPENED = "file_opened"
    LOCKED = "locked"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    FREED = "freed"

class SMBCommand(Enum):
    """SMB commands that trigger state transitions"""
    NEGOTIATE = "SMB2_NEGOTIATE"
    SESSION_SETUP = "SMB2_SESSION_SETUP"
    TREE_CONNECT = "SMB2_TREE_CONNECT"
    CREATE = "SMB2_CREATE"
    READ = "SMB2_READ"
    WRITE = "SMB2_WRITE"
    LOCK = "SMB2_LOCK"
    CLOSE = "SMB2_CLOSE"
    TREE_DISCONNECT = "SMB2_TREE_DISCONNECT"
    LOGOFF = "SMB2_LOGOFF"
    ECHO = "SMB2_ECHO"
    CANCEL = "SMB2_CANCEL"
    FLUSH = "SMB2_FLUSH"

@dataclass
class StateTransition:
    """Represents a state transition in SMB protocol"""
    from_state: SMBState
    command: SMBCommand
    to_state: SMBState
    timestamp: float
    session_id: int
    success: bool = True
    error_code: int = 0

@dataclass
class AnomalyDetection:
    """Result of anomaly detection"""
    sequence: List[StateTransition]
    anomaly_score: float
    is_anomaly: bool
    risk_level: str
    suspected_vulnerability_types: List[str]
    evidence: List[str]

class SMBStateAnomalyDetector:
    """Detects anomalous SMB state transitions that may indicate vulnerabilities"""
    
    def __init__(self):
        self.state_encoders = {
            'from_state': LabelEncoder(),
            'command': LabelEncoder(),
            'to_state': LabelEncoder()
        }
        self.anomaly_model = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.normal_transitions = self._build_normal_state_machine()
        self.trained = False
        self.sequence_buffer = deque(maxlen=1000)
        
    def _build_normal_state_machine(self) -> Dict[Tuple[SMBState, SMBCommand], SMBState]:
        """Build the expected SMB state machine transitions"""
        transitions = {
            # Normal SMB flow
            (SMBState.INITIAL, SMBCommand.NEGOTIATE): SMBState.NEGOTIATED,
            (SMBState.NEGOTIATED, SMBCommand.SESSION_SETUP): SMBState.AUTHENTICATED,
            (SMBState.AUTHENTICATED, SMBCommand.TREE_CONNECT): SMBState.TREE_CONNECTED,
            (SMBState.TREE_CONNECTED, SMBCommand.CREATE): SMBState.FILE_OPENED,
            (SMBState.FILE_OPENED, SMBCommand.READ): SMBState.FILE_OPENED,
            (SMBState.FILE_OPENED, SMBCommand.WRITE): SMBState.FILE_OPENED,
            (SMBState.FILE_OPENED, SMBCommand.LOCK): SMBState.LOCKED,
            (SMBState.LOCKED, SMBCommand.READ): SMBState.LOCKED,
            (SMBState.LOCKED, SMBCommand.WRITE): SMBState.LOCKED,
            (SMBState.LOCKED, SMBCommand.LOCK): SMBState.LOCKED,  # Re-lock
            (SMBState.FILE_OPENED, SMBCommand.CLOSE): SMBState.TREE_CONNECTED,
            (SMBState.LOCKED, SMBCommand.CLOSE): SMBState.TREE_CONNECTED,
            (SMBState.TREE_CONNECTED, SMBCommand.TREE_DISCONNECT): SMBState.AUTHENTICATED,
            (SMBState.AUTHENTICATED, SMBCommand.LOGOFF): SMBState.DISCONNECTED,
            
            # Echo can happen in most states
            (SMBState.NEGOTIATED, SMBCommand.ECHO): SMBState.NEGOTIATED,
            (SMBState.AUTHENTICATED, SMBCommand.ECHO): SMBState.AUTHENTICATED,
            (SMBState.TREE_CONNECTED, SMBCommand.ECHO): SMBState.TREE_CONNECTED,
            (SMBState.FILE_OPENED, SMBCommand.ECHO): SMBState.FILE_OPENED,
            
            # Flush operations
            (SMBState.FILE_OPENED, SMBCommand.FLUSH): SMBState.FILE_OPENED,
            (SMBState.LOCKED, SMBCommand.FLUSH): SMBState.LOCKED,
        }
        return transitions
    
    def generate_normal_sequences(self, num_sequences: int = 1000) -> List[List[StateTransition]]:
        """Generate normal SMB operation sequences for training"""
        sequences = []
        
        for i in range(num_sequences):
            sequence = []
            current_state = SMBState.INITIAL
            session_id = i
            timestamp = 0.0
            
            # Generate a normal SMB session flow
            normal_flow = [
                SMBCommand.NEGOTIATE,
                SMBCommand.SESSION_SETUP,
                SMBCommand.TREE_CONNECT,
                SMBCommand.CREATE,
                SMBCommand.READ,
                SMBCommand.WRITE,
                SMBCommand.CLOSE,
                SMBCommand.TREE_DISCONNECT,
                SMBCommand.LOGOFF
            ]
            
            # Add some variations
            if i % 3 == 0:  # Some sessions use locks
                normal_flow.insert(4, SMBCommand.LOCK)
            if i % 5 == 0:  # Some sessions have multiple files
                normal_flow.extend([SMBCommand.CREATE, SMBCommand.READ, SMBCommand.CLOSE])
            if i % 7 == 0:  # Some sessions use echo
                normal_flow.insert(2, SMBCommand.ECHO)
            
            for command in normal_flow:
                expected_next_state = self.normal_transitions.get((current_state, command))
                if expected_next_state:
                    transition = StateTransition(
                        from_state=current_state,
                        command=command,
                        to_state=expected_next_state,
                        timestamp=timestamp,
                        session_id=session_id,
                        success=True
                    )
                    sequence.append(transition)
                    current_state = expected_next_state
                    timestamp += np.random.uniform(0.1, 2.0)
            
            if sequence:
                sequences.append(sequence)
        
        return sequences
    
    def generate_anomalous_sequences(self, num_sequences: int = 100) -> List[List[StateTransition]]:
        """Generate anomalous SMB sequences that simulate vulnerabilities"""
        sequences = []
        
        vulnerability_patterns = [
            # Use-after-free: operations after LOGOFF
            {
                "name": "use_after_free",
                "pattern": [SMBCommand.NEGOTIATE, SMBCommand.SESSION_SETUP, 
                           SMBCommand.TREE_CONNECT, SMBCommand.LOGOFF, SMBCommand.READ]
            },
            
            # Authentication bypass: operations without proper auth
            {
                "name": "auth_bypass", 
                "pattern": [SMBCommand.NEGOTIATE, SMBCommand.TREE_CONNECT, SMBCommand.CREATE]
            },
            
            # State confusion: operations in wrong order
            {
                "name": "state_confusion",
                "pattern": [SMBCommand.READ, SMBCommand.NEGOTIATE, SMBCommand.WRITE]
            },
            
            # Double operations (potential double-free)
            {
                "name": "double_operation",
                "pattern": [SMBCommand.NEGOTIATE, SMBCommand.SESSION_SETUP,
                           SMBCommand.LOGOFF, SMBCommand.LOGOFF]
            },
            
            # Privilege escalation attempts
            {
                "name": "privilege_escalation",
                "pattern": [SMBCommand.CREATE, SMBCommand.LOCK, SMBCommand.TREE_CONNECT]
            }
        ]
        
        for i in range(num_sequences):
            pattern = vulnerability_patterns[i % len(vulnerability_patterns)]
            sequence = []
            current_state = SMBState.INITIAL
            session_id = 1000 + i
            timestamp = 0.0
            
            for command in pattern["pattern"]:
                # For anomalous sequences, don't follow normal state transitions
                expected_next_state = self.normal_transitions.get((current_state, command))
                
                if expected_next_state is None:
                    # This is an anomalous transition
                    if "auth_bypass" in pattern["name"]:
                        next_state = SMBState.ERROR if current_state == SMBState.INITIAL else SMBState.TREE_CONNECTED
                    elif "use_after_free" in pattern["name"]:
                        next_state = SMBState.FREED if command == SMBCommand.LOGOFF else SMBState.ERROR
                    elif "state_confusion" in pattern["name"]:
                        next_state = SMBState.ERROR
                    else:
                        next_state = SMBState.ERROR
                else:
                    next_state = expected_next_state
                
                transition = StateTransition(
                    from_state=current_state,
                    command=command,
                    to_state=next_state,
                    timestamp=timestamp,
                    session_id=session_id,
                    success=(next_state != SMBState.ERROR),
                    error_code=0x80000005 if next_state == SMBState.ERROR else 0
                )
                sequence.append(transition)
                current_state = next_state
                timestamp += np.random.uniform(0.1, 1.0)
            
            sequences.append(sequence)
        
        return sequences
    
    def _encode_transition_sequence(self, sequence: List[StateTransition]) -> np.ndarray:
        """Encode a sequence of state transitions for ML analysis"""
        if not sequence:
            return np.array([])
        
        features = []
        for transition in sequence[-10:]:  # Look at last 10 transitions
            feature_vector = [
                self.state_encoders['from_state'].transform([transition.from_state.value])[0],
                self.state_encoders['command'].transform([transition.command.value])[0],
                self.state_encoders['to_state'].transform([transition.to_state.value])[0],
                1 if transition.success else 0,
                transition.error_code,
                len(sequence)  # Sequence length as feature
            ]
            features.extend(feature_vector)
        
        # Pad or truncate to fixed size (60 features = 10 transitions * 6 features)
        if len(features) < 60:
            features.extend([0] * (60 - len(features)))
        else:
            features = features[:60]
        
        return np.array(features)
    
    def train_anomaly_detector(self) -> Dict:
        """Train the anomaly detection model on normal and anomalous sequences"""
        logger.info("Generating training data...")
        
        # Generate training data
        normal_sequences = self.generate_normal_sequences(800)
        anomalous_sequences = self.generate_anomalous_sequences(80)
        
        all_sequences = normal_sequences + anomalous_sequences
        all_labels = [0] * len(normal_sequences) + [1] * len(anomalous_sequences)
        
        # Fit encoders on all possible values
        all_states = [state.value for state in SMBState]
        all_commands = [cmd.value for cmd in SMBCommand]
        
        self.state_encoders['from_state'].fit(all_states)
        self.state_encoders['command'].fit(all_commands)
        self.state_encoders['to_state'].fit(all_states)
        
        # Encode sequences
        logger.info("Encoding sequences for training...")
        X = []
        for sequence in all_sequences:
            encoded = self._encode_transition_sequence(sequence)
            if len(encoded) > 0:
                X.append(encoded)
        
        X = np.array(X)
        
        # Train model
        logger.info(f"Training anomaly detector on {len(X)} sequences...")
        self.anomaly_model.fit(X)
        self.trained = True
        
        # Evaluate on training data
        predictions = self.anomaly_model.predict(X)
        anomaly_scores = self.anomaly_model.decision_function(X)
        
        # Calculate metrics
        true_positives = sum(1 for i, pred in enumerate(predictions) if pred == -1 and all_labels[i] == 1)
        false_positives = sum(1 for i, pred in enumerate(predictions) if pred == -1 and all_labels[i] == 0)
        true_negatives = sum(1 for i, pred in enumerate(predictions) if pred == 1 and all_labels[i] == 0)
        false_negatives = sum(1 for i, pred in enumerate(predictions) if pred == 1 and all_labels[i] == 1)
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        training_results = {
            "training_sequences": len(all_sequences),
            "normal_sequences": len(normal_sequences),
            "anomalous_sequences": len(anomalous_sequences),
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives
        }
        
        logger.info(f"Training complete. Precision: {precision:.3f}, Recall: {recall:.3f}, F1: {f1_score:.3f}")
        return training_results
    
    def detect_anomalies(self, sequence: List[StateTransition]) -> AnomalyDetection:
        """Detect if a sequence contains anomalous state transitions"""
        if not self.trained:
            raise ValueError("Model must be trained before detecting anomalies")
        
        if not sequence:
            return AnomalyDetection(
                sequence=sequence,
                anomaly_score=0.0,
                is_anomaly=False,
                risk_level="INFO",
                suspected_vulnerability_types=[],
                evidence=[]
            )
        
        # Encode sequence
        encoded = self._encode_transition_sequence(sequence)
        if len(encoded) == 0:
            return AnomalyDetection(
                sequence=sequence,
                anomaly_score=0.0,
                is_anomaly=False,
                risk_level="INFO",
                suspected_vulnerability_types=[],
                evidence=[]
            )
        
        # Predict anomaly
        prediction = self.anomaly_model.predict([encoded])[0]
        anomaly_score = self.anomaly_model.decision_function([encoded])[0]
        is_anomaly = prediction == -1
        
        # Analyze for specific vulnerability patterns
        vulnerability_types = []
        evidence = []
        risk_level = "INFO"
        
        if is_anomaly:
            # Check for specific patterns
            states = [t.from_state for t in sequence] + [sequence[-1].to_state]
            commands = [t.command for t in sequence]
            
            # Use-after-free detection
            if SMBState.FREED in states or (SMBCommand.LOGOFF in commands and 
                any(cmd in commands[commands.index(SMBCommand.LOGOFF)+1:] 
                    for cmd in [SMBCommand.READ, SMBCommand.WRITE, SMBCommand.CREATE])):
                vulnerability_types.append("use_after_free")
                evidence.append("Operations performed after session freed/logged off")
                risk_level = "CRITICAL"
            
            # Authentication bypass detection
            if (SMBCommand.TREE_CONNECT in commands and SMBCommand.SESSION_SETUP not in commands):
                vulnerability_types.append("authentication_bypass")
                evidence.append("Tree connect without proper session setup")
                risk_level = "HIGH" if risk_level != "CRITICAL" else risk_level
            
            # State confusion detection
            invalid_transitions = []
            for transition in sequence:
                expected = self.normal_transitions.get((transition.from_state, transition.command))
                if expected and expected != transition.to_state:
                    invalid_transitions.append(f"{transition.command.value}: {transition.from_state.value} -> {transition.to_state.value}")
            
            if invalid_transitions:
                vulnerability_types.append("state_confusion")
                evidence.extend([f"Invalid transition: {t}" for t in invalid_transitions[:3]])
                risk_level = "MEDIUM" if risk_level not in ["CRITICAL", "HIGH"] else risk_level
            
            # Error accumulation
            error_count = sum(1 for t in sequence if not t.success)
            if error_count > len(sequence) * 0.5:
                vulnerability_types.append("error_accumulation")
                evidence.append(f"High error rate: {error_count}/{len(sequence)} operations failed")
        
        return AnomalyDetection(
            sequence=sequence,
            anomaly_score=abs(anomaly_score),
            is_anomaly=is_anomaly,
            risk_level=risk_level,
            suspected_vulnerability_types=vulnerability_types,
            evidence=evidence
        )
    
    def analyze_real_time_sequence(self, new_transitions: List[StateTransition]) -> List[AnomalyDetection]:
        """Analyze transitions in real-time, maintaining a sliding window"""
        results = []
        
        for transition in new_transitions:
            self.sequence_buffer.append(transition)
            
            # Analyze current window
            current_sequence = list(self.sequence_buffer)
            detection = self.detect_anomalies(current_sequence)
            
            if detection.is_anomaly:
                results.append(detection)
        
        return results
    
    def export_patterns_for_smb_detector(self) -> List[Dict]:
        """Export discovered patterns for integration with SMB detector"""
        if not self.trained:
            return []
        
        # Generate test sequences and find anomalies
        test_sequences = self.generate_anomalous_sequences(50)
        patterns = []
        
        for sequence in test_sequences:
            detection = self.detect_anomalies(sequence)
            if detection.is_anomaly and detection.risk_level in ["CRITICAL", "HIGH"]:
                pattern = {
                    "vulnerability_types": detection.suspected_vulnerability_types,
                    "risk_level": detection.risk_level,
                    "detection_signatures": [],
                    "state_sequence": [t.to_state.value for t in detection.sequence],
                    "command_sequence": [t.command.value for t in detection.sequence],
                    "evidence": detection.evidence
                }
                
                # Generate regex patterns for SMB detector
                for vuln_type in detection.suspected_vulnerability_types:
                    if vuln_type == "use_after_free":
                        pattern["detection_signatures"].extend([
                            "LOGOFF.*READ|WRITE|CREATE",
                            "freed.*session.*access",
                            "after.*free.*operation"
                        ])
                    elif vuln_type == "authentication_bypass":
                        pattern["detection_signatures"].extend([
                            "TREE_CONNECT.*without.*SESSION_SETUP",
                            "bypass.*authentication.*check",
                            "unauthenticated.*access"
                        ])
                    elif vuln_type == "state_confusion":
                        pattern["detection_signatures"].extend([
                            "invalid.*state.*transition",
                            "unexpected.*command.*state",
                            "protocol.*violation"
                        ])
                
                patterns.append(pattern)
        
        return patterns

def main():
    """Run SMB state machine anomaly detection analysis"""
    print("🔍 SMB State Machine Anomaly Detector")
    print("Discovering unknown vulnerabilities through state transition analysis")
    print("=" * 75)
    
    detector = SMBStateAnomalyDetector()
    
    # Phase 1: Train the model
    print("\n📊 Phase 1: Training Anomaly Detection Model")
    training_results = detector.train_anomaly_detector()
    
    print(f"✅ Training Complete:")
    print(f"   Training Sequences: {training_results['training_sequences']}")
    print(f"   Precision: {training_results['precision']:.3f}")
    print(f"   Recall: {training_results['recall']:.3f}")
    print(f"   F1 Score: {training_results['f1_score']:.3f}")
    
    # Phase 2: Test on anomalous sequences
    print(f"\n🔬 Phase 2: Anomaly Detection Testing")
    test_anomalous = detector.generate_anomalous_sequences(20)
    anomaly_detections = []
    
    for sequence in test_anomalous:
        detection = detector.detect_anomalies(sequence)
        if detection.is_anomaly:
            anomaly_detections.append(detection)
    
    print(f"📈 Detection Results:")
    print(f"   Test Sequences: {len(test_anomalous)}")
    print(f"   Anomalies Detected: {len(anomaly_detections)}")
    print(f"   Detection Rate: {len(anomaly_detections)/len(test_anomalous):.1%}")
    
    # Analyze vulnerability types
    vuln_types = defaultdict(int)
    risk_levels = defaultdict(int)
    
    for detection in anomaly_detections:
        for vuln_type in detection.suspected_vulnerability_types:
            vuln_types[vuln_type] += 1
        risk_levels[detection.risk_level] += 1
    
    print(f"\n🎯 Vulnerability Types Discovered:")
    for vuln_type, count in vuln_types.items():
        print(f"   {vuln_type.replace('_', ' ').title()}: {count}")
    
    print(f"\n🔴 Risk Level Distribution:")
    for risk_level, count in risk_levels.items():
        print(f"   {risk_level}: {count}")
    
    # Phase 3: Integration patterns
    print(f"\n🔧 Phase 3: SMB Detector Integration")
    integration_patterns = detector.export_patterns_for_smb_detector()
    
    print(f"✅ Generated {len(integration_patterns)} patterns for SMB detector")
    
    if integration_patterns:
        print(f"\n📋 Sample Detection Patterns:")
        for pattern in integration_patterns[:2]:
            print(f"   Vulnerability: {', '.join(pattern['vulnerability_types'])}")
            print(f"   Risk: {pattern['risk_level']}")
            print(f"   Signatures: {pattern['detection_signatures'][:2]}")
    
    print(f"\n🎉 SMB State Anomaly Analysis Complete!")
    print(f"⚡ Ready for integration and Multi-LLM validation")
    
    return detector, anomaly_detections, integration_patterns

if __name__ == "__main__":
    main()