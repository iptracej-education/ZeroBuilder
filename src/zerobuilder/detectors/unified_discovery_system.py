#!/usr/bin/env python3
"""
Unified Unknown Vulnerability Discovery System
Integrates SMB, kernel race, and anomaly detection systems for comprehensive unknown vulnerability discovery
"""

import time
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging

# Import our discovery systems
import sys
import os
sys.path.append(os.path.dirname(__file__))

from smb_concurrent_analyzer import SMBConcurrentAnalyzer, ConcurrencyTestResult
from smb_state_anomaly_detector import SMBStateAnomalyDetector, AnomalyDetection
from smb_differential_tester import SMBDifferentialTester, DifferentialTestResult
from kernel_race_discovery import KernelRaceDiscovery, RaceCondition, RaceType
from smb_protocol_analyzer import SMBHybridDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DiscoverySystemType(Enum):
    """Types of vulnerability discovery systems"""
    SMB_CONCURRENT = "smb_concurrent"
    SMB_STATE_ANOMALY = "smb_state_anomaly"
    SMB_DIFFERENTIAL = "smb_differential"
    KERNEL_RACE = "kernel_race"
    HYBRID_DETECTOR = "hybrid_detector"

class VulnerabilitySource(Enum):
    """Source of vulnerability discovery"""
    UNKNOWN_PATTERN = "unknown_pattern"
    NOVEL_COMBINATION = "novel_combination"
    ANOMALY_DETECTION = "anomaly_detection"
    DIFFERENTIAL_ANALYSIS = "differential_analysis"
    TEMPORAL_ANALYSIS = "temporal_analysis"
    RACE_CONDITION = "race_condition"

@dataclass
class UnifiedVulnerability:
    """Unified representation of discovered vulnerabilities"""
    id: str
    discovery_system: DiscoverySystemType
    vulnerability_source: VulnerabilitySource
    target_system: str  # "smb", "kernel", "hybrid"
    vulnerability_type: str
    risk_level: str
    confidence_score: float
    evidence: List[str]
    detection_signatures: List[str]
    affected_components: List[str]
    exploitation_complexity: str
    temporal_characteristics: Dict[str, Any]
    mitigation_suggestions: List[str]
    discovery_timestamp: float
    cross_system_correlations: List[str] = None
    
    def __post_init__(self):
        if self.cross_system_correlations is None:
            self.cross_system_correlations = []

@dataclass
class DiscoveryReport:
    """Comprehensive discovery report across all systems"""
    total_vulnerabilities: int
    by_system: Dict[str, int]
    by_risk_level: Dict[str, int]
    by_source: Dict[str, int]
    novel_patterns: int
    cross_system_correlations: int
    detection_coverage: Dict[str, float]
    performance_metrics: Dict[str, Any]
    integration_recommendations: List[str]

class UnifiedDiscoverySystem:
    """Unified system integrating all vulnerability discovery methods"""
    
    def __init__(self):
        self.smb_concurrent = SMBConcurrentAnalyzer()
        self.smb_anomaly = SMBStateAnomalyDetector()
        self.smb_differential = SMBDifferentialTester()
        self.kernel_discovery = KernelRaceDiscovery()
        self.smb_hybrid = SMBHybridDetector()
        
        self.discovered_vulnerabilities = []
        self.discovery_metrics = {}
        self.cross_correlations = []
        
    def run_comprehensive_discovery(self) -> DiscoveryReport:
        """Run all discovery systems and generate unified report"""
        logger.info("🚀 Starting Comprehensive Unknown Vulnerability Discovery")
        
        start_time = time.time()
        
        # Phase 1: SMB-based discovery
        logger.info("📊 Phase 1: SMB Vulnerability Discovery")
        smb_vulnerabilities = self._run_smb_discovery_suite()
        
        # Phase 2: Kernel race discovery
        logger.info("🔍 Phase 2: Kernel Race Condition Discovery")
        kernel_vulnerabilities = self._run_kernel_discovery()
        
        # Phase 3: Cross-system correlation analysis
        logger.info("🔗 Phase 3: Cross-System Correlation Analysis")
        correlations = self._analyze_cross_system_correlations(
            smb_vulnerabilities, kernel_vulnerabilities
        )
        
        # Phase 4: Generate unified report
        logger.info("📈 Phase 4: Unified Analysis Report")
        total_time = time.time() - start_time
        
        all_vulnerabilities = smb_vulnerabilities + kernel_vulnerabilities
        self.discovered_vulnerabilities = all_vulnerabilities
        
        report = self._generate_discovery_report(all_vulnerabilities, correlations, total_time)
        
        logger.info(f"✅ Discovery Complete: {report.total_vulnerabilities} vulnerabilities found in {total_time:.2f}s")
        return report
    
    def _run_smb_discovery_suite(self) -> List[UnifiedVulnerability]:
        """Run all SMB-related discovery systems"""
        vulnerabilities = []
        
        # 1. Concurrent session analysis
        logger.info("   🔄 Running SMB concurrent session analysis...")
        concurrent_results = self.smb_concurrent.systematic_concurrency_analysis(max_operations=6)
        vulnerabilities.extend(self._convert_concurrent_results(concurrent_results))
        
        # 2. State machine anomaly detection
        logger.info("   🧠 Training and running SMB state anomaly detection...")
        self.smb_anomaly.train_anomaly_detector()
        anomaly_sequences = self.smb_anomaly.generate_anomalous_sequences(50)
        for sequence in anomaly_sequences:
            detection = self.smb_anomaly.detect_anomalies(sequence)
            if detection.is_anomaly:
                vulnerabilities.append(self._convert_anomaly_detection(detection))
        
        # 3. Differential implementation testing
        logger.info("   ⚖️  Running SMB differential implementation testing...")
        diff_summary = self.smb_differential.run_comprehensive_test_suite()
        vulnerabilities.extend(self._convert_differential_results())
        
        logger.info(f"   ✅ SMB discovery: {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_kernel_discovery(self) -> List[UnifiedVulnerability]:
        """Run kernel race condition discovery"""
        vulnerabilities = []
        
        # Generate kernel traces and detect races
        logger.info("   🐧 Generating kernel execution traces...")
        traces = self.kernel_discovery.generate_kernel_execution_traces(200)
        
        logger.info("   🔍 Detecting kernel race conditions...")
        races = self.kernel_discovery.detect_race_conditions(traces)
        
        # Convert to unified format
        for race in races:
            if race.risk_level in ["CRITICAL", "HIGH"]:
                vuln = self._convert_race_condition(race)
                vulnerabilities.append(vuln)
        
        logger.info(f"   ✅ Kernel discovery: {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _convert_concurrent_results(self, results: List[ConcurrencyTestResult]) -> List[UnifiedVulnerability]:
        """Convert SMB concurrent analysis results to unified format"""
        vulnerabilities = []
        
        for i, result in enumerate(results):
            if result.vulnerability_detected and result.risk_level.value in ["CRITICAL", "HIGH"]:
                vuln = UnifiedVulnerability(
                    id=f"SMB_CONCURRENT_{i:04d}",
                    discovery_system=DiscoverySystemType.SMB_CONCURRENT,
                    vulnerability_source=VulnerabilitySource.RACE_CONDITION,
                    target_system="smb",
                    vulnerability_type=result.race_condition_type or "concurrent_access",
                    risk_level=result.risk_level.value,
                    confidence_score=0.8 if result.risk_level.value == "CRITICAL" else 0.6,
                    evidence=result.evidence,
                    detection_signatures=[
                        f"concurrent_{result.operation_pair[0].value}_{result.operation_pair[1].value}",
                        f"smb_race_{result.race_condition_type}",
                        f"timing_window_{result.timing_ms}ms"
                    ],
                    affected_components=[f"smb_{op.value}" for op in result.operation_pair],
                    exploitation_complexity="MEDIUM" if result.timing_ms < 10 else "HIGH",
                    temporal_characteristics={
                        "timing_window_ms": result.timing_ms,
                        "operation_sequence": [op.value for op in result.operation_pair],
                        "session_state_transition": f"{result.session_state_before} -> {result.session_state_after}"
                    },
                    mitigation_suggestions=[
                        "Implement proper session synchronization",
                        "Add reference counting for concurrent access",
                        "Use atomic operations for session state"
                    ],
                    discovery_timestamp=time.time()
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_anomaly_detection(self, detection: AnomalyDetection) -> UnifiedVulnerability:
        """Convert SMB anomaly detection to unified format"""
        return UnifiedVulnerability(
            id=f"SMB_ANOMALY_{int(time.time() * 1000000) % 10000:04d}",
            discovery_system=DiscoverySystemType.SMB_STATE_ANOMALY,
            vulnerability_source=VulnerabilitySource.ANOMALY_DETECTION,
            target_system="smb",
            vulnerability_type="_".join(detection.suspected_vulnerability_types),
            risk_level=detection.risk_level,
            confidence_score=detection.anomaly_score,
            evidence=detection.evidence,
            detection_signatures=[
                f"smb_state_anomaly_{vuln_type}" 
                for vuln_type in detection.suspected_vulnerability_types
            ],
            affected_components=["smb_state_machine"],
            exploitation_complexity="HIGH",
            temporal_characteristics={
                "sequence_length": len(detection.sequence),
                "anomaly_score": detection.anomaly_score,
                "state_transitions": [f"{t.from_state.value}->{t.to_state.value}" for t in detection.sequence]
            },
            mitigation_suggestions=[
                "Validate state transitions",
                "Implement state machine hardening",
                "Add anomaly detection monitoring"
            ],
            discovery_timestamp=time.time()
        )
    
    def _convert_differential_results(self) -> List[UnifiedVulnerability]:
        """Convert SMB differential testing results to unified format"""
        vulnerabilities = []
        
        for i, result in enumerate(self.smb_differential.test_results):
            if result.risk_level in ["CRITICAL", "HIGH"] and result.differences_detected:
                vuln = UnifiedVulnerability(
                    id=f"SMB_DIFF_{i:04d}",
                    discovery_system=DiscoverySystemType.SMB_DIFFERENTIAL,
                    vulnerability_source=VulnerabilitySource.DIFFERENTIAL_ANALYSIS,
                    target_system="smb",
                    vulnerability_type=result.test_case.vulnerability_target,
                    risk_level=result.risk_level,
                    confidence_score=0.7,
                    evidence=result.vulnerability_indicators,
                    detection_signatures=[
                        f"differential_{result.test_case.vulnerability_target}",
                        f"implementation_specific_{result.test_case.name}"
                    ],
                    affected_components=list(result.implementation_behaviors.keys()),
                    exploitation_complexity="MEDIUM",
                    temporal_characteristics={
                        "implementation_differences": result.implementation_behaviors,
                        "suspicious_patterns": result.suspicious_patterns
                    },
                    mitigation_suggestions=[
                        "Standardize implementation behavior",
                        "Add cross-platform testing",
                        "Implement consistent error handling"
                    ],
                    discovery_timestamp=time.time()
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _convert_race_condition(self, race: RaceCondition) -> UnifiedVulnerability:
        """Convert kernel race condition to unified format"""
        return UnifiedVulnerability(
            id=f"KERNEL_RACE_{hash(str(race.conflicting_events)) % 10000:04d}",
            discovery_system=DiscoverySystemType.KERNEL_RACE,
            vulnerability_source=VulnerabilitySource.TEMPORAL_ANALYSIS,
            target_system="kernel",
            vulnerability_type=race.race_type.value,
            risk_level=race.risk_level,
            confidence_score=race.probability_score,
            evidence=race.evidence,
            detection_signatures=[
                f"kernel_{race.race_type.value}_{race.subsystem.value}",
                f"temporal_window_{race.temporal_window_ms:.0f}ms"
            ] + race.affected_code_patterns,
            affected_components=[race.subsystem.value],
            exploitation_complexity=race.exploitability,
            temporal_characteristics={
                "temporal_window_ms": race.temporal_window_ms,
                "subsystem": race.subsystem.value,
                "conflicting_operations": [e.operation.value for e in race.conflicting_events],
                "happens_before_violations": len(race.happens_before_violations)
            },
            mitigation_suggestions=race.mitigation_suggestions,
            discovery_timestamp=time.time()
        )
    
    def _analyze_cross_system_correlations(self, smb_vulns: List[UnifiedVulnerability], 
                                         kernel_vulns: List[UnifiedVulnerability]) -> List[Dict]:
        """Analyze correlations between SMB and kernel vulnerabilities"""
        correlations = []
        
        # Look for similar vulnerability patterns across systems
        for smb_vuln in smb_vulns:
            for kernel_vuln in kernel_vulns:
                correlation_score = self._calculate_correlation_score(smb_vuln, kernel_vuln)
                
                if correlation_score > 0.6:
                    correlation = {
                        "smb_vulnerability": smb_vuln.id,
                        "kernel_vulnerability": kernel_vuln.id,
                        "correlation_type": self._determine_correlation_type(smb_vuln, kernel_vuln),
                        "correlation_score": correlation_score,
                        "shared_patterns": self._find_shared_patterns(smb_vuln, kernel_vuln),
                        "combined_risk": self._assess_combined_risk(smb_vuln, kernel_vuln)
                    }
                    correlations.append(correlation)
                    
                    # Update vulnerability cross-correlations
                    smb_vuln.cross_system_correlations.append(kernel_vuln.id)
                    kernel_vuln.cross_system_correlations.append(smb_vuln.id)
        
        return correlations
    
    def _calculate_correlation_score(self, vuln1: UnifiedVulnerability, 
                                   vuln2: UnifiedVulnerability) -> float:
        """Calculate correlation score between two vulnerabilities"""
        score = 0.0
        
        # Same vulnerability type
        if vuln1.vulnerability_type == vuln2.vulnerability_type:
            score += 0.4
        
        # Similar risk levels
        risk_levels = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        risk_diff = abs(risk_levels.get(vuln1.risk_level, 0) - risk_levels.get(vuln2.risk_level, 0))
        score += 0.2 * (1 - risk_diff / 3)
        
        # Temporal characteristics similarity
        if ("use_after_free" in vuln1.vulnerability_type and 
            "use_after_free" in vuln2.vulnerability_type):
            score += 0.3
        
        # Detection signature overlap
        sig_overlap = len(set(vuln1.detection_signatures) & set(vuln2.detection_signatures))
        score += 0.1 * min(sig_overlap / max(len(vuln1.detection_signatures), 1), 1.0)
        
        return min(score, 1.0)
    
    def _determine_correlation_type(self, vuln1: UnifiedVulnerability, 
                                   vuln2: UnifiedVulnerability) -> str:
        """Determine type of correlation between vulnerabilities"""
        if vuln1.vulnerability_type == vuln2.vulnerability_type:
            return "same_vulnerability_type"
        elif ("race" in vuln1.vulnerability_type and "race" in vuln2.vulnerability_type):
            return "related_race_conditions"
        elif ("memory" in vuln1.vulnerability_type or "memory" in vuln2.vulnerability_type):
            return "memory_related"
        else:
            return "pattern_similarity"
    
    def _find_shared_patterns(self, vuln1: UnifiedVulnerability, 
                            vuln2: UnifiedVulnerability) -> List[str]:
        """Find shared patterns between vulnerabilities"""
        shared = []
        
        # Check for shared vulnerability types
        if "use_after_free" in vuln1.vulnerability_type and "use_after_free" in vuln2.vulnerability_type:
            shared.append("use_after_free_pattern")
        
        if "race" in vuln1.vulnerability_type and "race" in vuln2.vulnerability_type:
            shared.append("race_condition_pattern")
        
        # Check temporal characteristics
        if (vuln1.temporal_characteristics.get("timing_window_ms", 0) < 10 and
            vuln2.temporal_characteristics.get("temporal_window_ms", 0) < 10):
            shared.append("tight_timing_window")
        
        return shared
    
    def _assess_combined_risk(self, vuln1: UnifiedVulnerability, 
                            vuln2: UnifiedVulnerability) -> str:
        """Assess combined risk when vulnerabilities are correlated"""
        risk_levels = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
        
        max_risk = max(risk_levels.get(vuln1.risk_level, 0), 
                      risk_levels.get(vuln2.risk_level, 0))
        
        # Escalate risk for correlated vulnerabilities
        if max_risk >= 2:  # HIGH or CRITICAL
            return "CRITICAL"
        elif max_risk >= 1:  # MEDIUM
            return "HIGH"
        else:
            return "MEDIUM"
    
    def _generate_discovery_report(self, vulnerabilities: List[UnifiedVulnerability], 
                                 correlations: List[Dict], total_time: float) -> DiscoveryReport:
        """Generate comprehensive discovery report"""
        
        # Count by system
        by_system = {}
        for vuln in vulnerabilities:
            system = vuln.target_system
            by_system[system] = by_system.get(system, 0) + 1
        
        # Count by risk level
        by_risk_level = {}
        for vuln in vulnerabilities:
            risk = vuln.risk_level
            by_risk_level[risk] = by_risk_level.get(risk, 0) + 1
        
        # Count by source
        by_source = {}
        for vuln in vulnerabilities:
            source = vuln.vulnerability_source.value
            by_source[source] = by_source.get(source, 0) + 1
        
        # Count novel patterns (vulnerabilities from unknown/anomaly sources)
        novel_patterns = len([v for v in vulnerabilities 
                            if v.vulnerability_source in [VulnerabilitySource.UNKNOWN_PATTERN,
                                                         VulnerabilitySource.ANOMALY_DETECTION,
                                                         VulnerabilitySource.NOVEL_COMBINATION]])
        
        # Calculate detection coverage
        detection_coverage = {
            "smb_concurrent": len([v for v in vulnerabilities if v.discovery_system == DiscoverySystemType.SMB_CONCURRENT]),
            "smb_anomaly": len([v for v in vulnerabilities if v.discovery_system == DiscoverySystemType.SMB_STATE_ANOMALY]),
            "smb_differential": len([v for v in vulnerabilities if v.discovery_system == DiscoverySystemType.SMB_DIFFERENTIAL]),
            "kernel_race": len([v for v in vulnerabilities if v.discovery_system == DiscoverySystemType.KERNEL_RACE])
        }
        
        # Performance metrics
        performance_metrics = {
            "total_discovery_time_seconds": total_time,
            "vulnerabilities_per_second": len(vulnerabilities) / total_time if total_time > 0 else 0,
            "average_confidence_score": sum(v.confidence_score for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0,
            "high_confidence_count": len([v for v in vulnerabilities if v.confidence_score > 0.7])
        }
        
        # Integration recommendations
        integration_recommendations = [
            f"Integrate {len(vulnerabilities)} new detection signatures into existing detectors",
            f"Implement cross-system correlation monitoring for {len(correlations)} correlated patterns",
            f"Prioritize {by_risk_level.get('CRITICAL', 0)} critical vulnerabilities for immediate analysis",
            "Deploy temporal analysis for race condition detection",
            "Implement anomaly detection for state machine violations"
        ]
        
        return DiscoveryReport(
            total_vulnerabilities=len(vulnerabilities),
            by_system=by_system,
            by_risk_level=by_risk_level,
            by_source=by_source,
            novel_patterns=novel_patterns,
            cross_system_correlations=len(correlations),
            detection_coverage=detection_coverage,
            performance_metrics=performance_metrics,
            integration_recommendations=integration_recommendations
        )
    
    def export_for_detector_integration(self) -> Dict:
        """Export all findings for integration with existing detectors"""
        integration_data = {
            "smb_signatures": [],
            "kernel_signatures": [],
            "cross_system_patterns": [],
            "anomaly_patterns": [],
            "temporal_analysis_rules": []
        }
        
        for vuln in self.discovered_vulnerabilities:
            # SMB-related signatures
            if vuln.target_system == "smb":
                for signature in vuln.detection_signatures:
                    integration_data["smb_signatures"].append({
                        "pattern": signature,
                        "risk_level": vuln.risk_level,
                        "confidence": vuln.confidence_score,
                        "vulnerability_type": vuln.vulnerability_type,
                        "source_system": vuln.discovery_system.value
                    })
            
            # Kernel-related signatures
            elif vuln.target_system == "kernel":
                for signature in vuln.detection_signatures:
                    integration_data["kernel_signatures"].append({
                        "pattern": signature,
                        "risk_level": vuln.risk_level,
                        "confidence": vuln.confidence_score,
                        "vulnerability_type": vuln.vulnerability_type,
                        "subsystem": vuln.affected_components[0] if vuln.affected_components else "unknown"
                    })
            
            # Cross-system patterns
            if vuln.cross_system_correlations:
                integration_data["cross_system_patterns"].append({
                    "primary_vulnerability": vuln.id,
                    "correlated_vulnerabilities": vuln.cross_system_correlations,
                    "pattern_type": vuln.vulnerability_type,
                    "combined_risk": "CRITICAL" if vuln.risk_level == "CRITICAL" else "HIGH"
                })
            
            # Anomaly detection patterns
            if vuln.vulnerability_source == VulnerabilitySource.ANOMALY_DETECTION:
                integration_data["anomaly_patterns"].append({
                    "anomaly_signature": vuln.detection_signatures[0] if vuln.detection_signatures else "",
                    "confidence_threshold": vuln.confidence_score,
                    "target_system": vuln.target_system,
                    "temporal_characteristics": vuln.temporal_characteristics
                })
            
            # Temporal analysis rules
            if vuln.temporal_characteristics:
                integration_data["temporal_analysis_rules"].append({
                    "vulnerability_id": vuln.id,
                    "timing_constraints": vuln.temporal_characteristics,
                    "detection_window": vuln.temporal_characteristics.get("timing_window_ms", 
                                                                        vuln.temporal_characteristics.get("temporal_window_ms", 1000))
                })
        
        return integration_data
    
    def generate_summary_report(self) -> str:
        """Generate human-readable summary report"""
        if not self.discovered_vulnerabilities:
            return "No vulnerabilities discovered yet. Run comprehensive discovery first."
        
        report = self._generate_discovery_report(self.discovered_vulnerabilities, self.cross_correlations, 0)
        
        summary = f"""
🔍 **ZeroBuilder Unknown Vulnerability Discovery Report**
=========================================================

📊 **Discovery Summary:**
   Total Vulnerabilities: {report.total_vulnerabilities}
   Novel Patterns: {report.novel_patterns}
   Cross-System Correlations: {report.cross_system_correlations}

🎯 **By Target System:**
"""
        for system, count in report.by_system.items():
            summary += f"   {system.upper()}: {count}\n"
        
        summary += f"""
⚠️  **By Risk Level:**
"""
        for risk, count in report.by_risk_level.items():
            summary += f"   {risk}: {count}\n"
        
        summary += f"""
🔬 **By Discovery Source:**
"""
        for source, count in report.by_source.items():
            summary += f"   {source.replace('_', ' ').title()}: {count}\n"
        
        summary += f"""
📈 **Performance Metrics:**
   Discovery Rate: {report.performance_metrics['vulnerabilities_per_second']:.1f} vulns/sec
   Average Confidence: {report.performance_metrics['average_confidence_score']:.2f}
   High Confidence: {report.performance_metrics['high_confidence_count']}

🔧 **Integration Status:**
   SMB Signatures: {len([v for v in self.discovered_vulnerabilities if v.target_system == 'smb'])}
   Kernel Signatures: {len([v for v in self.discovered_vulnerabilities if v.target_system == 'kernel'])}
   
✅ **Ready for Multi-LLM Validation**
"""
        
        return summary

def main():
    """Run unified unknown vulnerability discovery system"""
    print("🚀 ZeroBuilder Unified Unknown Vulnerability Discovery System")
    print("Comprehensive integration of all discovery methods")
    print("=" * 80)
    
    # Initialize unified system
    unified_system = UnifiedDiscoverySystem()
    
    # Run comprehensive discovery
    print("\n🔍 Running Comprehensive Vulnerability Discovery...")
    report = unified_system.run_comprehensive_discovery()
    
    # Display results
    print(f"\n📊 **DISCOVERY RESULTS:**")
    print(f"   Total Vulnerabilities: {report.total_vulnerabilities}")
    print(f"   Novel Patterns: {report.novel_patterns}")
    print(f"   Cross-System Correlations: {report.cross_system_correlations}")
    
    print(f"\n🎯 **By Target System:**")
    for system, count in report.by_system.items():
        print(f"   {system.upper()}: {count}")
    
    print(f"\n⚠️  **By Risk Level:**")
    for risk, count in report.by_risk_level.items():
        print(f"   {risk}: {count}")
    
    print(f"\n🔬 **Discovery Methods:**")
    for method, count in report.detection_coverage.items():
        print(f"   {method.replace('_', ' ').title()}: {count}")
    
    print(f"\n📈 **Performance:**")
    print(f"   Discovery Time: {report.performance_metrics['total_discovery_time_seconds']:.2f}s")
    print(f"   Discovery Rate: {report.performance_metrics['vulnerabilities_per_second']:.1f} vulns/sec")
    print(f"   Average Confidence: {report.performance_metrics['average_confidence_score']:.2f}")
    
    # Export for integration
    print(f"\n🔧 **Integration Preparation:**")
    integration_data = unified_system.export_for_detector_integration()
    print(f"   SMB Signatures: {len(integration_data['smb_signatures'])}")
    print(f"   Kernel Signatures: {len(integration_data['kernel_signatures'])}")
    print(f"   Cross-System Patterns: {len(integration_data['cross_system_patterns'])}")
    print(f"   Anomaly Patterns: {len(integration_data['anomaly_patterns'])}")
    
    print(f"\n✅ **Integration Recommendations:**")
    for recommendation in report.integration_recommendations[:5]:
        print(f"   • {recommendation}")
    
    print(f"\n🎉 **Unified Discovery Complete!**")
    print(f"⚡ Ready for Multi-LLM validation with {report.total_vulnerabilities} discoveries")
    print(f"💰 Cost Efficiency: Comprehensive unknown vulnerability discovery completed locally")
    
    return unified_system, report

if __name__ == "__main__":
    main()