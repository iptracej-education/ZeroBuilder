#!/usr/bin/env python3
"""
ZeroBuilder Hybrid Multi-LLM Fallback Architecture Diagram Generator
Creates visual architecture diagrams using the Diagrams library
"""

from diagrams import Diagram, Cluster, Edge
from diagrams.generic.blank import Blank
from diagrams.programming.language import Python
from diagrams.onprem.analytics import Spark
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.aws.ml import SagemakerModel
from diagrams.gcp.ml import AutomlNaturalLanguage as AIModel
from diagrams.onprem.client import Client
import os

def create_hybrid_architecture_diagram():
    """Create the main hybrid architecture diagram"""
    
    with Diagram("ZeroBuilder Hybrid Multi-LLM Fallback Architecture", 
                 filename="docs/architecture/hybrid_architecture", 
                 show=False, 
                 direction="TB"):
        
        # Input Data
        with Cluster("Vulnerability Discovery Input"):
            vulnerability_patterns = Python("12,843 Patterns")
            afl_fuzzing = Server("AFL++ Fuzzing")
            smb_analysis = Server("SMB Analysis")
            kernel_racing = Server("Kernel Racing")
            
        # Smart Routing Layer
        with Cluster("Smart Routing Decision Engine"):
            decision_engine = Spark("Decision Engine")
            confidence_check = Blank("Confidence ≥75%?")
            pattern_type = Blank("Critical Pattern?")
            
        # Gemini Primary Path (85%)
        with Cluster("Gemini Primary Path (85%)"):
            gemini_api = AIModel("Gemini API")
            gemini_analysis = Python("Python Security")
            gemini_patterns = Python("Pattern Recognition")
            gemini_cross = Python("Cross-System")
            
        # Multi-LLM Fallback Path (15%)
        with Cluster("Multi-LLM Fallback (15%)"):
            codellama = SagemakerModel("CodeLlama 7B\n(35%)")
            starcoder = SagemakerModel("StarCoder 7B\n(35%)")
            deepseek = SagemakerModel("DeepSeek 6.7B\n(15%)")
            claude = SagemakerModel("Claude Code\n(15%)")
            
        # Result Processing
        with Cluster("Result Processing"):
            result_combiner = Spark("Result Combiner")
            final_validation = PostgreSQL("Final Validation")
            monitoring = Server("Monitoring & Stats")
            
        # Connections
        vulnerability_patterns >> decision_engine
        afl_fuzzing >> decision_engine
        smb_analysis >> decision_engine
        kernel_racing >> decision_engine
        
        decision_engine >> confidence_check
        decision_engine >> pattern_type
        
        # Routing paths
        confidence_check >> Edge(label="High Conf\n85%") >> gemini_api
        pattern_type >> Edge(label="Low Conf/Critical\n15%") >> codellama
        
        gemini_api >> [gemini_analysis, gemini_patterns, gemini_cross]
        
        [codellama, starcoder, deepseek, claude] >> result_combiner
        [gemini_analysis, gemini_patterns, gemini_cross] >> result_combiner
        
        result_combiner >> final_validation
        result_combiner >> monitoring

def create_smart_routing_flowchart():
    """Create the smart routing decision flowchart"""
    
    with Diagram("Smart Routing Decision Flow", 
                 filename="docs/architecture/smart_routing_flow", 
                 show=False, 
                 direction="TB"):
        
        # Input
        pattern_input = Python("New Pattern")
        
        # Primary Analysis
        with Cluster("Primary Analysis"):
            gemini_primary = AIModel("Gemini Primary")
            confidence_score = Blank("Confidence Score")
            
        # Decision Points
        with Cluster("Routing Decision"):
            confidence_check = Blank("Confidence ≥ 75%?")
            critical_check = Blank("Critical Pattern?")
            value_check = Blank("High Value?")
            
        # Routing Paths
        with Cluster("Validation Paths"):
            gemini_only = Python("Gemini Only\n(Fast & Cheap)")
            multi_llm = Spark("Multi-LLM Ensemble\n(Quality Assured)")
            
        # Final Processing
        with Cluster("Result Processing"):
            weighted_combo = Spark("Weighted Combination")
            final_result = PostgreSQL("Final Result")
            
        # Flow connections
        pattern_input >> gemini_primary >> confidence_score
        confidence_score >> confidence_check
        confidence_score >> critical_check
        confidence_score >> value_check
        
        confidence_check >> Edge(label="≥75%") >> gemini_only
        confidence_check >> Edge(label="<75%") >> multi_llm
        critical_check >> Edge(label="Yes") >> multi_llm
        value_check >> Edge(label="Yes") >> multi_llm
        
        [gemini_only, multi_llm] >> weighted_combo >> final_result

def create_cost_distribution_diagram():
    """Create cost and performance distribution diagram"""
    
    with Diagram("Cost & Performance Distribution", 
                 filename="docs/architecture/cost_distribution", 
                 show=False, 
                 direction="LR"):
        
        # Total System
        with Cluster("12,843 Patterns"):
            total_patterns = Python("Total Workload")
            
        # Gemini Path (85%)
        with Cluster("Gemini Primary (85%)"):
            gemini_patterns = Python("~10,917 patterns")
            gemini_cost = Blank("Cost: $21-34")
            gemini_time = Blank("Time: 5-8 hrs")
            gemini_quality = Blank("Quality: 88/100")
            
        # Multi-LLM Path (15%)
        with Cluster("Multi-LLM Fallback (15%)"):
            fallback_patterns = Python("~1,926 patterns")
            fallback_cost = Blank("Cost: $30-45")
            fallback_time = Blank("Time: 8-12 hrs")
            fallback_quality = Blank("Quality: Very High")
            
        # Results
        with Cluster("System Results"):
            total_cost = PostgreSQL("Total: $55-85\n(65-75% savings)")
            total_time = PostgreSQL("Total: 13-20 hrs")
            quality_improvement = PostgreSQL("Enhanced Quality")
            
        # Connections
        total_patterns >> Edge(label="85%") >> gemini_patterns
        total_patterns >> Edge(label="15%") >> fallback_patterns
        
        [gemini_cost, gemini_time, gemini_quality] >> total_cost
        [fallback_cost, fallback_time, fallback_quality] >> total_time
        
        [total_cost, total_time] >> quality_improvement

def create_deployment_architecture():
    """Create deployment architecture diagram"""
    
    with Diagram("Deployment Architecture", 
                 filename="docs/architecture/deployment_architecture", 
                 show=False, 
                 direction="TB"):
        
        # Local Environment
        with Cluster("Local Development"):
            local_machine = Server("Local Machine")
            validation_runner = Python("validation_runner.py")
            session_mgmt = PostgreSQL("Session Management")
            
        # Cloud Services
        with Cluster("Cloud Services"):
            with Cluster("Gemini API"):
                gemini_service = AIModel("Gemini API")
                gemini_cost = Blank("~$0.001/pattern")
                
            with Cluster("Vast.ai GPU"):
                rtx_8000 = Server("RTX 8000 48GB")
                codellama_model = SagemakerModel("CodeLlama")
                starcoder_model = SagemakerModel("StarCoder")
                deepseek_model = SagemakerModel("DeepSeek")
                
            with Cluster("Claude Code"):
                claude_service = AIModel("Claude API")
                orchestration = Spark("Orchestration")
                
        # Results Storage
        with Cluster("Results & Monitoring"):
            results_export = PostgreSQL("Results Export")
            monitoring_dash = Server("Monitoring Dashboard")
            cost_tracking = Blank("Cost Tracking")
            
        # Connections
        local_machine >> validation_runner
        validation_runner >> session_mgmt
        
        validation_runner >> gemini_service
        validation_runner >> rtx_8000
        validation_runner >> claude_service
        
        rtx_8000 >> [codellama_model, starcoder_model, deepseek_model]
        
        [gemini_service, rtx_8000, claude_service] >> results_export
        results_export >> monitoring_dash
        monitoring_dash >> cost_tracking

def main():
    """Generate all architecture diagrams"""
    print("🎨 Generating ZeroBuilder Hybrid Architecture Diagrams...")
    
    # Create docs/architecture directory if it doesn't exist
    os.makedirs("docs/architecture", exist_ok=True)
    
    try:
        print("📊 Creating main hybrid architecture diagram...")
        create_hybrid_architecture_diagram()
        
        print("🔄 Creating smart routing flowchart...")
        create_smart_routing_flowchart()
        
        print("💰 Creating cost distribution diagram...")
        create_cost_distribution_diagram()
        
        print("🚀 Creating deployment architecture...")
        create_deployment_architecture()
        
        print("✅ All diagrams generated successfully!")
        print("📁 Check docs/architecture/ for PNG files")
        
    except Exception as e:
        print(f"❌ Error generating diagrams: {e}")
        print("💡 Make sure you have 'diagrams' library installed:")
        print("   pip install diagrams")

if __name__ == "__main__":
    main()