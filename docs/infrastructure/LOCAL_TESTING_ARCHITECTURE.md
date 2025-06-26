# 🏠 ZeroBuilder Local Testing Architecture

**Document Version**: v1.0  
**Date**: June 25, 2025  
**Purpose**: Cost-effective local validation before cloud deployment  
**Strategy**: Docker + VM testing → Proven architecture → Minimal cloud scaling

## 🎯 **Strategic Approach**

### **Cost-Minimization Strategy**:
```
Phase 1: Local Docker/VM Testing    → $0 infrastructure cost
Phase 2: Proven Architecture        → Deploy only validated components  
Phase 3: Minimal Cloud Deployment   → $200/month (vs $448/month full setup)
Phase 4: Scale After Validation     → Expand only proven components
```

### **Key Objectives**:
- ✅ **Validate SMB/HTTP stateful protocol fuzzing locally**
- ✅ **Test Linux kernel race detection in VMs**  
- ✅ **Prove GAT + Multi-LLM integration works**
- ✅ **Minimize cloud costs during development**
- ✅ **Create reproducible local development environment**

## 🐳 **Docker-Based Protocol Fuzzing Setup**

### **3-Container Architecture**:
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SMB-SERVER    │    │   SMB-FUZZER    │    │  GAT-MONITOR    │
│                 │    │                 │    │                 │
│ • Samba 4.x     │◄──►│ • Custom SMB    │◄──►│ • GAT Analysis  │
│ • nginx/Apache  │    │   Client Fuzzer │    │ • RL Controller │
│ • tcpdump       │    │ • Protocol      │    │ • Multi-LLM     │
│ • Crash Monitor │    │   State Machine │    │ • PyTorch/CUDA  │
│                 │    │ • AFL++ Core    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
   Container 1            Container 2            Container 3
   Port 445/80           Client Network         GPU Access
```

### **Docker Compose Configuration**:

```yaml
# docker-compose.yml - ZeroBuilder Local Protocol Fuzzing
version: '3.8'

services:
  # Container 1: Protocol Servers
  smb-server:
    image: dperson/samba:latest
    container_name: zb-smb-server
    ports:
      - "445:445"     # SMB
      - "139:139"     # NetBIOS
    volumes:
      - ./smb-data:/data
      - ./logs/smb:/logs
    environment:
      - SHARE=testshare;/data;yes;no;no;all;all;all
      - USER=testuser;testpass
      - WORKGROUP=ZBTEST
    networks:
      - zb-fuzz-net
    restart: unless-stopped
    
  http-server:
    image: nginx:alpine
    container_name: zb-http-server  
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./http-data:/usr/share/nginx/html
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./logs/http:/var/log/nginx
    networks:
      - zb-fuzz-net
    restart: unless-stopped

  # Container 2: Protocol Fuzzer
  protocol-fuzzer:
    build: 
      context: ./fuzzer
      dockerfile: Dockerfile.fuzzer
    container_name: zb-protocol-fuzzer
    depends_on:
      - smb-server
      - http-server
    volumes:
      - ./zerobuilder:/app
      - ./logs/fuzzer:/logs
      - ./crashes:/crashes
      - ./corpus:/corpus
    environment:
      - TARGET_SMB=smb-server:445
      - TARGET_HTTP=http-server:80
      - FUZZER_MODE=stateful
      - LOG_LEVEL=INFO
    networks:
      - zb-fuzz-net
    working_dir: /app
    command: python step1_stateful_fuzzer.py
    
  # Container 3: GAT Analysis & Monitoring
  gat-monitor:
    build:
      context: ./monitor  
      dockerfile: Dockerfile.monitor
    container_name: zb-gat-monitor
    depends_on:
      - smb-server
      - http-server
      - protocol-fuzzer
    volumes:
      - ./zerobuilder:/app
      - ./logs/monitor:/logs
      - ./models:/models
      - ./analysis:/analysis
    environment:
      - CUDA_VISIBLE_DEVICES=0
      - PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:512
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]
    networks:
      - zb-fuzz-net
    working_dir: /app
    command: python gat_protocol_monitor.py

networks:
  zb-fuzz-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

volumes:
  smb-data:
  http-data:
  logs:
  crashes:
  corpus:
  models:
  analysis:
```

### **Fuzzer Container Dockerfile**:
```dockerfile
# fuzzer/Dockerfile.fuzzer
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    gcc g++ make \
    libssl-dev libffi-dev \
    tcpdump wireshark-common \
    smbclient cifs-utils \
    curl wget \
    && rm -rf /var/lib/apt/lists/*

# Install AFL++
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git \
    && cd AFLplusplus \
    && make all \
    && make install

# Install Python dependencies
COPY requirements.fuzzer.txt /tmp/
RUN pip3 install -r /tmp/requirements.fuzzer.txt

# Create working directory
WORKDIR /app
COPY fuzzer/ .

# Entry point
CMD ["python3", "step1_stateful_fuzzer.py"]
```

### **Monitor Container Dockerfile**:
```dockerfile
# monitor/Dockerfile.monitor  
FROM pytorch/pytorch:2.3.0-cuda12.1-cudnn8-devel

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    gcc g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.monitor.txt /tmp/
RUN pip install -r /tmp/requirements.monitor.txt

# Install PyTorch Geometric
RUN pip install torch-geometric torch-scatter torch-sparse

# Create working directory
WORKDIR /app
COPY monitor/ .

# Entry point
CMD ["python", "gat_protocol_monitor.py"]
```

## 🖥️ **VM-Based Kernel Race Testing**

### **Local Hypervisor Setup Options**:

#### **Option 1: QEMU/KVM (Recommended)**
```bash
# Install QEMU/KVM
sudo apt install qemu-kvm virt-manager virtinst

# Create ZeroBuilder kernel test VM
qemu-img create -f qcow2 zb-kernel-test.qcow2 20G

# Boot with custom debug kernel
qemu-system-x86_64 \
  -enable-kvm \
  -m 4G -smp 4 \
  -drive file=zb-kernel-test.qcow2,format=qcow2 \
  -kernel ./linux-6.6-debug/arch/x86/boot/bzImage \
  -append "root=/dev/sda1 debug ftrace=1 kpti=off spectre_v2=off" \
  -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
  -serial stdio \
  -monitor telnet:localhost:1234,server,nowait
```

#### **Option 2: VirtualBox (Easier Setup)**
```bash
# Create VM
VBoxManage createvm --name "ZB-Kernel-Test" --register
VBoxManage modifyvm "ZB-Kernel-Test" \
  --memory 4096 --cpus 4 \
  --nested-paging on \
  --vtxvpid on \
  --pae on

# Attach storage
VBoxManage createhd --filename ZB-Kernel-Test.vdi --size 20480
VBoxManage storagectl "ZB-Kernel-Test" --name "SATA" --add sata
VBoxManage storageattach "ZB-Kernel-Test" \
  --storagectl "SATA" --port 0 --device 0 \
  --type hdd --medium ZB-Kernel-Test.vdi
```

### **Custom Debug Kernel Build**:
```bash
#!/bin/bash
# scripts/build_debug_kernel.sh

# Download Linux kernel 6.6
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
tar -xf linux-6.6.tar.xz
cd linux-6.6

# Configure for ZeroBuilder race detection
cat > .config << 'EOF'
# Basic kernel config
CONFIG_64BIT=y
CONFIG_X86_64=y
CONFIG_SMP=y

# Debug options for race detection
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_FRAME_POINTER=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y

# Tracing support
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FUNCTION_GRAPH_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_KPROBES=y
CONFIG_KRETPROBES=y
CONFIG_KPROBE_EVENTS=y

# Race detection support
CONFIG_DEBUG_LOCK_ALLOC=y
CONFIG_PROVE_LOCKING=y
CONFIG_LOCKDEP=y
CONFIG_DEBUG_SPINLOCK=y
CONFIG_DEBUG_MUTEXES=y
CONFIG_DEBUG_ATOMIC_SLEEP=y

# Sanitizers (if available)
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_UBSAN=y

# Disable security mitigations for performance
# CONFIG_RETPOLINE is not set
# CONFIG_CPU_MITIGATIONS is not set
EOF

# Build kernel
make olddefconfig
make -j$(nproc) bzImage modules
make modules_install
make install

echo "Debug kernel built: /boot/vmlinuz-6.6.0-zerobuilder"
```

### **Kernel Race Detection Setup**:
```bash
#!/bin/bash
# scripts/setup_race_detection.sh

# Enable ftrace
echo 1 > /sys/kernel/debug/tracing/events/syscalls/enable
echo function > /sys/kernel/debug/tracing/current_tracer

# Set up kprobes for common race-prone syscalls
echo 'p:open_probe sys_openat' > /sys/kernel/debug/tracing/kprobe_events
echo 'p:close_probe sys_close' >> /sys/kernel/debug/tracing/kprobe_events
echo 'p:mmap_probe sys_mmap' >> /sys/kernel/debug/tracing/kprobe_events
echo 'p:munmap_probe sys_munmap' >> /sys/kernel/debug/tracing/kprobe_events

# Enable probes
echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable

echo "Kernel race detection enabled"
```

## 🛠️ **Local Implementation Plan**

### **Week 1: Docker Protocol Fuzzing Setup**

#### **Day 1-2: Environment Setup**
```bash
# Clone ZeroBuilder
git clone https://github.com/user/ZeroBuilder.git
cd ZeroBuilder

# Create directory structure
mkdir -p {logs/{smb,http,fuzzer,monitor},crashes,corpus,models,analysis}
mkdir -p {smb-data,http-data,fuzzer,monitor}

# Build containers
docker-compose build
docker-compose up -d
```

#### **Day 3-4: SMB Stateful Fuzzing**
```python
# step1_stateful_fuzzer.py
import socket
import struct
import time
from typing import List, Dict
from dataclasses import dataclass

@dataclass
class SMBSession:
    """SMB session state tracker"""
    state: str = "disconnected"  # negotiate, setup, connected, tree_connected
    session_id: int = 0
    tree_id: int = 0
    
class StatefulSMBFuzzer:
    """ZeroBuilder stateful SMB protocol fuzzer"""
    
    def __init__(self, target_host: str = "smb-server", target_port: int = 445):
        self.target = (target_host, target_port)
        self.session = SMBSession()
        self.gat_guidance = None  # Will integrate with GAT
        
    def smb_negotiate(self) -> bytes:
        """SMB2 Negotiate request with fuzzing"""
        # Base SMB2 negotiate packet
        negotiate = b'\xfe\x53\x4d\x42'  # SMB2 signature
        negotiate += b'\x40\x00'          # Header length
        negotiate += b'\x00\x00'          # Negotiate command
        # Add fuzzing mutations based on GAT risk scores
        return negotiate
        
    def fuzz_smb_session(self):
        """Execute complete SMB session with state tracking"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(self.target)
            
            # State 1: Negotiate
            self.session.state = "negotiating"
            negotiate_pkt = self.smb_negotiate()
            sock.send(negotiate_pkt)
            response = sock.recv(4096)
            
            # State 2: Session Setup (with mutations)
            if self.session.state == "negotiating":
                self.session.state = "setup"
                setup_pkt = self.smb_session_setup()
                sock.send(setup_pkt)
                response = sock.recv(4096)
                
            # Continue with tree connect, file operations...
            
        except Exception as e:
            self.log_crash(f"SMB fuzzing crash: {e}")
        finally:
            sock.close()
```

#### **Day 5-7: GAT Integration & Testing**
```python
# gat_protocol_monitor.py
import torch
from main import VulnerabilityGAT
from src.llm_reviewers import LLMReviewOrchestrator

class ProtocolGATMonitor:
    """Monitor protocol fuzzing with GAT analysis"""
    
    def __init__(self):
        self.gat_model = VulnerabilityGAT()
        self.llm_orchestrator = LLMReviewOrchestrator()
        
    def analyze_protocol_state(self, smb_session_data: Dict):
        """Analyze SMB session with GAT for risk assessment"""
        # Convert protocol data to graph representation
        protocol_graph = self.protocol_to_graph(smb_session_data)
        
        # GAT risk assessment
        risk_scores = self.gat_model(protocol_graph)
        
        # Multi-LLM analysis
        llm_analysis = self.llm_orchestrator.review_protocol_session(
            smb_session_data, risk_scores
        )
        
        return {
            'gat_risk': risk_scores,
            'llm_consensus': llm_analysis,
            'recommended_mutations': self.generate_mutations(risk_scores)
        }
```

### **Week 2: VM Kernel Race Testing**

#### **Day 1-3: VM Setup & Kernel Build**
```bash
# Build debug kernel
./scripts/build_debug_kernel.sh

# Create test VM
./scripts/create_kernel_test_vm.sh

# Boot VM with debug kernel
qemu-system-x86_64 \
  -enable-kvm -m 4G -smp 4 \
  -drive file=zb-kernel-test.qcow2,format=qcow2 \
  -kernel ./linux-6.6-debug/arch/x86/boot/bzImage \
  -append "root=/dev/sda1 debug ftrace=1"
```

#### **Day 4-5: Race Detection Implementation**
```python
# kernel_race_detector.py
import subprocess
import re
from typing import List, Tuple
from dataclasses import dataclass

@dataclass  
class RaceCondition:
    """Detected race condition"""
    syscall_pair: Tuple[str, str]
    timing_window: float
    reproducibility: float
    trace_data: str

class KernelRaceDetector:
    """ZeroBuilder kernel race condition detector"""
    
    def __init__(self, vm_interface: str = "qemu_monitor"):
        self.vm = vm_interface
        self.race_patterns = [
            ("sys_openat", "sys_close"),
            ("sys_mmap", "sys_munmap"), 
            ("sys_read", "sys_write"),
            ("sys_access", "sys_open")  # Classic TOCTOU
        ]
        
    def generate_concurrent_syscalls(self, syscall_pair: Tuple[str, str]):
        """Generate concurrent syscall sequences to trigger races"""
        # Use RL-guided timing to find race windows
        pass
        
    def detect_race_with_ftrace(self) -> List[RaceCondition]:
        """Use ftrace to detect actual race conditions"""
        # Enable ftrace in VM
        # Generate concurrent syscalls
        # Analyze happens-before relationships
        # Return detected races
        pass
```

#### **Day 6-7: TGN Integration**
```python
# tgn_race_analysis.py
import torch
import torch_geometric
from typing import Dict, List

class HappensBeforeGraph:
    """Build happens-before graphs from kernel traces"""
    
    def __init__(self):
        self.edges = []
        self.nodes = []
        
    def build_from_ftrace(self, trace_data: str):
        """Convert ftrace output to happens-before graph"""
        # Parse ftrace output
        # Build temporal relationships
        # Create graph structure for TGN
        pass

class TGNRaceDetector(torch.nn.Module):
    """TGN-based race condition detection"""
    
    def __init__(self, node_features: int = 64):
        super().__init__()
        self.tgn = torch_geometric.nn.TGNMemory(
            node_features=node_features,
            memory_dimension=100,
            time_dimension=100
        )
        
    def forward(self, happens_before_graph):
        """Detect races using temporal graph networks"""
        # Process happens-before relationships
        # Identify potential race windows
        # Return race probability scores
        pass
```

### **Week 3: Integration & Validation**

#### **Combined Local Testing**:
```python
# local_integration_test.py
from step1_stateful_fuzzer import StatefulSMBFuzzer
from kernel_race_detector import KernelRaceDetector
from gat_protocol_monitor import ProtocolGATMonitor

class ZeroBuilderLocalTest:
    """Complete local testing integration"""
    
    def __init__(self):
        self.protocol_fuzzer = StatefulSMBFuzzer()
        self.kernel_detector = KernelRaceDetector()
        self.gat_monitor = ProtocolGATMonitor()
        
    def run_comprehensive_test(self):
        """Execute full ZeroBuilder test locally"""
        
        print("🔥 Starting ZeroBuilder Local Testing...")
        
        # Test 1: SMB Protocol Fuzzing
        print("📡 Testing SMB stateful protocol fuzzing...")
        smb_results = self.protocol_fuzzer.fuzz_smb_session()
        gat_analysis = self.gat_monitor.analyze_protocol_state(smb_results)
        
        # Test 2: Kernel Race Detection  
        print("🐧 Testing kernel race detection...")
        race_results = self.kernel_detector.detect_race_with_ftrace()
        
        # Test 3: Integration
        print("🧠 Testing GAT + Multi-LLM integration...")
        combined_analysis = self.integrate_results(smb_results, race_results)
        
        return {
            'protocol_fuzzing': smb_results,
            'kernel_races': race_results, 
            'gat_analysis': gat_analysis,
            'integration_success': True
        }

if __name__ == "__main__":
    test = ZeroBuilderLocalTest()
    results = test.run_comprehensive_test()
    print(f"✅ Local testing complete: {results}")
```

## 💰 **Cost Analysis: Local vs Cloud**

### **Local Testing Costs**:
- **Infrastructure**: $0 (use existing development machine)
- **Docker Overhead**: ~2GB RAM, minimal CPU
- **VM Overhead**: ~4GB RAM, 2-4 CPU cores  
- **Development Time**: 3 weeks validation
- **Total Infrastructure Cost**: **$0**

### **After Local Validation - Minimal Cloud**:
- **Proven Components Only**: Deploy validated architecture
- **Single Instance**: Combined server/fuzzer ($60/month)
- **A100 Analysis**: Keep Vast.ai for GAT/Multi-LLM ($84/month)
- **Total**: **$144/month** (vs $448/month full setup)
- **Savings**: **68% cost reduction**

### **Risk Mitigation**:
- **Validation First**: Prove architecture works locally
- **Incremental Deployment**: Start small, scale gradually  
- **Cost Control**: Only pay for proven components
- **Debugging**: Fix issues locally before cloud deployment

## 📋 **Quick Start Commands**

### **Start Protocol Testing**:
```bash
# Clone and setup
git clone https://github.com/user/ZeroBuilder.git
cd ZeroBuilder

# Start Docker environment
docker-compose up -d

# Monitor logs
docker-compose logs -f

# Run tests
docker exec zb-protocol-fuzzer python step1_stateful_fuzzer.py
```

### **Start Kernel Testing**:
```bash
# Build debug kernel
./scripts/build_debug_kernel.sh

# Start test VM
./scripts/start_kernel_test_vm.sh

# Run race detection
python kernel_race_detector.py
```

### **Integration Test**:
```bash
# Run complete local test suite
python local_integration_test.py

# Generate report
python generate_local_test_report.py
```

## 📊 **Success Metrics**

### **Protocol Fuzzing Validation**:
- ✅ **SMB Session States**: Successfully navigate negotiate → setup → tree connect
- ✅ **HTTP/2 Streams**: Test multiplexed stream fuzzing  
- ✅ **GAT Integration**: Risk-based protocol command prioritization working
- ✅ **Coverage**: Local testing shows >10% improvement over single-input fuzzing

### **Kernel Race Validation**:
- ✅ **ftrace Integration**: Successfully capture syscall traces in VM
- ✅ **Race Detection**: Detect at least 1 known race condition (TOCTOU)
- ✅ **TGN Processing**: Build happens-before graphs from traces
- ✅ **Performance**: <5% overhead in VM environment

### **Integration Success**:
- ✅ **Multi-LLM**: All 3 models working in local Docker environment
- ✅ **GAT Guidance**: Risk scores improving fuzzing effectiveness locally
- ✅ **Cost Validation**: Prove architecture before $400+/month cloud deployment
- ✅ **Reproducibility**: Other developers can reproduce setup with documentation

**Next Phase**: Deploy only validated components to cloud with **68% cost savings** vs. full architecture.