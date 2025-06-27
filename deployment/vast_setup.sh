#!/bin/bash
# ZeroBuilder Vast.ai Instance Setup Script
# Automated environment setup from scratch for RTX 8000

set -e  # Exit on any error

echo "🚀 ZeroBuilder Vast.ai Setup - Starting..."
echo "💰 Budget tracking initialized"

# Record start time for cost monitoring
echo "SETUP_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')" > /tmp/session_metadata.env
echo "INSTANCE_START_TIME=$(date +%s)" >> /tmp/session_metadata.env

# System updates and basic tools
echo "📦 Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    git \
    curl \
    wget \
    htop \
    tmux \
    unzip \
    build-essential \
    cmake \
    libssl-dev \
    pkg-config

# Install UV for fast Python package management
echo "⚡ Installing UV package manager..."
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.cargo/bin:$PATH"
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc

# Create workspace
echo "📁 Setting up workspace..."
mkdir -p ~/zerobuilder_workspace
cd ~/zerobuilder_workspace

# Clone ZeroBuilder repository
echo "📥 Cloning ZeroBuilder repository..."
git clone https://github.com/iptracej-education/ZeroBuilder.git
cd ZeroBuilder

# Check for continuation data
echo "🔍 Checking for continuation data..."
if [ -f ~/continuation_data.tar.gz ]; then
    echo "📦 Found continuation data - extracting..."
    tar -xzf ~/continuation_data.tar.gz -C ~/zerobuilder_workspace/ZeroBuilder/
    echo "✅ Session state restored"
else
    echo "🆕 Starting fresh session"
fi

# Setup Python environment
echo "🐍 Setting up Python environment..."
uv sync

# Install additional ML dependencies for Multi-LLM
echo "🤖 Installing Multi-LLM dependencies..."
uv add transformers torch accelerate datasets tokenizers
uv add huggingface-hub
uv add gymnasium stable-baselines3

# Download and setup models
echo "📥 Downloading LLM models..."
python3 -c "
import os
from huggingface_hub import hf_hub_download, snapshot_download

print('Downloading CodeLlama Python 7B...')
snapshot_download(
    repo_id='codellama/CodeLlama-7b-Python-hf',
    cache_dir='./models/codellama',
    local_files_only=False
)

print('Downloading StarCoder 2 7B...')  
snapshot_download(
    repo_id='bigcode/starcoder2-7b',
    cache_dir='./models/starcoder2', 
    local_files_only=False
)

print('Downloading DeepSeekCoder 6.7B...')
snapshot_download(
    repo_id='deepseek-ai/deepseek-coder-6.7b-base',
    cache_dir='./models/deepseek',
    local_files_only=False
)

print('✅ All models downloaded successfully')
"

# Create session tracking
echo "📊 Initializing session tracking..."
python3 << 'EOF'
import json
import time
from datetime import datetime

session_data = {
    "session_id": f"session_{int(time.time())}",
    "start_time": datetime.now().isoformat(),
    "setup_completed": True,
    "validation_progress": {
        "total_patterns": 12843,
        "validated_patterns": 0,
        "current_batch": 0,
        "completed_batches": []
    },
    "models_ready": True,
    "budget_remaining": 249.77,
    "estimated_hourly_cost": 0.20
}

with open('session_state.json', 'w') as f:
    json.dump(session_data, f, indent=2)

print("✅ Session state initialized")
EOF

# Setup completion
echo "SETUP_END_TIME=$(date '+%Y-%m-%d %H:%M:%S')" >> /tmp/session_metadata.env
setup_duration=$(($(date +%s) - $(grep INSTANCE_START_TIME /tmp/session_metadata.env | cut -d= -f2)))
echo "SETUP_DURATION_SECONDS=$setup_duration" >> /tmp/session_metadata.env

echo ""
echo "🎉 ZeroBuilder Setup Complete!"
echo "⏱️  Setup time: $setup_duration seconds"
echo "💾 Session state saved to session_state.json"
echo "🤖 All LLM models ready for validation"
echo ""
echo "Next steps:"
echo "1. Run: ./deployment/validation_runner.py"
echo "2. Monitor: ./deployment/budget_monitor.py" 
echo "3. Export: ./deployment/pre_destroy_export.sh"
echo ""