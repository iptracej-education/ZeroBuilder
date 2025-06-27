#!/bin/bash
# ZeroBuilder Instance Cleanup Script
# Clean up resources and prepare for instance destruction

set -e

echo "🧹 ZeroBuilder Instance Cleanup - Starting..."
echo "🗑️ Preparing instance for destruction"

# Stop any running processes
echo "🛑 Stopping running processes..."
pkill -f "validation_runner.py" || true
pkill -f "budget_monitor.py" || true
pkill -f "python.*torch" || true

# Clear GPU memory
echo "🎮 Clearing GPU memory..."
if command -v nvidia-smi &> /dev/null; then
    nvidia-smi --gpu-reset || true
fi

# Clear Python caches
echo "🐍 Clearing Python caches..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Clear model caches
echo "🤖 Clearing model caches..."
rm -rf ~/.cache/huggingface/ 2>/dev/null || true
rm -rf ~/.cache/torch/ 2>/dev/null || true
rm -rf ./models/ 2>/dev/null || true

# Clear temporary files
echo "🗂️ Clearing temporary files..."
rm -rf /tmp/session_metadata.env 2>/dev/null || true
rm -rf /tmp/budget_* 2>/dev/null || true
rm -rf /tmp/pytorch_* 2>/dev/null || true

# Clear logs (except export archives)
echo "📜 Clearing logs..."
rm -f validation_session.log 2>/dev/null || true
rm -f budget_monitor.log 2>/dev/null || true
rm -f budget_checkpoint_*.json 2>/dev/null || true

# Clear build artifacts
echo "🔨 Clearing build artifacts..."
rm -rf build/ 2>/dev/null || true
rm -rf dist/ 2>/dev/null || true
rm -rf *.egg-info/ 2>/dev/null || true

# Show remaining files
echo "📋 Remaining files:"
ls -la

# Show disk usage
echo "💾 Current disk usage:"
df -h

# Create cleanup completion marker
echo "CLEANUP_COMPLETED=$(date)" > /tmp/cleanup_completed
echo "READY_FOR_DESTRUCTION=true" >> /tmp/cleanup_completed

echo ""
echo "✅ Instance Cleanup Complete!"
echo "🗑️ All temporary files and caches cleared"
echo "💾 GPU memory released"
echo "🛑 All background processes stopped"
echo ""
echo "⚠️ INSTANCE READY FOR DESTRUCTION"
echo "📦 Ensure all exports are downloaded before destroying instance"
echo ""