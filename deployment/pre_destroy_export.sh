#!/bin/bash
# ZeroBuilder Pre-Destroy Export Script
# Export all validation results and session data before instance termination

set -e

echo "🚀 ZeroBuilder Pre-Destroy Export - Starting..."
echo "📦 Preparing data for export before instance destruction"

# Create export directory with timestamp
EXPORT_DIR="zerobuilder_export_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EXPORT_DIR"

echo "📁 Export directory: $EXPORT_DIR"

# Export session metadata
echo "📊 Exporting session metadata..."
if [ -f "/tmp/session_metadata.env" ]; then
    cp /tmp/session_metadata.env "$EXPORT_DIR/"
    echo "✅ Session metadata exported"
else
    echo "⚠️ No session metadata found"
fi

# Export validation session state
echo "🔄 Exporting validation session state..."
if [ -f "session_state.json" ]; then
    cp session_state.json "$EXPORT_DIR/"
    echo "✅ Session state exported"
else
    echo "⚠️ No session state found"
fi

# Export all validation results
echo "📋 Exporting validation results..."
find . -name "validation_results_*.json" -exec cp {} "$EXPORT_DIR/" \;
find . -name "validation_summary_*.md" -exec cp {} "$EXPORT_DIR/" \;

# Count exported result files
RESULT_COUNT=$(find "$EXPORT_DIR" -name "validation_results_*.json" | wc -l)
SUMMARY_COUNT=$(find "$EXPORT_DIR" -name "validation_summary_*.md" | wc -l)
echo "✅ Exported $RESULT_COUNT result files and $SUMMARY_COUNT summaries"

# Export logs
echo "📜 Exporting logs..."
if [ -f "validation_session.log" ]; then
    cp validation_session.log "$EXPORT_DIR/"
fi
if [ -f "budget_monitor.log" ]; then
    cp budget_monitor.log "$EXPORT_DIR/"
fi
find . -name "budget_checkpoint_*.json" -exec cp {} "$EXPORT_DIR/" \;

# Export any crash dumps or debug info
echo "🐛 Exporting debug information..."
if [ -d "debug_info" ]; then
    cp -r debug_info "$EXPORT_DIR/"
fi

# Create session summary
echo "📝 Creating session summary..."
cat > "$EXPORT_DIR/session_summary.txt" << EOF
ZeroBuilder Session Summary
==========================
Export Date: $(date)
Session Directory: $(pwd)
Instance Type: RTX 8000 (48GB VRAM)

Files Exported:
- Session metadata: $([ -f "$EXPORT_DIR/session_metadata.env" ] && echo "✅" || echo "❌")
- Session state: $([ -f "$EXPORT_DIR/session_state.json" ] && echo "✅" || echo "❌")
- Validation results: $RESULT_COUNT files
- Summary reports: $SUMMARY_COUNT files
- Logs: $(find "$EXPORT_DIR" -name "*.log" | wc -l) files

Validation Progress:
$(if [ -f "session_state.json" ]; then
    python3 -c "
import json
with open('session_state.json', 'r') as f:
    data = json.load(f)
    print(f'- Total patterns: {data.get(\"total_patterns\", 0):,}')
    print(f'- Validated patterns: {data.get(\"validated_patterns\", 0):,}')
    print(f'- Completion rate: {(data.get(\"validated_patterns\", 0) / data.get(\"total_patterns\", 1) * 100):.1f}%')
    print(f'- Completed batches: {len(data.get(\"completed_batches\", []))}')
"
else
    echo "- No session state available"
fi)

Budget Information:
$(if [ -f "/tmp/session_metadata.env" ]; then
    source /tmp/session_metadata.env
    if [ -n "$INSTANCE_START_TIME" ]; then
        CURRENT_TIME=$(date +%s)
        ELAPSED_SECONDS=$((CURRENT_TIME - INSTANCE_START_TIME))
        ELAPSED_HOURS=$(echo "scale=2; $ELAPSED_SECONDS / 3600" | bc)
        ESTIMATED_COST=$(echo "scale=2; $ELAPSED_HOURS * 0.20" | bc)
        echo "- Session duration: ${ELAPSED_HOURS} hours"
        echo "- Estimated cost: \$${ESTIMATED_COST}"
        echo "- Hourly rate: \$0.20"
    fi
else
    echo "- No budget metadata available"
fi)

Export completed at: $(date)
EOF

# Calculate total export size
EXPORT_SIZE=$(du -sh "$EXPORT_DIR" | cut -f1)
echo "📦 Total export size: $EXPORT_SIZE"

# Create compressed archive
echo "🗜️ Creating compressed archive..."
tar -czf "${EXPORT_DIR}.tar.gz" "$EXPORT_DIR"
ARCHIVE_SIZE=$(du -sh "${EXPORT_DIR}.tar.gz" | cut -f1)
echo "✅ Archive created: ${EXPORT_DIR}.tar.gz ($ARCHIVE_SIZE)"

# Generate download instructions
echo "📥 Creating download instructions..."
cat > "${EXPORT_DIR}_download_instructions.txt" << EOF
ZeroBuilder Export Download Instructions
=======================================

1. Download the archive:
   wget http://[INSTANCE_IP]:8000/${EXPORT_DIR}.tar.gz
   
   OR
   
   scp root@[INSTANCE_IP]:~/zerobuilder_workspace/ZeroBuilder/${EXPORT_DIR}.tar.gz .

2. Extract the archive:
   tar -xzf ${EXPORT_DIR}.tar.gz

3. Archive contains:
   - Session metadata and state
   - Validation results (JSON format)
   - Summary reports (Markdown format)
   - Logs and debug information
   - Session summary

4. Total size: $ARCHIVE_SIZE

Generated: $(date)
EOF

# Start simple HTTP server for download (if requested)
if [ "$1" = "--serve" ]; then
    echo "🌐 Starting HTTP server for download..."
    echo "📥 Download URL: http://$(curl -s ifconfig.me):8000/${EXPORT_DIR}.tar.gz"
    echo "🛑 Press Ctrl+C to stop server and continue with destruction"
    python3 -m http.server 8000 &
    HTTP_PID=$!
    
    # Wait for user to download
    echo "⏳ Waiting for download... (or press Enter to continue)"
    read -t 300 || true  # 5 minute timeout
    
    # Stop HTTP server
    kill $HTTP_PID 2>/dev/null || true
    echo "🛑 HTTP server stopped"
fi

# Cleanup uncompressed directory
rm -rf "$EXPORT_DIR"

echo ""
echo "🎉 Pre-Destroy Export Complete!"
echo "📦 Archive: ${EXPORT_DIR}.tar.gz"
echo "📋 Instructions: ${EXPORT_DIR}_download_instructions.txt"
echo "💾 Size: $ARCHIVE_SIZE"
echo ""
echo "🚨 IMPORTANT: Download the archive before instance destruction!"
echo "⚠️ All data will be permanently lost when instance is destroyed"
echo ""
echo "Next steps:"
echo "1. Download: ${EXPORT_DIR}.tar.gz"
echo "2. Verify: Extract and check contents"
echo "3. Destroy: Instance can now be safely terminated"
echo ""