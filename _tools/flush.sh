#!/bin/bash
# ============================================================================
# flush.sh — Manual pipeline flush (convenience wrapper)
# ============================================================================
# Equivalent to Chronicler:flush_pipeline MCP tool call.
# Run from anywhere: bash ~/flush.sh
#
# What it does:
#   1. Pulls latest repo state (handles Chronicler API commits)
#   2. Extracts all traffic logs into text files
#   3. Pushes extracted files to GitHub
#
# After running, files are available via Chronicler:read_file
# ============================================================================

set -euo pipefail

echo "=== Pipeline Flush ==="
echo ""

echo "[1/3] Syncing repo..."
cd /home/ubuntu/clgysing-extractions
git pull --no-rebase origin main || {
    echo "ERROR: Pull failed. Check: git status"
    exit 1
}

echo "[2/3] Extracting traffic logs..."
cd /home/ubuntu/mcp-logger
python3 extract.py --all

echo "[3/3] Pushing to GitHub..."
bash push-to-github.sh

echo ""
echo "=== Flush complete ==="
echo "Files available via Chronicler:list_files / Chronicler:read_file"
