#!/usr/bin/env bash
# Code Security Skill — one-line installer for Unix / macOS
#
# Usage (run from your project root):
#
#   curl -sSL https://raw.githubusercontent.com/Chiehyii/code-security-skill/main/install.sh | bash
#
# Pass extra flags after '--':
#
#   curl -sSL .../install.sh | bash -s -- --ai claude
#   curl -sSL .../install.sh | bash -s -- --ai cursor copilot --force
#   curl -sSL .../install.sh | bash -s -- --force
#
# Requires: git, python3

set -euo pipefail

REPO_URL="https://github.com/Chiehyii/code-security-skill"
TMP_DIR="$(mktemp -d)"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo ""
echo "  🛡️  Code Security Skill — Downloading..."
git clone --depth 1 --quiet "$REPO_URL" "$TMP_DIR/skill"

echo "  🛡️  Installing into $(pwd) ..."
python3 "$TMP_DIR/skill/scripts/install_skill.py" . "$@"
