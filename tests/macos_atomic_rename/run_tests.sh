#!/bin/bash

# Test script for macOS atomic rename functionality
# This script runs all the clean, working tests for the GitHub issue #914 fix

set -e

echo "🧪 Testing macOS atomic rename functionality on gocryptfs (GitHub issue #914 fix)"
echo "================================================================================"

# Get the gocryptfs root directory (script is in tests/macos_atomic_rename/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GOCRYPTFS_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$GOCRYPTFS_ROOT"

echo "Working directory: $(pwd)"

echo
echo "Running all tests (6 tests, should complete in ~3 seconds)..."
echo "Tests include gocryptfs mounting, app save simulation, and native filesystem validation"
echo "Test Summary:"
echo "   - TestRenameExchangeOnGocryptfs: Basic atomic exchange on gocryptfs"
echo "   - TestMacOSAppSaveWorkflowOnGocryptfs: Full app save workflow (3 saves)"  
echo "   - TestRenameExchangeWithSubdirectories: Subdirectory support"
echo "   - TestMacOSAppSaveSimulation: Integration test"
echo "   - TestRenameat2_BasicFunctionality: Native filesystem basic test"
echo "   - TestMacOSAppSavePattern: Native filesystem app pattern test"

go test ./tests/macos_atomic_rename -v
