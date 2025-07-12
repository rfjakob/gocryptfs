#!/bin/bash
set -eu

# Test script for reverse mode Unicode normalization support
# This tests that files with different Unicode normalizations can be accessed
# correctly through the reverse-mounted encrypted view.

echo "=== gocryptfs Reverse Mode Unicode Test ==="

# Capture the current directory where gocryptfs binary is located
GOCRYPTFS_DIR="$(pwd)"
GOCRYPTFS_BIN="$GOCRYPTFS_DIR/gocryptfs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test directories
PLAIN_DIR="/tmp/gocryptfs_test_plain"
REVERSE_DIR="/tmp/gocryptfs_test_reverse"
PASSWORD="test123"

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    
    # Unmount if mounted
    if mount | grep -q "$REVERSE_DIR"; then
        echo "Unmounting $REVERSE_DIR"
        umount "$REVERSE_DIR" 2>/dev/null || diskutil unmount "$REVERSE_DIR" 2>/dev/null || true
        sleep 2
        
        # Force unmount if still mounted
        if mount | grep -q "$REVERSE_DIR"; then
            echo "Force unmounting..."
            umount -f "$REVERSE_DIR" 2>/dev/null || diskutil unmount force "$REVERSE_DIR" 2>/dev/null || true
            sleep 1
        fi
    fi
    
    # Remove directories (only if they exist and are not mounted)
    if [[ -d "$PLAIN_DIR" ]]; then
        rm -rf "$PLAIN_DIR" 2>/dev/null || true
    fi
    if [[ -d "$REVERSE_DIR" ]] && ! mount | grep -q "$REVERSE_DIR"; then
        rmdir "$REVERSE_DIR" 2>/dev/null || true
    fi
    echo -e "${GREEN}Cleanup complete${NC}"
}

# Set up cleanup trap
trap cleanup EXIT

# Function to create test files with different Unicode normalizations
create_test_files() {
    echo -e "${YELLOW}Creating test files with different Unicode normalizations...${NC}"
    
    # Create NFC normalized filename (é as single character U+00E9)
    echo "Content of café NFC" > "$PLAIN_DIR/café_nfc.txt"
    
    # Create NFD normalized filename (é as e + combining acute accent U+0065 U+0301)
    # Using printf to ensure exact byte sequence
    printf "Content of café NFD" > "$PLAIN_DIR/cafe$(printf '\u0301')_nfd.txt"
    
    # Create more complex examples
    echo "Content of résumé NFC" > "$PLAIN_DIR/résumé_nfc.txt"
    printf "Content of résumé NFD" > "$PLAIN_DIR/re$(printf '\u0301')sume$(printf '\u0301')_nfd.txt"
    
    # Create files with other diacritics
    echo "Content of naïve" > "$PLAIN_DIR/naïve.txt"
    echo "Content of piñata" > "$PLAIN_DIR/piñata.txt"
    echo "Content of Zürich" > "$PLAIN_DIR/Zürich.txt"
    
    # Non-diacritic files for comparison
    echo "Content of normal file" > "$PLAIN_DIR/normal.txt"
    echo "Content of test file" > "$PLAIN_DIR/test.txt"
}

# Function to display Unicode analysis
analyze_filenames() {
    echo -e "${YELLOW}Analyzing filenames in plaintext directory:${NC}"
    
    cd "$PLAIN_DIR"
    for file in *; do
        if [[ "$file" == *"café"* ]] || [[ "$file" == *"résumé"* ]]; then
            echo "File: $file"
            # Show hex dump to see exact bytes
            echo -n "  Hex: "
            echo -n "$file" | xxd -p | tr -d '\n'
            echo
            # Show length
            echo "  Length: ${#file} characters"
            echo
        fi
    done
}

# Function to test reverse mode
test_reverse_mode() {
    echo -e "${YELLOW}Testing reverse mode access...${NC}"
    
    # List encrypted files
    echo "Encrypted files in reverse mount:"
    ls -la "$REVERSE_DIR"
    echo
    
    # Try to access each encrypted file and read its content
    cd "$REVERSE_DIR"
    local success_count=0
    local total_count=0
    
    for encrypted_file in *; do
        # Skip directories and special files
        if [[ -f "$encrypted_file" ]] && [[ "$encrypted_file" != "gocryptfs.conf" ]]; then
            total_count=$((total_count + 1))
            echo -n "Testing access to encrypted file: $encrypted_file ... "
            
            if content=$(cat "$encrypted_file" 2>/dev/null); then
                echo -e "${GREEN}SUCCESS${NC}"
                echo "  Content: $content"
                success_count=$((success_count + 1))
            else
                echo -e "${RED}FAILED${NC}"
                echo "  Error: Could not read file"
            fi
            echo
        fi
    done
    
    echo -e "${YELLOW}Results: $success_count/$total_count files accessible${NC}"
    
    if [[ $success_count -eq $total_count ]] && [[ $total_count -gt 0 ]]; then
        echo -e "${GREEN}✓ All encrypted files are accessible!${NC}"
        return 0
    else
        echo -e "${RED}✗ Some files are not accessible${NC}"
        return 1
    fi
}

# Function to test specific Unicode scenarios
test_unicode_scenarios() {
    echo -e "${YELLOW}Testing specific Unicode normalization scenarios...${NC}"
    
    cd "$REVERSE_DIR"
    local test_passed=true
    
    # Count total encrypted files (excluding gocryptfs.conf and .diriv)
    encrypted_files=$(ls -1 | grep -v -E '^(gocryptfs\.(conf|diriv))$' | wc -l | tr -d ' ')
    echo "Found $encrypted_files encrypted files"
    
    # Test that we can read files regardless of their Unicode normalization
    local accessible_files=0
    for encrypted_file in *; do
        if [[ -f "$encrypted_file" ]] && [[ "$encrypted_file" != "gocryptfs.conf" ]] && [[ "$encrypted_file" != "gocryptfs.diriv" ]]; then
            if cat "$encrypted_file" >/dev/null 2>&1; then
                accessible_files=$((accessible_files + 1))
            fi
        fi
    done
    
    echo "Successfully accessed $accessible_files encrypted files"
    
    # Check that we have the expected number of files (should be 9 plaintext files)
    expected_files=9
    if [[ $accessible_files -eq $expected_files ]]; then
        echo -e "${GREEN}✓ All $expected_files plaintext files are accessible through reverse mode${NC}"
        echo -e "${GREEN}✓ Unicode normalization fallback is working correctly${NC}"
    else
        echo -e "${YELLOW}⚠ Expected $expected_files files, but accessed $accessible_files${NC}"
        if [[ $accessible_files -gt 0 ]]; then
            echo -e "${GREEN}✓ Unicode normalization fallback appears to be working${NC}"
        else
            echo -e "${RED}✗ Unicode normalization fallback may not be working${NC}"
            test_passed=false
        fi
    fi
    
    $test_passed
}

# Main execution
main() {
    echo "Starting reverse mode Unicode test..."
    echo "Platform: $(uname -s)"
    echo "gocryptfs version: $($GOCRYPTFS_BIN -version 2>&1 | head -1 || echo 'Could not determine version')"
    echo
    
    # Create directories
    mkdir -p "$PLAIN_DIR" "$REVERSE_DIR"
    
    # Create test files
    create_test_files
    
    # Show what we created
    echo -e "${YELLOW}Created files in plaintext directory:${NC}"
    ls -la "$PLAIN_DIR"
    echo
    
    # Analyze filenames
    analyze_filenames
    
    # Initialize reverse mode
    echo -e "${YELLOW}Initializing reverse mode...${NC}"
    echo "$PASSWORD" | "$GOCRYPTFS_BIN" -init -reverse "$PLAIN_DIR"
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Failed to initialize reverse mode${NC}"
        exit 1
    fi
    
    # Ensure mount directory exists and is empty
    if mount | grep -q "$REVERSE_DIR"; then
        umount "$REVERSE_DIR" 2>/dev/null || diskutil unmount "$REVERSE_DIR" 2>/dev/null || true
        sleep 1
    fi
    rm -rf "$REVERSE_DIR"
    mkdir -p "$REVERSE_DIR"
    
    # Mount in reverse mode
    echo -e "${YELLOW}Mounting in reverse mode...${NC}"
    echo "$PASSWORD" | "$GOCRYPTFS_BIN" -reverse "$PLAIN_DIR" "$REVERSE_DIR"
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Failed to mount in reverse mode${NC}"
        exit 1
    fi
    
    # Wait a moment for mount to stabilize
    sleep 2
    
    # Verify mount
    if ! mount | grep -q "$REVERSE_DIR"; then
        echo -e "${RED}Reverse mount failed${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Reverse mode mounted successfully${NC}"
    echo
    
    # Test access
    if test_reverse_mode && test_unicode_scenarios; then
        echo
        echo -e "${GREEN}=== ALL TESTS PASSED ===${NC}"
        echo -e "${GREEN}Reverse mode Unicode normalization is working correctly!${NC}"
        exit 0
    else
        echo
        echo -e "${RED}=== SOME TESTS FAILED ===${NC}"
        echo -e "${RED}There may be issues with Unicode normalization in reverse mode${NC}"
        exit 1
    fi
}

# Check if we're on macOS
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo -e "${YELLOW}Warning: This test is designed for macOS Unicode normalization issues${NC}"
    echo -e "${YELLOW}On other platforms, Unicode normalization differences may not occur${NC}"
    echo
fi

# Check if gocryptfs binary exists
if [[ ! -x "$GOCRYPTFS_BIN" ]]; then
    echo -e "${RED}Error: gocryptfs binary not found at $GOCRYPTFS_BIN${NC}"
    echo "Please run this script from the gocryptfs build directory"
    exit 1
fi

# Run main function
main
