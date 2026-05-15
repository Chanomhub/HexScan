#!/bin/bash

# HexScan Integration Test Script
# This script verifies the scanner by running DummyTarget and scanning it with HexScanCLI.

BUILD_DIR=${1:-"build"}
DUMMY_TARGET="./${BUILD_DIR}/DummyTarget"
HEXSCAN_CLI="./${BUILD_DIR}/HexScanCLI"

if [[ ! -f "$DUMMY_TARGET" || ! -f "$HEXSCAN_CLI" ]]; then
    echo "Error: Binaries not found in $BUILD_DIR. Please build them first."
    exit 1
fi

echo "Starting DummyTarget..."
# Start DummyTarget in a new process group to prevent it from exiting when the script waits
$DUMMY_TARGET > target_output.txt 2>&1 &
TARGET_PID=$!

# Wait for PID to appear in output
for i in {1..20}; do
    if grep -q "Process ID (PID):" target_output.txt; then
        break
    fi
    sleep 0.5
done

# Extract PID and Addresses from output
ACTUAL_PID=$(grep "Process ID (PID):" target_output.txt | awk '{print $4}')
ADDR_I32=$(grep "int32" target_output.txt | awk '{print $2}')
ADDR_I64=$(grep "int64" target_output.txt | awk '{print $2}')
ADDR_F32=$(grep "float" target_output.txt | awk '{print $2}')
ADDR_F64=$(grep "double" target_output.txt | awk '{print $2}')
ADDR_STR=$(grep "string" target_output.txt | awk '{print $2}')

echo "Ground Truth from DummyTarget (PID: $ACTUAL_PID):"
echo "  int32 address:  $ADDR_I32"
echo "  int64 address:  $ADDR_I64"
echo "  float address:  $ADDR_F32"
echo "  double address: $ADDR_F64"
echo "  string address: $ADDR_STR"

FAILED=0

check_scan() {
    local type=$1
    local value=$2
    local expected_addr=$3
    local scan_name=$4

    echo "Running Scan: $scan_name ($type, value: $value)..."
    RESULT=$($HEXSCAN_CLI $ACTUAL_PID $type "$value" 0)
    
    if echo "$RESULT" | grep -qi "${expected_addr#0x}"; then
        echo "  [PASS] Found correct address."
    else
        echo "  [FAIL] Expected address $expected_addr not found in results!"
        # echo "DEBUG: Full Result:"
        # echo "$RESULT"
        FAILED=1
    fi
}

# 1. Test i32 Scan
check_scan "i32" "1234" "$ADDR_I32" "Specific Type (i32)"

# 2. Test f64 Scan
check_scan "f64" "987.654" "$ADDR_F64" "Specific Type (f64)"

# 3. Test 'all' Scan for double value
check_scan "all" "987.654" "$ADDR_F64" "All Scan Type (double)"

# 4. Test 'all' Scan for int value
check_scan "all" "567890" "$ADDR_I64" "All Scan Type (int64)"

# 5. Test string Scan
check_scan "string" "CheatTurbine" "$ADDR_STR" "String Scan"

# Cleanup
echo "Cleaning up..."
kill $TARGET_PID
rm target_output.txt

if [ $FAILED -eq 0 ]; then
    echo "========================================"
    echo "   ALL INTEGRATION TESTS PASSED!        "
    echo "========================================"
    exit 0
else
    echo "========================================"
    echo "   INTEGRATION TESTS FAILED!            "
    echo "========================================"
    exit 1
fi
