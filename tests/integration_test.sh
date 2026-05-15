#!/bin/bash

# HexScan Integration Test Script (v2)
# Tests scanner against the comprehensive DummyTarget

BUILD_DIR=${1:-"build"}
DUMMY_TARGET="./${BUILD_DIR}/DummyTarget"
HEXSCAN_CLI="./${BUILD_DIR}/HexScanCLI"

if [[ ! -f "$DUMMY_TARGET" || ! -f "$HEXSCAN_CLI" ]]; then
    echo "Error: Binaries not found in $BUILD_DIR. Please build them first."
    exit 1
fi

echo "Starting DummyTarget..."
echo "q" | $DUMMY_TARGET > target_output.txt 2>&1 &
TARGET_PID=$!

# Wait for output
for i in {1..20}; do
    if grep -q "PID:" target_output.txt; then
        break
    fi
    sleep 0.5
done

# Give it a moment to fully print
sleep 1

# Extract PID
ACTUAL_PID=$(grep "^PID:" target_output.txt | awk '{print $2}')

# Extract addresses from the new format (Type  Address  Value)
ADDR_I32=$(grep "^i32 " target_output.txt | head -1 | awk '{print $2}')
ADDR_I64=$(grep "^i64 " target_output.txt | head -1 | awk '{print $2}')
ADDR_F32=$(grep "^f32 " target_output.txt | head -1 | awk '{print $2}')
ADDR_F64=$(grep "^f64 " target_output.txt | head -1 | awk '{print $2}')
ADDR_STR=$(grep "^string " target_output.txt | head -1 | awk '{print $2}')

echo "Ground Truth from DummyTarget (PID: $ACTUAL_PID):"
echo "  int32 address:  $ADDR_I32"
echo "  int64 address:  $ADDR_I64"
echo "  float address:  $ADDR_F32"
echo "  double address: $ADDR_F64"
echo "  string address: $ADDR_STR"

# Kill the quick-exit one, restart for scanning
kill $TARGET_PID 2>/dev/null
wait $TARGET_PID 2>/dev/null

# Restart DummyTarget properly (keep it running for scans)
$DUMMY_TARGET < /dev/null > /dev/null 2>&1 &
TARGET_PID=$!
sleep 1

ACTUAL_PID=$TARGET_PID

FAILED=0

check_scan() {
    local type=$1
    local value=$2
    local expected_addr=$3
    local scan_name=$4

    echo "Running Scan: $scan_name ($type, value: $value)..."
    RESULT=$($HEXSCAN_CLI $ACTUAL_PID scan $type "$value" 0)
    
    if echo "$RESULT" | grep -qi "${expected_addr#0x}"; then
        echo "  [PASS] Found correct address."
    else
        echo "  [FAIL] Expected address $expected_addr not found in results!"
        FAILED=1
    fi
}

# 1. Test i32 Scan
check_scan "i32" "123456" "$ADDR_I32" "Specific Type (i32)"

# 2. Test f64 Scan
check_scan "f64" "2.718281828" "$ADDR_F64" "Specific Type (f64)"

# 3. Test 'all' Scan for i32 value
check_scan "all" "123456" "$ADDR_I32" "All Scan Type (i32)"

# 4. Test string Scan
check_scan "string" "HexScan" "$ADDR_STR" "String Scan"

# 5. Test Disassembler
FUNC_ADDR=$(grep "^applyDamage " target_output.txt | head -1 | awk '{print $2}')
echo "Testing Disassembler at $FUNC_ADDR..."
DISASM_RES=$($HEXSCAN_CLI $ACTUAL_PID disasm ${FUNC_ADDR#0x} 16)
if echo "$DISASM_RES" | grep -q ":"; then
    echo "  [PASS] Disassembler returned instructions."
else
    echo "  [FAIL] Disassembler failed!"
    FAILED=1
fi

# 6. Test Patching (NOP)
echo "Testing Patching at $FUNC_ADDR..."
ORIG_BYTE=$(python3 -c "import os; f=open('/proc/$ACTUAL_PID/mem', 'rb'); f.seek(int('$FUNC_ADDR', 16)); print(f.read(1).hex())" 2>/dev/null)
$HEXSCAN_CLI $ACTUAL_PID patch ${FUNC_ADDR#0x} 1 > /dev/null
PATCHED_BYTE=$(python3 -c "import os; f=open('/proc/$ACTUAL_PID/mem', 'rb'); f.seek(int('$FUNC_ADDR', 16)); print(f.read(1).hex())" 2>/dev/null)

if [ "$PATCHED_BYTE" == "90" ]; then
    echo "  [PASS] Successfully NOPed instruction (byte is 0x90)."
else
    echo "  [FAIL] Patch failed! Expected 90, got $PATCHED_BYTE (Original: $ORIG_BYTE)"
    FAILED=1
fi

# 7. Test AOB Scan
echo "Testing AOB Scan..."
AOB_VAL=$(python3 -c "import os; f=open('/proc/$ACTUAL_PID/mem', 'rb'); f.seek(int('$ADDR_I32', 16)); print(' '.join(['{:02X}'.format(b) for b in f.read(4)]))" 2>/dev/null)
echo "  Pattern to find: $AOB_VAL (at $ADDR_I32)"
AOB_PATTERN=$(echo $AOB_VAL | awk '{print $1 " ?? " $3 " " $4}')
echo "  Scanning for pattern: $AOB_PATTERN"

check_scan "aob" "$AOB_PATTERN" "$ADDR_I32" "AOB Scan with Wildcard"

# Cleanup
echo "Cleaning up..."
kill $TARGET_PID 2>/dev/null
wait $TARGET_PID 2>/dev/null
rm -f target_output.txt

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
