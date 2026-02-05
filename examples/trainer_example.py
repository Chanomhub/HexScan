#!/usr/bin/env python3
"""
HexScan Python Trainer Example
Demonstrates AOB scanning and memory read/write for Linux games
"""

import re
import struct
from pathlib import Path


def get_pid_by_name(process_name: str) -> int:
    """Find process ID by name"""
    for proc in Path("/proc").iterdir():
        if proc.name.isdigit():
            try:
                cmdline = (proc / "comm").read_text().strip()
                if process_name.lower() in cmdline.lower():
                    return int(proc.name)
            except:
                pass
    return -1


def get_memory_regions(pid: int, filter_type: str = "rw") -> list:
    """Get memory regions from /proc/pid/maps
    filter_type: 'rw' for data, 'rx' for code
    """
    regions = []
    maps_path = Path(f"/proc/{pid}/maps")
    
    for line in maps_path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        
        perms = parts[1]
        addr_range = parts[0].split('-')
        start = int(addr_range[0], 16)
        end = int(addr_range[1], 16)
        
        # Filter by permissions
        if filter_type == "rw" and 'r' in perms and 'w' in perms:
            regions.append((start, end))
        elif filter_type == "rx" and 'r' in perms and 'x' in perms:
            regions.append((start, end))
    
    return regions


def read_memory(pid: int, address: int, size: int) -> bytes:
    """Read memory from process"""
    mem_path = Path(f"/proc/{pid}/mem")
    with open(mem_path, 'rb') as f:
        f.seek(address)
        return f.read(size)


def write_memory(pid: int, address: int, data: bytes) -> bool:
    """Write memory to process"""
    mem_path = Path(f"/proc/{pid}/mem")
    try:
        with open(mem_path, 'r+b') as f:
            f.seek(address)
            f.write(data)
        return True
    except:
        return False


def aob_to_pattern(aob_string: str) -> tuple:
    """Convert AOB string to pattern and mask
    Example: "48 8B ?? 28" -> (b'\x48\x8B\x00\x28', b'\xFF\xFF\x00\xFF')
    """
    pattern = bytearray()
    mask = bytearray()
    
    for byte_str in aob_string.split():
        if byte_str == "??" or byte_str == "?":
            pattern.append(0)
            mask.append(0)  # Wildcard
        else:
            pattern.append(int(byte_str, 16))
            mask.append(0xFF)  # Must match
    
    return bytes(pattern), bytes(mask)


def find_pattern(pid: int, aob_string: str, region_type: str = "rx") -> list:
    """Find AOB pattern in process memory
    region_type: 'rx' for code, 'rw' for data
    """
    pattern, mask = aob_to_pattern(aob_string)
    results = []
    
    regions = get_memory_regions(pid, region_type)
    
    for start, end in regions:
        try:
            # Read in chunks to avoid memory issues
            chunk_size = 0x100000  # 1MB
            for offset in range(0, end - start, chunk_size):
                addr = start + offset
                size = min(chunk_size, end - addr)
                
                try:
                    data = read_memory(pid, addr, size)
                except:
                    continue
                
                # Search for pattern
                for i in range(len(data) - len(pattern)):
                    match = True
                    for j in range(len(pattern)):
                        if mask[j] != 0 and data[i + j] != pattern[j]:
                            match = False
                            break
                    
                    if match:
                        results.append(addr + i)
        except:
            continue
    
    return results


def read_int32(pid: int, address: int) -> int:
    """Read 32-bit integer"""
    data = read_memory(pid, address, 4)
    return struct.unpack('<i', data)[0]


def write_int32(pid: int, address: int, value: int) -> bool:
    """Write 32-bit integer"""
    data = struct.pack('<i', value)
    return write_memory(pid, address, data)


def nop_instruction(pid: int, address: int, length: int) -> bool:
    """NOP an instruction (fill with 0x90)"""
    nops = b'\x90' * length
    return write_memory(pid, address, nops)


# ============================================================
# EXAMPLE USAGE
# ============================================================

if __name__ == "__main__":
    import sys
    
    # 1. Find game process
    GAME_NAME = "YourGame"  # Change this!
    pid = get_pid_by_name(GAME_NAME)
    
    if pid == -1:
        print(f"Game '{GAME_NAME}' not found!")
        sys.exit(1)
    
    print(f"Found game PID: {pid}")
    
    # 2. Find instruction by AOB (Code)
    # This is the AOB from Disassembler that WRITES to health/money
    CODE_AOB = "89 7B 14"  # Example: mov [rbx+0x14], edi
    
    print(f"\nSearching for code AOB: {CODE_AOB}")
    code_results = find_pattern(pid, CODE_AOB, "rx")
    
    if code_results:
        print(f"Found {len(code_results)} matches:")
        for addr in code_results[:5]:  # Show first 5
            print(f"  0x{addr:X}")
        
        # NOP the first match (disable health decrease)
        # nop_instruction(pid, code_results[0], 3)
        # print(f"NOPed instruction at 0x{code_results[0]:X}")
    
    # 3. Find data value by AOB (Data)
    # If you know bytes around your value, you can search for them
    # Example: If health is always near specific bytes
    DATA_AOB = "64 00 00 00"  # Example: value 100 as int32
    
    print(f"\nSearching for data AOB: {DATA_AOB}")
    data_results = find_pattern(pid, DATA_AOB, "rw")
    
    if data_results:
        print(f"Found {len(data_results)} matches:")
        for addr in data_results[:5]:
            value = read_int32(pid, addr)
            print(f"  0x{addr:X} = {value}")
    
    # 4. Direct read/write if you know the address
    # known_address = 0x12345678
    # current_value = read_int32(pid, known_address)
    # print(f"Current value: {current_value}")
    # write_int32(pid, known_address, 9999)
    # print("Set value to 9999!")
