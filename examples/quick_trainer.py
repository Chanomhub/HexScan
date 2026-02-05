#!/usr/bin/env python3
"""
Quick Trainer - NOP the 'sub edx, esi' instruction
Run with: sudo python3 quick_trainer.py
"""

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


def get_code_regions(pid: int) -> list:
    """Get executable memory regions"""
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
        
        if 'r' in perms and 'x' in perms:
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
    except Exception as e:
        print(f"Write failed: {e}")
        return False


def aob_to_pattern(aob_string: str) -> tuple:
    """Convert AOB string to pattern and mask"""
    pattern = bytearray()
    mask = bytearray()
    
    for byte_str in aob_string.split():
        if byte_str == "??" or byte_str == "?":
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(byte_str, 16))
            mask.append(0xFF)
    
    return bytes(pattern), bytes(mask)


def find_pattern(pid: int, aob_string: str) -> int:
    """Find first match of AOB pattern in code regions"""
    pattern, mask = aob_to_pattern(aob_string)
    
    regions = get_code_regions(pid)
    print(f"Scanning {len(regions)} code regions...")
    
    for start, end in regions:
        try:
            chunk_size = 0x100000
            for offset in range(0, end - start, chunk_size):
                addr = start + offset
                size = min(chunk_size, end - addr)
                
                try:
                    data = read_memory(pid, addr, size)
                except:
                    continue
                
                for i in range(len(data) - len(pattern)):
                    match = True
                    for j in range(len(pattern)):
                        if mask[j] != 0 and data[i + j] != pattern[j]:
                            match = False
                            break
                    
                    if match:
                        return addr + i
        except:
            continue
    
    return 0


def nop_bytes(pid: int, address: int, length: int) -> bool:
    """NOP an instruction"""
    nops = b'\x90' * length
    return write_memory(pid, address, nops)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    # === CHANGE THESE ===
    GAME_NAME = "supertux2"  # ชื่อ process ของเกม
    
    # AOB ที่คุณหาได้ (ใช้ยาวพอให้ unique)
    AOB = "2B D6 45 33 C9 44 0F B6 C7 48 8B CB E8"
    
    # จำนวน bytes ที่จะ NOP (sub edx, esi = 2 bytes)
    NOP_LENGTH = 2
    # ====================
    
    print(f"Looking for game: {GAME_NAME}")
    pid = get_pid_by_name(GAME_NAME)
    
    if pid == -1:
        print(f"❌ Game '{GAME_NAME}' not found!")
        print("Make sure the game is running.")
        exit(1)
    
    print(f"✅ Found game PID: {pid}")
    
    print(f"\nSearching for AOB: {AOB[:20]}...")
    address = find_pattern(pid, AOB)
    
    if address == 0:
        print("❌ AOB not found!")
        exit(1)
    
    print(f"✅ Found at: 0x{address:X}")
    
    # Read original bytes
    original = read_memory(pid, address, NOP_LENGTH)
    print(f"Original bytes: {original.hex().upper()}")
    
    # NOP it!
    print(f"\nNOPing {NOP_LENGTH} bytes...")
    if nop_bytes(pid, address, NOP_LENGTH):
        print(f"✅ Success! Value should no longer decrease.")
        print(f"\nTo restore, run: sudo python3 -c \"")
        print(f"from pathlib import Path")
        print(f"with open('/proc/{pid}/mem', 'r+b') as f:")
        print(f"    f.seek(0x{address:X})")
        print(f"    f.write(bytes.fromhex('{original.hex()}'))\"")
    else:
        print("❌ Failed to NOP!")
