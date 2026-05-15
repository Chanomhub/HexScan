# HexScan Test Specification — dummy_target.cpp

This document describes **every test scenario** that `dummy_target.cpp` provides and exactly how to exercise each HexScan feature against it.

> **Purpose:** ใช้เป็น reference สำหรับ LLM หรือ developer คนอื่นที่จะ implement/test features ของ HexScan
> โดยไม่ต้องไปอ่าน source code ทั้งหมด

---

## 1. Build & Run

```bash
cd /home/jop/work/CheatTurbine
cmake --build build --target DummyTarget
./build/DummyTarget
```

Target จะแสดง address table ทั้งหมดเมื่อเริ่ม และรอ input จาก user

---

## 2. Value Scanning Tests [SCAN]

### 2.1 Exact Value Scan (ScanType::Equal)

| Variable | Type | Default Value | Address Source |
|----------|------|---------------|----------------|
| `g_i8` | int8 (signed) | -42 | global (BSS) |
| `g_i16` | int16 (signed) | -1234 | global (BSS) |
| `g_i32` | int32 (signed) | 123456 | global (BSS) |
| `g_i64` | int64 (signed) | 9876543210 | global (BSS) |
| `g_u8` | uint8 | 200 | global (BSS) |
| `g_u16` | uint16 | 50000 | global (BSS) |
| `g_u32` | uint32 | 3000000000 | global (BSS) |
| `g_u64` | uint64 | 0xDEADBEEFCAFE | global (BSS) |
| `g_f32` | float | 3.14159 | global (BSS) |
| `g_f64` | double | 2.718281828 | global (BSS) |
| `g_str` | string | "HexScan" | global (data) |
| `g_wstr` | wchar_t[] | L"WideScan" | global (data) |
| `stack_i32` | int32 (volatile) | 1234 | stack |
| `stack_f32` | float (volatile) | 123.456 | stack |

**Test procedure:**
1. Start DummyTarget, note addresses
2. Scan for default value → should find the address
3. Press `1` (change values) → value changes to `999` patterns
4. Next scan for new value → should narrow down

### 2.2 Relative Scans (Increased/Decreased/Changed/Unchanged)

**Test procedure:**
1. Unknown initial scan (ScanType::Unknown) → captures all addresses
2. Press `2` (increase) → next scan with ScanType::Increased → narrows down
3. Press `3` (decrease) → next scan with ScanType::Decreased
4. Press nothing → next scan with ScanType::Unchanged → should keep addresses that didn't change
5. Repeat until only target addresses remain

**IncreasedBy / DecreasedBy:**
- Press `2`: i32 increases by +100, i64 by +1000, f32 by +1.5, f64 by +2.5
- Press `3`: i32 decreases by -50, i64 by -500, f32 by -0.5, f64 by -1.0

### 2.3 Range Scan (ScanType::Range)

- Scan for i32 in range [100000, 200000] → should find `g_i32` (123456)
- Scan for f32 in range [3.0, 4.0] → should find `g_f32` (3.14159)

### 2.4 All-Type Scan (CTValueType::all)

Scan with `all` type and value `123456` → should match `g_i32` as int32
Scan with `all` type and value `3.14159` → should match `g_f32` as float

### 2.5 AOB Scan (Array of Bytes)

`g_pattern` contains 64 known bytes:
```
DE AD BE EF CA FE BA BE 48 65 78 53 63 61 6E 21 ...
```

**Test with wildcards:**
```
DE AD ?? EF CA FE ?? BE
```
Should find address of `g_pattern`.

### 2.6 String Scan

- Scan for `"HexScan"` → finds `g_str`
- Press `1` to change → string becomes `"Changed!"`
- Scan for `"Changed!"` → should find same address

### 2.7 Wide String Scan (future feature)

`g_wstr` contains `L"WideScan"` — each character is 4 bytes (wchar_t on Linux).
Pattern in memory: `57 00 00 00 69 00 00 00 64 00 00 00 ...`

---

## 3. Pointer Chain Tests [PCHAIN]

### 3.1 Chain Structure

```
g_world (global static) → World*
  └─ currentRoom (offset +0x00) → Room*
       └─ player (offset +0x00) → Entity*
            ├─ stats.health (offset +0x20) → int32 = 100
            ├─ stats.mana (offset +0x28) → int32 = 50
            └─ inventory (offset +0x58) → Inventory*
                 └─ gold (offset +0x00) → int32 = 1000
```

**4-level chain to gold:**
`g_world → [+0x00] → [+0x00] → [+0x58] → [+0x00]`

**3-level chain to health:**
`g_world → [+0x00] → [+0x00] → [+0x20]`

### 3.2 Pointer Scan Test

1. Find address of `health` (printed at startup)
2. Run pointer scan targeting that address
3. Should find path: `g_world + offsets` as a valid chain
4. Verify chain resolves correctly after restart (ASLR changes heap addresses, but `g_world` is static in BSS)

### 3.3 Pointer Chain Rebase

- `g_world` is in BSS → its address is module_base + fixed_offset
- Chain should survive process restart if rebased from module

---

## 4. Structure Dissector Tests [STRUCT]

### 4.1 Entity Structure (at `g_player` address)

```
Offset  Type        Field               Expected Value
0x00    char[32]    name                "Player_One"
0x20    int32       stats.health        100
0x24    int32       stats.maxHealth     100
0x28    int32       stats.mana          50
0x2C    int32       stats.maxMana       100
0x30    float       stats.speed         2.5
0x34    float       stats.armor         10.0
0x38    double      stats.experience    0.0 (changes over time)
0x40    uint32      stats.level         5
0x44    uint32      stats.flags         0b0101 (alive + shield)
0x48    float       pos.x               10.0 (changes over time)
0x4C    float       pos.y               20.0
0x50    float       pos.z               0.0
0x58    ptr         inventory           → Inventory*
0x60    ptr         target              → Entity* (enemy[0])
```

**Auto-guess test:** Open structure dissector at `g_player` address. Auto-guess should detect:
- String at offset 0x00
- Integers at 0x20-0x2C
- Floats at 0x30-0x34
- Double at 0x38
- Pointers at 0x58 and 0x60

### 4.2 Enemy Array

4 enemies accessible via `g_world->currentRoom->enemies[0..3]`:

| Index | Name | HP | Position |
|-------|------|----|----------|
| 0 | Goblin | 30 | (15, 25, 0) |
| 1 | Skeleton | 50 | (20, 30, 0) |
| 2 | Dragon | 500 | (50, 50, 0) |
| 3 | Slime | 10 | (5, 10, 0) |

---

## 5. Disassembler Tests [DISASM]

### 5.1 Available Functions

| Function | Address Label | Pattern Type |
|----------|---------------|-------------|
| `applyDamage(Entity*, int32_t)` | `applyDamage` | Conditional branch + memory write |
| `healPlayer(Entity*, int32_t)` | `healPlayer` | Conditional branch + compare |
| `purchaseItem(Inventory*, int32_t, int32_t)` | `purchaseItem` | Multi-branch + memory write |
| `calculateDamage(int32_t, int32_t, int32_t)` | `calculateDmg` | Arithmetic + nested conditionals |
| `tickGameLoop(Entity*)` | `tickGameLoop` | Read + write + float operations |

**Test:** Disassemble 64 bytes at each function address. Verify instructions decode correctly (mnemonic + operands).

---

## 6. Patch Tests [PATCH]

### 6.1 NOP Patch — God Mode

**Target:** `applyDamage()` — the `sub` instruction that does `health -= damage`

**Procedure:**
1. Disassemble `applyDamage` to find the `sub` instruction
2. NOP that instruction
3. Press `5` (deal damage) → health should NOT decrease
4. Restore patch → health decreases again

### 6.2 NOP Patch — Free Purchases

**Target:** `purchaseItem()` — the `sub` instruction that does `gold -= cost`

**Procedure:**
1. Find the `sub` in `purchaseItem`
2. NOP it
3. Press `7` (buy item) → gold should NOT decrease

### 6.3 Conditional Jump Inversion

**Target:** `healPlayer()` — the condition `health <= maxHealth`

**Procedure:**
1. Find conditional jump in `healPlayer`
2. Invert it (jle → jg)
3. Press `6` (heal) → behavior should invert

---

## 7. Watchpoint / Access Tracker Tests [WATCH]

### 7.1 Write Watchpoint

**Target:** `g_player->stats.mana` (offset +0x28 from player)

The background thread calls `tickGameLoop()` every 1 second, which increments mana by 1.

**Procedure:**
1. Set DataWrite watchpoint on mana address
2. Wait 1-2 seconds
3. Access tracker should record the `add` instruction in `tickGameLoop()` with its RIP

### 7.2 Read Watchpoint

**Target:** `g_player->stats.health` (offset +0x20 from player)

`tickGameLoop()` reads health every tick.

**Procedure:**
1. Set DataReadWrite watchpoint on health address
2. Reads from `tickGameLoop()` should be recorded
3. Every 5 ticks, `applyDamage()` writes to health — that should also appear

### 7.3 Freeze Test

**Target:** `g_tickCount` (atomic counter, increments every second)

**Procedure:**
1. Find `g_tickCount` address (printed as "tick" in address table)
2. Freeze its value
3. Wait several seconds — value should stay frozen
4. Unfreeze — value should start incrementing again

---

## 8. Memory Region Tests [REGION]

### 8.1 Region Types

| Variable | Expected Region |
|----------|----------------|
| `g_i32`, `g_str`, `g_pattern` | BSS/data section (static, inode > 0) |
| `g_player`, `g_world` | Heap (anonymous mapping, inode = 0) |
| `stack_i32`, `stack_f32` | Stack ([stack] region) |
| `applyDamage` function | Code section (r-x permission) |

### 8.2 Static Address Detection

`g_world` pointer is in BSS → `Regions::isStaticAddress()` should return `true`.
Heap addresses (e.g., what `g_player` points to) → should return `false`.

---

## 9. Interactive Menu Reference

| Key | Action | Scan Feature Tested |
|-----|--------|-------------------|
| `1` | Change all scalars to 999 patterns | Equal scan, Changed scan |
| `2` | Increase scalars by fixed amounts | Increased, IncreasedBy |
| `3` | Decrease scalars by fixed amounts | Decreased, DecreasedBy |
| `4` | Reset scalars to defaults | Equal scan after reset |
| `5` | Deal 10 damage to player | Watchpoint on health write |
| `6` | Heal player 20 HP | Conditional jump patch test |
| `7` | Buy item (100 gold) | NOP patch test on gold sub |
| `8` | Attack enemy[0] | calculateDamage + applyDamage |
| `9` | Toggle player flags | Bitfield / bit scan |
| `s` | Show status | Visual verification |
| `a` | Show address table | Re-print all addresses |
| `q` | Quit | Cleanup |

---

## 10. Expected Test Results Summary

If all HexScan features work correctly:

- ✅ All 14 value types scannable and findable
- ✅ All relative scan types (increased/decreased/changed/unchanged) narrow correctly
- ✅ AOB scan with wildcards finds `g_pattern`
- ✅ Pointer chain `g_world→...→health` resolves to correct address
- ✅ Pointer scan finds valid paths to `health` from static base
- ✅ Structure dissector auto-guesses Entity fields correctly
- ✅ All 5 functions disassemble with valid instructions
- ✅ NOP patch on `applyDamage` prevents health decrease
- ✅ Conditional jump inversion on `healPlayer` changes behavior
- ✅ Hardware watchpoint on mana catches `tickGameLoop` writes
- ✅ Freeze on `g_tickCount` holds value steady
- ✅ Region detection correctly identifies stack/heap/BSS/code
