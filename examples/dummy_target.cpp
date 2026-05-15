/**
 * ============================================================================
 *  HexScan Comprehensive Test Target
 * ============================================================================
 *
 *  This program is a "fake game" designed to exercise every capability of
 *  HexScan. Each section is labeled with the HexScan feature it tests.
 *
 *  FEATURE COVERAGE:
 *  ─────────────────────────────────────────────────────────────────────────
 *  [SCAN]      Value scanning: i8, i16, i32, i64, f32, f64, string, AOB
 *  [SCAN]      Signed & unsigned variants
 *  [SCAN]      Scan types: equal, bigger, smaller, range, inc/dec, changed
 *  [SCAN]      Unknown initial scan → narrow down
 *  [SCAN]      All-type simultaneous scan
 *  [SCAN]      Wide string (wchar_t / UTF-16) scanning
 *  [SCAN]      Fast scan alignment testing (odd offsets)
 *  [PCHAIN]    Pointer chain: 1-level, 2-level, 4-level deep
 *  [PCHAIN]    Pointer chain through heap allocations
 *  [PCHAIN]    Static base (global) → dynamic chain
 *  [PSCAN]     Pointer scan target: known address reachable via pointers
 *  [STRUCT]    Structure dissector: mixed types, padding, nested pointers
 *  [STRUCT]    Array of structs (enemy list)
 *  [STRUCT]    Bitfield / flags testing
 *  [DISASM]    Multiple functions with different instruction patterns
 *  [PATCH]     NOP-able instructions (conditional branches, writes)
 *  [PATCH]     Conditional jump inversion targets (jz/jnz, jl/jge)
 *  [WATCH]     Thread-based auto-changing values (access tracker / watchpoint)
 *  [WATCH]     Read-triggered and write-triggered access patterns
 *  [FREEZE]    Continuously changing value that user can freeze
 *  [HEXVIEW]   Dense memory region with known byte patterns
 *  [REGION]    Stack, heap, and global (BSS/data) variables
 *  ─────────────────────────────────────────────────────────────────────────
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <unistd.h>
#include <cwchar>
#include <bitset>

// ═══════════════════════════════════════════════════════════════════════════
//  DATA STRUCTURES — [STRUCT] [PCHAIN] [PSCAN]
// ═══════════════════════════════════════════════════════════════════════════

struct Stats {
    int32_t  health;        // +0x00
    int32_t  maxHealth;     // +0x04
    int32_t  mana;          // +0x08
    int32_t  maxMana;       // +0x0C
    float    speed;         // +0x10
    float    armor;         // +0x14
    double   experience;    // +0x18  (8-byte aligned)
    uint32_t level;         // +0x20
    uint32_t flags;         // +0x24  [bitfield: 0=alive, 1=poisoned, 2=shield, 3=invisible]
};

struct Inventory {
    int32_t gold;           // +0x00
    int32_t items[8];       // +0x04  (item IDs)
    int32_t itemCount;      // +0x24
};

struct Position {
    float x;                // +0x00
    float y;                // +0x04
    float z;                // +0x08
};

struct Entity {
    char     name[32];      // +0x00  [string in struct]
    Stats    stats;         // +0x20
    Position pos;           // +0x48
    Inventory* inventory;   // +0x58  [pointer to heap]
    Entity*  target;        // +0x60  [pointer to another entity]
};

// 4-level pointer chain: g_world → room → player → inventory → gold
struct Room {
    Entity* player;         // +0x00
    Entity* enemies[4];     // +0x08
    int32_t enemyCount;     // +0x28
    char    roomName[32];   // +0x2C
};

struct World {
    Room* currentRoom;      // +0x00
    int32_t roomCount;      // +0x08
    double  gameTime;       // +0x10
};

// ═══════════════════════════════════════════════════════════════════════════
//  GLOBAL VARIABLES — [REGION] [PCHAIN] [SCAN]
// ═══════════════════════════════════════════════════════════════════════════

// Static/BSS globals (static addresses — stable across scans)
World*   g_world   = nullptr;   // Root of 4-level pointer chain
Entity*  g_player  = nullptr;   // Shortcut pointer to player

// Data section globals for basic type scanning
int8_t   g_i8      = -42;
int16_t  g_i16     = -1234;
int32_t  g_i32     = 123456;
int64_t  g_i64     = 9876543210LL;
uint8_t  g_u8      = 200;
uint16_t g_u16     = 50000;
uint32_t g_u32     = 3000000000U;
uint64_t g_u64     = 0xDEADBEEFCAFEULL;
float    g_f32     = 3.14159f;
double   g_f64     = 2.718281828;
char     g_str[32] = "HexScan";
wchar_t  g_wstr[32]= L"WideScan";

// Dense byte pattern for AOB scanning / hex view testing
uint8_t  g_pattern[64] = {
    0xDE, 0xAD, 0xBE, 0xEF,  0xCA, 0xFE, 0xBA, 0xBE,
    0x48, 0x65, 0x78, 0x53,  0x63, 0x61, 0x6E, 0x21,  // "HexScan!"
    0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,  0x0C, 0x0D, 0x0E, 0x0F,
    0xFF, 0xFE, 0xFD, 0xFC,  0xFB, 0xFA, 0xF9, 0xF8,
    0x90, 0x90, 0x90, 0x90,  0xCC, 0xCC, 0xCC, 0xCC,  // NOP + INT3 patterns
    0x41, 0x42, 0x43, 0x44,  0x45, 0x46, 0x47, 0x48,
    0x00, 0x00, 0x00, 0x00,  0xFF, 0xFF, 0xFF, 0xFF,
};

// Thread control
std::atomic<bool> g_running{true};
std::atomic<int32_t> g_tickCount{0};

// ═══════════════════════════════════════════════════════════════════════════
//  PATCHABLE FUNCTIONS — [DISASM] [PATCH] [WATCH]
// ═══════════════════════════════════════════════════════════════════════════

// [PATCH] NOP target: this subtracts damage. NOP it = god mode.
extern "C" {
void __attribute__((noinline)) applyDamage(Entity* entity, int32_t damage) {
    if (entity->stats.health > 0) {
        entity->stats.health -= damage;
        if (entity->stats.health < 0)
            entity->stats.health = 0;
    }
}
}

// [PATCH] Conditional jump inversion: invert jle→jg = always heal
extern "C" {
void __attribute__((noinline)) healPlayer(Entity* entity, int32_t amount) {
    if (entity->stats.health <= entity->stats.maxHealth) {
        entity->stats.health += amount;
        if (entity->stats.health > entity->stats.maxHealth)
            entity->stats.health = entity->stats.maxHealth;
    }
}
}

// [PATCH] Gold subtraction — NOP the sub = free purchases
extern "C" {
int __attribute__((noinline)) purchaseItem(Inventory* inv, int32_t cost, int32_t itemId) {
    if (inv->gold >= cost) {
        inv->gold -= cost;
        if (inv->itemCount < 8) {
            inv->items[inv->itemCount] = itemId;
            inv->itemCount++;
            return 1; // success
        }
    }
    return 0; // failure
}
}

// [DISASM] Function with multiple branch patterns
extern "C" {
int32_t __attribute__((noinline)) calculateDamage(int32_t baseDmg, int32_t armor, int32_t level) {
    int32_t dmg = baseDmg - armor / 2;
    if (dmg < 1) dmg = 1;
    if (level > 10) dmg += level * 2;
    else if (level > 5) dmg += level;
    return dmg;
}
}

// [WATCH] Function that reads/writes a value — for access tracker
extern "C" {
void __attribute__((noinline)) tickGameLoop(Entity* player) {
    // Read health (triggers read watchpoint)
    int32_t hp = player->stats.health;
    
    // Modify mana (triggers write watchpoint)
    if (player->stats.mana < player->stats.maxMana)
        player->stats.mana += 1;
    
    // Update experience (triggers write on double)
    player->stats.experience += 0.1;
    
    // Update position (continuous float change)
    player->pos.x += player->stats.speed * 0.016f;
    
    (void)hp; // suppress unused warning
}
}

// ═══════════════════════════════════════════════════════════════════════════
//  INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════

static Entity* createEnemy(const char* name, int32_t hp, float x, float y) {
    auto* e = new Entity{};
    strncpy(e->name, name, 31);
    e->stats.health = hp;
    e->stats.maxHealth = hp;
    e->stats.mana = 0;
    e->stats.maxMana = 0;
    e->stats.speed = 1.0f;
    e->stats.armor = 5.0f;
    e->stats.experience = 0.0;
    e->stats.level = 1;
    e->stats.flags = 0b0001; // alive
    e->pos = {x, y, 0.0f};
    e->inventory = nullptr;
    e->target = nullptr;
    return e;
}

static void initGameWorld() {
    // Player
    g_player = new Entity{};
    strncpy(g_player->name, "Player_One", 31);
    g_player->stats = {100, 100, 50, 100, 2.5f, 10.0f, 0.0, 5, 0b0101}; // alive + shield
    g_player->pos = {10.0f, 20.0f, 0.0f};
    g_player->inventory = new Inventory{1000, {101,102,103,0,0,0,0,0}, 3};
    g_player->target = nullptr;

    // Enemies
    auto* enemy0 = createEnemy("Goblin",    30, 15.0f, 25.0f);
    auto* enemy1 = createEnemy("Skeleton",  50, 20.0f, 30.0f);
    auto* enemy2 = createEnemy("Dragon",   500, 50.0f, 50.0f);
    auto* enemy3 = createEnemy("Slime",     10,  5.0f, 10.0f);

    // Player targets first enemy
    g_player->target = enemy0;
    // Enemy0 targets player
    enemy0->target = g_player;

    // Room
    auto* room = new Room{};
    room->player = g_player;
    room->enemies[0] = enemy0;
    room->enemies[1] = enemy1;
    room->enemies[2] = enemy2;
    room->enemies[3] = enemy3;
    room->enemyCount = 4;
    strncpy(room->roomName, "Dark_Dungeon", 31);

    // World (root of pointer chain)
    g_world = new World{};
    g_world->currentRoom = room;
    g_world->roomCount = 1;
    g_world->gameTime = 0.0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  BACKGROUND THREAD — [WATCH] [FREEZE] [SCAN: changed/unchanged]
// ═══════════════════════════════════════════════════════════════════════════

static void gameThread() {
    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (!g_world || !g_world->currentRoom || !g_world->currentRoom->player)
            continue;

        Entity* player = g_world->currentRoom->player;

        // [WATCH] Call function that reads/writes player fields
        tickGameLoop(player);

        // [FREEZE] Increment tick counter (good freeze test)
        g_tickCount.fetch_add(1, std::memory_order_relaxed);

        // [SCAN: changed] Update game time
        g_world->gameTime += 1.0;

        // [WATCH] Periodic damage to player (every 5 ticks)
        if (g_tickCount.load() % 5 == 0 && player->stats.health > 0) {
            applyDamage(player, 3);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════════════════════

static void printHeader() {
    std::cout << "================================================================" << std::endl;
    std::cout << "   HexScan Comprehensive Test Target v2.0                       " << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "PID: " << getpid() << std::endl;
    std::cout << std::endl;
}

static void printAddressTable() {
    auto W = std::setw(16);
    auto L = std::left;

    std::cout << "─── Global Scalars (data/BSS section) ──────────────────────────" << std::endl;
    std::cout << L << W << "Type"  << W << "Address"        << "Value" << std::endl;
    std::cout << L << W << "i8"    << W << (void*)&g_i8     << (int)g_i8  << std::endl;
    std::cout << L << W << "i16"   << W << (void*)&g_i16    << g_i16   << std::endl;
    std::cout << L << W << "i32"   << W << (void*)&g_i32    << g_i32   << std::endl;
    std::cout << L << W << "i64"   << W << (void*)&g_i64    << g_i64   << std::endl;
    std::cout << L << W << "u8"    << W << (void*)&g_u8     << (unsigned)g_u8 << std::endl;
    std::cout << L << W << "u16"   << W << (void*)&g_u16    << g_u16   << std::endl;
    std::cout << L << W << "u32"   << W << (void*)&g_u32    << g_u32   << std::endl;
    std::cout << L << W << "u64"   << W << (void*)&g_u64    << g_u64   << std::endl;
    std::cout << L << W << "f32"   << W << (void*)&g_f32    << g_f32   << std::endl;
    std::cout << L << W << "f64"   << W << (void*)&g_f64    << g_f64   << std::endl;
    std::cout << L << W << "string"<< W << (void*)g_str     << g_str   << std::endl;
    std::cout << L << W << "wstring"<< W << (void*)g_wstr   << "(wide)" << std::endl;
    std::cout << L << W << "aob"   << W << (void*)g_pattern << "(64 bytes)" << std::endl;
    std::cout << L << W << "tick"  << W << (void*)&g_tickCount << g_tickCount.load() << std::endl;

    std::cout << std::endl;
    std::cout << "─── Pointer Chain: g_world → currentRoom → player → stats.health" << std::endl;
    std::cout << L << W << "g_world"     << W << (void*)&g_world      << (void*)g_world << std::endl;
    std::cout << L << W << "currentRoom" << W << (void*)&g_world->currentRoom << (void*)g_world->currentRoom << std::endl;
    std::cout << L << W << "player"      << W << (void*)&g_world->currentRoom->player << (void*)g_world->currentRoom->player << std::endl;
    std::cout << L << W << "health"      << W << (void*)&g_player->stats.health << g_player->stats.health << std::endl;
    std::cout << L << W << "gold"        << W << (void*)&g_player->inventory->gold << g_player->inventory->gold << std::endl;

    std::cout << std::endl;
    std::cout << "─── Patchable Functions ────────────────────────────────────────" << std::endl;
    std::cout << L << W << "applyDamage"    << W << (void*)&applyDamage     << "(noinline)" << std::endl;
    std::cout << L << W << "healPlayer"     << W << (void*)&healPlayer      << "(noinline)" << std::endl;
    std::cout << L << W << "purchaseItem"   << W << (void*)&purchaseItem    << "(noinline)" << std::endl;
    std::cout << L << W << "calculateDmg"   << W << (void*)&calculateDamage << "(noinline)" << std::endl;
    std::cout << L << W << "tickGameLoop"   << W << (void*)&tickGameLoop    << "(noinline)" << std::endl;

    std::cout << std::endl;
    std::cout << "─── Enemy Array (structure dissector test) ────────────────────" << std::endl;
    Room* room = g_world->currentRoom;
    for (int i = 0; i < room->enemyCount; i++) {
        Entity* e = room->enemies[i];
        std::cout << L << W << e->name << W << (void*)e << "HP=" << e->stats.health << std::endl;
    }
    std::cout << "================================================================" << std::endl;
}

static void printStatus() {
    Entity* p = g_player;
    std::cout << "\n── Player Status ──" << std::endl;
    std::cout << "  HP:   " << p->stats.health << "/" << p->stats.maxHealth
              << "  MP: " << p->stats.mana << "/" << p->stats.maxMana
              << "  Gold: " << p->inventory->gold
              << "  Lvl: " << p->stats.level
              << "  XP: " << std::fixed << std::setprecision(1) << p->stats.experience
              << "  Pos: (" << p->pos.x << ", " << p->pos.y << ")"
              << "  Tick: " << g_tickCount.load()
              << "  Flags: 0b" << std::bitset<4>(p->stats.flags)
              << std::endl;

    std::cout << "── Scalars ──" << std::endl;
    std::cout << "  i8=" << (int)g_i8 << " i16=" << g_i16 << " i32=" << g_i32 << " i64=" << g_i64
              << " f32=" << g_f32 << " f64=" << g_f64 << " str=\"" << g_str << "\"" << std::endl;

    Room* room = g_world->currentRoom;
    std::cout << "── Enemies ──" << std::endl;
    for (int i = 0; i < room->enemyCount; i++) {
        Entity* e = room->enemies[i];
        std::cout << "  [" << i << "] " << e->name << " HP=" << e->stats.health << std::endl;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  INTERACTIVE MENU
// ═══════════════════════════════════════════════════════════════════════════

static void printMenu() {
    std::cout << "\n─ Commands ─────────────────────────────────────────────────────" << std::endl;
    std::cout << " [1] Change scalars (for next-scan testing)" << std::endl;
    std::cout << " [2] Increase scalars" << std::endl;
    std::cout << " [3] Decrease scalars" << std::endl;
    std::cout << " [4] Reset scalars to defaults" << std::endl;
    std::cout << " [5] Deal 10 damage to player" << std::endl;
    std::cout << " [6] Heal player 20 HP" << std::endl;
    std::cout << " [7] Buy item (costs 100 gold)" << std::endl;
    std::cout << " [8] Attack enemy[0] for 15 dmg" << std::endl;
    std::cout << " [9] Toggle player flags (poison/shield/invis)" << std::endl;
    std::cout << " [s] Show current status" << std::endl;
    std::cout << " [a] Show address table" << std::endl;
    std::cout << " [q] Quit" << std::endl;
    std::cout << "─────────────────────────────────────────────────────────────── " << std::endl;
    std::cout << "> ";
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);

    initGameWorld();

    printHeader();
    printAddressTable();

    // Start background game thread
    std::thread bgThread(gameThread);

    // Stack variables for scan testing (different memory region than globals)
    volatile int32_t stack_i32 = 1234;
    volatile float   stack_f32 = 123.456f;

    std::cout << "\n─── Stack Variables (for region-type testing) ───────────────────" << std::endl;
    std::cout << std::left << std::setw(16) << "stack_i32" << std::setw(16) << (void*)&stack_i32 << stack_i32 << std::endl;
    std::cout << std::left << std::setw(16) << "stack_f32" << std::setw(16) << (void*)&stack_f32 << stack_f32 << std::endl;

    std::string input;
    while (true) {
        printMenu();
        if (!(std::cin >> input)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        char cmd = input[0];
        if (cmd == 'q') break;

        switch (cmd) {
            case '1': // Change (for Equal → Changed scan)
                g_i8  = 99;
                g_i16 = 9999;
                g_i32 = 999999;
                g_i64 = 999999999LL;
                g_f32 = 999.9f;
                g_f64 = 9999.99;
                strncpy(g_str, "Changed!", 31);
                stack_i32 = 9999;
                stack_f32 = 999.9f;
                std::cout << ">> All scalars changed to '999' patterns." << std::endl;
                break;

            case '2': // Increase (for Increased/IncreasedBy scan)
                g_i8  += 5;
                g_i16 += 10;
                g_i32 += 100;
                g_i64 += 1000;
                g_f32 += 1.5f;
                g_f64 += 2.5;
                stack_i32 += 10;
                stack_f32 += 1.5f;
                std::cout << ">> Scalars increased." << std::endl;
                break;

            case '3': // Decrease (for Decreased/DecreasedBy scan)
                g_i8  -= 3;
                g_i16 -= 5;
                g_i32 -= 50;
                g_i64 -= 500;
                g_f32 -= 0.5f;
                g_f64 -= 1.0;
                stack_i32 -= 5;
                stack_f32 -= 0.5f;
                std::cout << ">> Scalars decreased." << std::endl;
                break;

            case '4': // Reset
                g_i8  = -42;
                g_i16 = -1234;
                g_i32 = 123456;
                g_i64 = 9876543210LL;
                g_u8  = 200;
                g_u16 = 50000;
                g_u32 = 3000000000U;
                g_u64 = 0xDEADBEEFCAFEULL;
                g_f32 = 3.14159f;
                g_f64 = 2.718281828;
                strncpy(g_str, "HexScan", 31);
                stack_i32 = 1234;
                stack_f32 = 123.456f;
                std::cout << ">> Scalars reset to defaults." << std::endl;
                break;

            case '5': // Damage player
                applyDamage(g_player, 10);
                std::cout << ">> Player took 10 damage. HP=" << g_player->stats.health << std::endl;
                break;

            case '6': // Heal player
                healPlayer(g_player, 20);
                std::cout << ">> Player healed 20 HP. HP=" << g_player->stats.health << std::endl;
                break;

            case '7': // Purchase
                if (purchaseItem(g_player->inventory, 100, 200 + g_player->inventory->itemCount))
                    std::cout << ">> Purchased item. Gold=" << g_player->inventory->gold << std::endl;
                else
                    std::cout << ">> Purchase failed (not enough gold or inventory full)." << std::endl;
                break;

            case '8': { // Attack enemy
                Room* room = g_world->currentRoom;
                if (room->enemyCount > 0 && room->enemies[0]) {
                    int32_t dmg = calculateDamage(15, (int32_t)room->enemies[0]->stats.armor, (int32_t)g_player->stats.level);
                    applyDamage(room->enemies[0], dmg);
                    std::cout << ">> Attacked " << room->enemies[0]->name
                              << " for " << dmg << " damage. HP=" << room->enemies[0]->stats.health << std::endl;
                }
                break;
            }

            case '9': // Toggle flags
                g_player->stats.flags ^= 0b1110; // toggle poison, shield, invisible
                std::cout << ">> Flags toggled. flags=0b";
                for (int b = 3; b >= 0; b--)
                    std::cout << ((g_player->stats.flags >> b) & 1);
                std::cout << std::endl;
                break;

            case 's': // Status
                printStatus();
                break;

            case 'a': // Address table
                printAddressTable();
                break;

            default:
                std::cout << "Unknown command." << std::endl;
                break;
        }
    }

    // Cleanup
    g_running.store(false, std::memory_order_relaxed);
    bgThread.join();

    std::cout << "Target exiting." << std::endl;
    return 0;
}
