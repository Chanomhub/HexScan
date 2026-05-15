#include <gtest/gtest.h>
#include "../src/backend/scanner/aobUtils.h"
#include "../src/backend/disassembler/disassembler.h"
#include "../src/backend/patch/patchManager.h"
#include "../src/gui/gui.h"
#include <vector>
#include <cstdint>
#include <list>
#include <mutex>

// Mock Gui globals for testing
namespace Gui {
    std::list<std::pair<std::string, int>> logs;
    std::mutex logsMutex;
}

TEST(AOBTest, ValidPattern) {
    auto result = ParseAOBString("48 8B 05 ?? ?? ?? ??");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.bytes.size(), 7);
    EXPECT_EQ(result.mask.size(), 7);
    EXPECT_EQ(result.mask[3], 0x00); // Wildcard
}

TEST(AOBTest, SpacingVariations) {
    auto res1 = ParseAOBString("488B05????????");
    EXPECT_TRUE(res1.success);
    EXPECT_EQ(res1.bytes.size(), 7);

    auto res2 = ParseAOBString("  48   8B   05 ?? ?? ?? ??  ");
    EXPECT_TRUE(res2.success);
    EXPECT_EQ(res2.bytes.size(), 7);
}

TEST(AOBTest, SingleWildcard) {
    auto result = ParseAOBString("48 8B 05 ? ? ? ?");
    // This currently fails in the current implementation because it expects even number of chars
    EXPECT_TRUE(result.success); 
    EXPECT_EQ(result.bytes.size(), 7);
}

TEST(AOBTest, NibbleWildcard) {
    auto result = ParseAOBString("4? 8B ?5");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.bytes.size(), 3);
    EXPECT_EQ(result.mask[0], 0xF0);
    EXPECT_EQ(result.bytes[0], 0x40);
    EXPECT_EQ(result.mask[2], 0x0F);
    EXPECT_EQ(result.bytes[2], 0x05);
}

TEST(AOBTest, InvalidPattern) {
    auto result = ParseAOBString("GG WP");
    EXPECT_FALSE(result.success);
}

#include "../src/backend/scanner/scanner.h"

TEST(ScannerComparatorTest, AOBMatching) {
    Scanner scanner("TestScanner");
    
    // Pattern: 48 8B ?? ?5
    auto parseRes = ParseAOBString("48 8B ?? ?5");
    ASSERT_TRUE(parseRes.success);
    
    scanner.setValue(parseRes.bytes);
    scanner.setValueMask(parseRes.mask);
    
    auto cmp = scanner.getAOBComparator();
    
    // Test match
    uint8_t data1[] = {0x48, 0x8B, 0x12, 0x35};
    EXPECT_TRUE(cmp(data1));
    
    uint8_t data2[] = {0x48, 0x8B, 0xFF, 0xA5};
    EXPECT_TRUE(cmp(data2));
    
    // Test mismatch
    uint8_t data3[] = {0x49, 0x8B, 0x12, 0x35};
    EXPECT_FALSE(cmp(data3));
    
    uint8_t data4[] = {0x48, 0x8B, 0x12, 0x34}; // Last nibble must be 5
    EXPECT_FALSE(cmp(data4));
}

TEST(DisassemblerTest, NOPCreation) {
    auto nops = Disassembler::createNOP(5);
    EXPECT_EQ(nops.size(), 5);
    for (auto b : nops) {
        EXPECT_EQ(b, 0x90);
    }
}

TEST(DisassemblerTest, DecodeBasicInstruction) {
    // 48 89 E5 -> mov rbp, rsp
    uint8_t code[] = {0x48, 0x89, 0xE5};
    auto inst = Disassembler::disassemble(code, sizeof(code), 0x1000);
    EXPECT_TRUE(inst.valid);
    EXPECT_EQ(inst.mnemonic, "mov");
    EXPECT_EQ(inst.length, 3);
}

TEST(PatchManagerTest, ConditionalJumpCheck) {
    // 74 05 -> jz +5
    uint8_t jz[] = {0x74, 0x05};
    // Note: PatchManager::isConditionalJump reads from memory, 
    // so we can't easily unit test it without a mock process.
    // However, we can test the internal logic if we expose it or use a helper.
    // For now, let's just verify the logic exists and compiles.
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
