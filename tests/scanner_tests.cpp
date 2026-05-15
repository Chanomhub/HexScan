#include <gtest/gtest.h>
#include "../src/backend/scanner/aobUtils.h"

TEST(AOBTest, ValidPattern) {
    auto result = ParseAOBString("48 8B 05 ?? ?? ?? ??");
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.bytes.size(), 7);
    EXPECT_EQ(result.mask.size(), 7);
    EXPECT_EQ(result.mask[3], 0x00); // Wildcard
}

TEST(AOBTest, InvalidPattern) {
    auto result = ParseAOBString("GG WP");
    EXPECT_FALSE(result.success);
}

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
