#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pakupaku {

struct AssetFile {
    const char* name;
    std::size_t size;
    const char* sha256;
};

inline constexpr std::array<AssetFile, 4> required_asset_files{{
    {"FONTS.DAT", 1152,
     "df9948df60e2a7e9785f0cf414eeefe1ebcf80019449775dea026553e2564ee9"},
    {"MAP.DAT", 566,
     "78a6ca53dc9fa87972ba1e83df8bd9db9568b6a909992187eaa2bd9e350e0fc9"},
    {"MAPTILES.DAT", 1152,
     "f5bc570be78ebd43977460c9ec9720afdbd86ba23cf6a2b85c25de6f8a3916eb"},
    {"SPRITES.DAT", 6720,
     "9de595527316bed18c5db0e1169083c348160352ce08e6c57b47ba686dfbc354"},
}};

struct Assets {
    std::vector<std::uint8_t> fonts;
    std::vector<std::uint8_t> map;
    std::vector<std::uint8_t> map_tiles;
    std::vector<std::uint8_t> sprites;
    std::array<std::uint8_t, 28 * 31> map_cells{};

    static Assets load_verified(const std::filesystem::path& directory);
};

std::array<std::uint8_t, 28 * 31>
decode_map(const std::vector<std::uint8_t>& encoded);

}  // namespace pakupaku
