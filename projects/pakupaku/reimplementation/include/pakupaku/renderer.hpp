#pragma once

#include "pakupaku/assets.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace pakupaku {

inline constexpr int screen_width = 160;
inline constexpr int screen_height = 100;
inline constexpr int map_width = 28;
inline constexpr int map_height = 31;
inline constexpr int tile_width = 3;
inline constexpr int tile_height = 3;
inline constexpr int map_tile_bytes = 24;

inline constexpr std::array<std::array<std::uint8_t, 3>, 16> cga_palette{{
    {{0x00, 0x00, 0x00}}, {{0x00, 0x00, 0xAA}},
    {{0x00, 0xAA, 0x00}}, {{0x00, 0xAA, 0xAA}},
    {{0xAA, 0x00, 0x00}}, {{0xAA, 0x00, 0xAA}},
    {{0xAA, 0x55, 0x00}}, {{0xAA, 0xAA, 0xAA}},
    {{0x55, 0x55, 0x55}}, {{0x55, 0x55, 0xFF}},
    {{0x55, 0xFF, 0x55}}, {{0x55, 0xFF, 0xFF}},
    {{0xFF, 0x55, 0x55}}, {{0xFF, 0x55, 0xFF}},
    {{0xFF, 0xFF, 0x55}}, {{0xFF, 0xFF, 0xFF}},
}};

class Renderer {
public:
    Renderer();

    void clear(std::uint8_t color);
    void draw_map(const Assets& assets);
    void draw_map_tile(const std::vector<std::uint8_t>& tiles,
                       std::uint8_t tile, int x, int y);
    void draw_sprite(const std::vector<std::uint8_t>& sprites,
                     std::uint8_t sprite, int x, int y);
    int text_width(const std::vector<std::uint8_t>& fonts,
                   const std::string& text) const;
    void draw_text(const std::vector<std::uint8_t>& fonts,
                   const std::string& text, std::uint8_t color,
                   int x, int y);

    const std::array<std::uint8_t, screen_width * screen_height>& raw() const {
        return raw_;
    }
    std::array<std::uint8_t, screen_width * screen_height>
    indexed_pixels() const;
    void write_raw(const std::filesystem::path& path) const;
    void write_ppm(const std::filesystem::path& path) const;

private:
    std::array<std::uint8_t, screen_width * screen_height> raw_{};
};

}  // namespace pakupaku
