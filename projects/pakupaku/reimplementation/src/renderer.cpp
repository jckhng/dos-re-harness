#include "pakupaku/renderer.hpp"

#include <array>
#include <fstream>
#include <stdexcept>

namespace pakupaku {

Renderer::Renderer() {
    clear(0);
}

void Renderer::clear(std::uint8_t color) {
    const auto attribute =
        static_cast<std::uint8_t>((color & 0x0FU) | ((color & 0x0FU) << 4U));
    for (std::size_t offset = 0; offset < raw_.size(); offset += 2) {
        raw_[offset] = 0xDD;
        raw_[offset + 1] = attribute;
    }
}

void Renderer::draw_map_tile(const std::vector<std::uint8_t>& tiles,
                             std::uint8_t tile, int x, int y) {
    const auto record = static_cast<std::size_t>(tile) * map_tile_bytes;
    if (record + map_tile_bytes > tiles.size()) {
        throw std::runtime_error("MAP.DAT references an invalid map tile");
    }
    if (x < 0 || x + tile_width > screen_width ||
        y < 0 || y + tile_height > screen_height) {
        throw std::runtime_error("map tile lies outside the framebuffer");
    }

    auto source = record + (x % 2 == 0 ? map_tile_bytes / 2 : 0);
    auto destination =
        static_cast<std::size_t>(y * screen_width + (x | 1));
    for (int row = 0; row < tile_height; ++row) {
        for (int pair = 0; pair < 2; ++pair) {
            const auto paint = tiles[source++];
            const auto mask = tiles[source++];
            const auto target = destination + static_cast<std::size_t>(pair * 2);
            raw_[target] =
                static_cast<std::uint8_t>(paint | (mask & raw_[target]));
        }
        destination += screen_width;
    }
}

int Renderer::text_width(const std::vector<std::uint8_t>& fonts,
                         const std::string& text) const {
    if (fonts.size() != 1152) {
        throw std::runtime_error("FONTS.DAT must contain 1152 bytes");
    }
    int width = 0;
    for (const unsigned char character : text) {
        width += fonts[0x400U + (character & 0x7FU)];
    }
    return width;
}

void Renderer::draw_text(const std::vector<std::uint8_t>& fonts,
                         const std::string& text, std::uint8_t color,
                         int x, int y) {
    if (fonts.size() != 1152) {
        throw std::runtime_error("FONTS.DAT must contain 1152 bytes");
    }
    color &= 0x0F;
    for (const unsigned char character : text) {
        const auto glyph = static_cast<std::size_t>(character & 0x7F) * 8U;
        for (int row = 0; row < 8; ++row) {
            const auto bits = fonts[glyph + static_cast<std::size_t>(row)];
            for (int column = 0; column < 8; ++column) {
                if ((bits & (0x80U >> column)) == 0) {
                    continue;
                }
                const int pixel_x = x + column;
                const int pixel_y = y + row;
                if (pixel_x < 0 || pixel_x >= screen_width ||
                    pixel_y < 0 || pixel_y >= screen_height) {
                    continue;
                }
                const auto target = static_cast<std::size_t>(
                    pixel_y * screen_width + (pixel_x / 2) * 2 + 1);
                if (pixel_x % 2 == 0) {
                    raw_[target] = static_cast<std::uint8_t>(
                        (raw_[target] & 0xF0U) | color);
                } else {
                    raw_[target] = static_cast<std::uint8_t>(
                        (raw_[target] & 0x0FU) | (color << 4U));
                }
            }
        }
        x += fonts[0x400U + (character & 0x7FU)];
    }
}
void Renderer::draw_sprite(const std::vector<std::uint8_t>& sprites,
                           std::uint8_t sprite, int x, int y) {
    constexpr int sprite_bytes = 60;
    constexpr int sprite_width = 5;
    constexpr int sprite_height = 5;
    const auto record = static_cast<std::size_t>(sprite) * sprite_bytes;
    if (record + sprite_bytes > sprites.size()) {
        throw std::runtime_error("invalid sprite index");
    }
    if (x < 0 || x + sprite_width > screen_width ||
        y < 0 || y + sprite_height > screen_height) {
        throw std::runtime_error("sprite lies outside the framebuffer");
    }
    auto source = record + (x % 2 == 0 ? sprite_bytes / 2 : 0);
    auto destination =
        static_cast<std::size_t>(y * screen_width + (x | 1));
    for (int row = 0; row < sprite_height; ++row) {
        for (int pair = 0; pair < 3; ++pair) {
            const auto paint = sprites[source++];
            const auto mask = sprites[source++];
            const auto target = destination + static_cast<std::size_t>(pair * 2);
            raw_[target] =
                static_cast<std::uint8_t>(paint | (mask & raw_[target]));
        }
        destination += screen_width;
    }
}
void Renderer::draw_map(const Assets& assets) {
    for (int row = 0; row < map_height; ++row) {
        for (int column = 0; column < map_width; ++column) {
            draw_map_tile(
                assets.map_tiles,
                assets.map_cells[static_cast<std::size_t>(
                    row * map_width + column)],
                1 + column * tile_width,
                row * tile_height);
        }
    }
}

std::array<std::uint8_t, screen_width * screen_height>
Renderer::indexed_pixels() const {
    std::array<std::uint8_t, screen_width * screen_height> result{};
    for (int y = 0; y < screen_height; ++y) {
        for (int cell = 0; cell < screen_width / 2; ++cell) {
            const auto attribute =
                raw_[static_cast<std::size_t>(y * screen_width + cell * 2 + 1)];
            result[static_cast<std::size_t>(y * screen_width + cell * 2)] =
                attribute & 0x0F;
            result[static_cast<std::size_t>(
                y * screen_width + cell * 2 + 1)] = attribute >> 4;
        }
    }
    return result;
}

void Renderer::write_raw(const std::filesystem::path& path) const {
    std::ofstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("cannot create " + path.string());
    }
    stream.write(reinterpret_cast<const char*>(raw_.data()),
                 static_cast<std::streamsize>(raw_.size()));
}

void Renderer::write_ppm(const std::filesystem::path& path) const {
    std::ofstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("cannot create " + path.string());
    }
    stream << "P6\n" << screen_width << ' ' << screen_height << "\n255\n";
    for (const auto color : indexed_pixels()) {
        const auto& rgb = cga_palette[color];
        stream.write(reinterpret_cast<const char*>(rgb.data()), 3);
    }
}

}  // namespace pakupaku
