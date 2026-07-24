#include "pakupaku/assets.hpp"
#include "pakupaku/game.hpp"
#include "pakupaku/presenter.hpp"
#include "pakupaku/renderer.hpp"
#include "pakupaku/sha256.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_sha256() {
    const std::vector<std::uint8_t> value{'a', 'b', 'c'};
    require(
        pakupaku::sha256_hex(value) ==
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        "SHA-256 known vector failed");
}

void test_map_rle() {
    std::vector<std::uint8_t> encoded;
    for (int run = 0; run < 6; ++run) {
        encoded.push_back(0xFF);
        encoded.push_back(3);
    }
    encoded.push_back(0xEA);
    encoded.push_back(3);
    const auto decoded = pakupaku::decode_map(encoded);
    require(std::all_of(decoded.begin(), decoded.end(),
                        [](std::uint8_t value) { return value == 3; }),
            "MAP.DAT RLE expansion failed");
}

void test_tile_alignment() {
    std::vector<std::uint8_t> tiles(24);
    tiles[0] = 0x12;
    tiles[1] = 0xF0;
    tiles[2] = 0x34;
    tiles[3] = 0x0F;
    tiles[12] = 0x56;
    tiles[13] = 0xF0;
    tiles[14] = 0x78;
    tiles[15] = 0x0F;

    pakupaku::Renderer odd;
    odd.clear(0x0A);
    odd.draw_map_tile(tiles, 0, 1, 0);
    require(odd.raw()[1] == 0xB2 && odd.raw()[3] == 0x3E,
            "odd tile alignment failed");

    pakupaku::Renderer even;
    even.clear(0x0A);
    even.draw_map_tile(tiles, 0, 2, 0);
    require(even.raw()[3] == 0xF6 && even.raw()[5] == 0x7A,
            "even tile alignment failed");
}

void test_game_presenter_uses_live_collision_map() {
    pakupaku::Assets assets;
    assets.fonts.resize(1152);
    assets.map_tiles.resize(41 * pakupaku::map_tile_bytes);
    assets.sprites.resize(87 * 60);
    assets.map_cells.fill(40);
    assets.map_cells[0] = 32;
    assets.map_tiles[32 * pakupaku::map_tile_bytes] = 0x11;
    assets.map_tiles[32 * pakupaku::map_tile_bytes + 1] = 0x00;
    assets.map_tiles[40 * pakupaku::map_tile_bytes] = 0x22;
    assets.map_tiles[40 * pakupaku::map_tile_bytes + 1] = 0x00;

    auto state = pakupaku::GameState::initial(assets);
    state.collision[0] = 40;
    pakupaku::Renderer renderer;
    pakupaku::render_game_frame(renderer, assets, state, false);

    require(renderer.raw()[1] == 0x22,
            "game presenter must erase consumed pellets from live state");
}

}  // namespace

int main() {
    try {
        test_sha256();
        test_map_rle();
        test_tile_alignment();
        test_game_presenter_uses_live_collision_map();
        std::cout << "pakupaku core tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
