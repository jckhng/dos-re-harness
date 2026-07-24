#include "pakupaku/presenter.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>

namespace pakupaku {
namespace {

std::string score_text(std::uint32_t score) {
    std::ostringstream output;
    output << std::setfill('0') << std::setw(8) << score;
    return output.str();
}

void draw_live_map(Renderer& renderer, const Assets& assets,
                   const GameState& state) {
    for (int row = 0; row < map_height; ++row) {
        for (int column = 0; column < map_width; ++column) {
            const auto index = static_cast<std::size_t>(
                row * map_width + column);
            auto tile = assets.map_cells[index];
            if ((tile == 32 || tile == 33) &&
                state.collision[index] == 40) {
                tile = 40;
            }
            renderer.draw_map_tile(
                assets.map_tiles, tile,
                1 + column * tile_width, row * tile_height);
        }
    }
}

void draw_actors(Renderer& renderer, const Assets& assets,
                 const GameState& state) {
    renderer.draw_sprite(
        assets.sprites,
        static_cast<std::uint8_t>(state.player.actor.sprite),
        state.player.actor.x, state.player.actor.y);
    for (const auto& ghost : state.ghosts) {
        renderer.draw_sprite(
            assets.sprites, static_cast<std::uint8_t>(ghost.actor.sprite),
            ghost.actor.x, ghost.actor.y);
    }
}

void draw_hud(Renderer& renderer, const Assets& assets,
              const GameState& state) {
    renderer.draw_text(assets.fonts, "HIGH SCORE", 7, 104, 12);
    renderer.draw_text(assets.fonts, score_text(state.high_score), 3, 108, 18);
    renderer.draw_text(assets.fonts, "YOUR SCORE", 7, 104, 30);
    renderer.draw_text(assets.fonts, score_text(state.score), 3, 108, 36);

    for (int life = 0; life < state.lives - 1; ++life) {
        renderer.draw_sprite(assets.sprites, 76, 2 + life * 6, 94);
    }
    constexpr std::array<int, 22> level_sprites{{
        86, 56, 57, 58, 58, 59, 59, 60, 60, 61, 61,
        62, 62, 63, 63, 63, 63, 63, 63, 63, 63, 63,
    }};
    const auto level_index =
        std::min<std::size_t>(static_cast<std::size_t>(state.level),
                              level_sprites.size() - 1);
    renderer.draw_sprite(
        assets.sprites,
        static_cast<std::uint8_t>(level_sprites[level_index]), 78, 94);

    renderer.draw_text(assets.fonts, "S", 7, 107, 94);
    renderer.draw_text(assets.fonts, "O", 15, 111, 94);
    renderer.draw_text(assets.fonts, "UND", 7, 115, 94);
    renderer.draw_text(assets.fonts, "ON", 10, 129, 94);
}

}  // namespace

void render_map_frame(Renderer& renderer, const Assets& assets) {
    renderer.clear(0);
    renderer.draw_map(assets);
}

void render_game_frame(Renderer& renderer, const Assets& assets,
                       const GameState& state, bool show_ready) {
    renderer.clear(0);
    draw_live_map(renderer, assets, state);
    draw_actors(renderer, assets, state);
    draw_hud(renderer, assets, state);
    if (show_ready || state.ready_banner) {
        const std::string ready = "READY!";
        renderer.draw_text(
            assets.fonts, ready, 14,
            43 - renderer.text_width(assets.fonts, ready) / 2, 50);
    }
}

}  // namespace pakupaku
