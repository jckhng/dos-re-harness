#pragma once

#include "pakupaku/assets.hpp"
#include "pakupaku/game.hpp"
#include "pakupaku/renderer.hpp"

namespace pakupaku {

void render_map_frame(Renderer& renderer, const Assets& assets);
void render_game_frame(Renderer& renderer, const Assets& assets,
                       const GameState& state, bool show_ready);

}  // namespace pakupaku
