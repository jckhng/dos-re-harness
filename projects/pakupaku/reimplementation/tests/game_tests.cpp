#include "pakupaku/assets.hpp"
#include "pakupaku/game.hpp"
#include "pakupaku/presenter.hpp"
#include "pakupaku/renderer.hpp"
#include "pakupaku/sha256.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
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

void test_initial_left_corridor() {
    pakupaku::Assets assets;
    constexpr std::array<std::uint8_t, 28> row{{
        8, 33, 32, 32, 15, 15, 32, 32, 32, 32, 32, 32, 32, 40,
        40, 32, 32, 32, 32, 32, 32, 32, 15, 15, 32, 32, 33, 9,
    }};
    for (std::size_t column = 0; column < row.size(); ++column) {
        assets.map_cells[23 * 28 + column] = row[column];
    }

    auto state = pakupaku::GameState::initial(assets);
    state.request(pakupaku::Direction::left);
    for (int step = 0; step < 22; ++step) {
        state.step_player();
    }

    require(state.player.actor.x == 18, "player x after 22 left steps");
    require(state.player.actor.y == 68, "player y after 22 left steps");
    require(state.player.actor.sprite == 78, "left animation sprite");
    require(state.score == 70, "seven regular pellets score 70");
    require(state.pellets_remaining == 237, "seven pellets consumed");
}

void test_ghost_rng_call_count() {
    pakupaku::Assets assets;
    auto state = pakupaku::GameState::initial(assets);

    for (int step = 0; step < 22; ++step) {
        state.step_ghosts();
    }

    require(state.rng_state == 0x45efab28U,
            "four ghosts consume one random value per update");
}

pakupaku::Assets passable_assets() {
    pakupaku::Assets assets;
    assets.map_cells.fill(40);
    return assets;
}

void test_normal_ghost_collision_resets_life() {
    const auto assets = passable_assets();
    auto state = pakupaku::GameState::initial(assets);
    state.ghosts[0].actor = {40, 68, 6, 40, 68};
    state.ghosts[0].direction = pakupaku::Direction::left;

    state.step();

    require(state.lives == 2, "normal ghost collision costs one life");
    require(!state.game_over, "two remaining lives continue the round");
    require(state.ready_banner,
            "life reset presents READY before gameplay resumes");
    require(state.score == 0 && state.pellets_remaining == 244,
            "life reset preserves score and pellet state");
    require(state.player.actor.x == 40 && state.player.actor.y == 68,
            "life reset restores player position");
    require(state.player.actor.sprite == 76,
            "life reset restores player sprite");
    require(state.player.direction == pakupaku::Direction::left &&
                state.player.requested_direction == pakupaku::Direction::left,
            "life reset restores player directions");
    require(state.ghosts[0].actor.x == 40 &&
                state.ghosts[0].actor.y == 32,
            "life reset restores red position");
    require(state.ghosts[2].release_ticks == 30 &&
                state.ghosts[3].release_ticks == 60,
            "life reset restores pen release counters");
    require(state.ghosts[1].in_pen && state.ghosts[2].in_pen &&
                state.ghosts[3].in_pen,
            "ghost reset preserves the collision routine's pen flags");
}

void test_frightened_ghost_collision_scores_and_returns_to_pen() {
    const auto assets = passable_assets();
    auto state = pakupaku::GameState::initial(assets);
    state.ghosts[0].actor = {40, 68, 32, 40, 68};
    state.ghosts[0].direction = pakupaku::Direction::left;
    state.ghosts[0].mode = 2;
    state.ghosts[0].mode_ticks = 200;

    state.step();

    require(state.lives == 3, "frightened collision does not cost a life");
    require(!state.ready_banner,
            "frightened collision does not present READY");
    require(state.score == 200, "first frightened ghost scores 200");
    require(state.ghost_score == 400,
            "frightened ghost score doubles after collision");
    require(state.ghosts[0].mode == 3,
            "eaten frightened ghost enters pen-return mode");
}

void test_original_data_checkpoint_when_available() {
    const char* data_dir = std::getenv("PAKUPAKU_DATA_DIR");
    if (data_dir == nullptr || std::string(data_dir).empty()) {
        return;
    }

    const auto assets = pakupaku::Assets::load_verified(data_dir);
    auto state = pakupaku::GameState::initial(assets);
    state.request(pakupaku::Direction::left);
    for (int step = 0; step < 22; ++step) {
        state.step();
    }

    require(state.player.actor.x == 18, "checkpoint player x");
    require(state.player.actor.y == 68, "checkpoint player y");
    require(state.player.actor.sprite == 78, "checkpoint player sprite");
    require(state.score == 70, "checkpoint score");
    require(state.pellets_remaining == 237, "checkpoint pellets");
    require(state.rng_state == 0x45efab28U, "checkpoint random state");

    const auto& red = state.ghosts[0];
    require(red.actor.x == 27 && red.actor.y == 41,
            "checkpoint red position");
    require(red.actor.sprite == 5, "checkpoint red sprite");
    require(red.direction == pakupaku::Direction::down,
            "checkpoint red direction");
    require(red.release_ticks == 0 && !red.in_pen,
            "checkpoint red pen state");

    const auto& magenta = state.ghosts[1];
    require(magenta.actor.x == 27 && magenta.actor.y == 33,
            "checkpoint magenta position");
    require(magenta.actor.sprite == 13, "checkpoint magenta sprite");
    require(magenta.direction == pakupaku::Direction::down,
            "checkpoint magenta direction");
    require(magenta.release_ticks == 0 && !magenta.in_pen,
            "checkpoint magenta pen state");

    const auto& cyan = state.ghosts[2];
    require(cyan.actor.x == 33 && cyan.actor.y == 39,
            "checkpoint cyan position");
    require(cyan.actor.sprite == 17, "checkpoint cyan sprite");
    require(cyan.direction == pakupaku::Direction::up,
            "checkpoint cyan direction");
    require(cyan.release_ticks == 23 && cyan.in_pen,
            "checkpoint cyan pen state");

    const auto& brown = state.ghosts[3];
    require(brown.actor.x == 47 && brown.actor.y == 41,
            "checkpoint brown position");
    require(brown.actor.sprite == 25, "checkpoint brown sprite");
    require(brown.direction == pakupaku::Direction::up,
            "checkpoint brown direction");
    require(brown.release_ticks == 60 && brown.in_pen,
            "checkpoint brown pen state");

    pakupaku::Renderer renderer;
    pakupaku::render_game_frame(renderer, assets, state, false);
    const std::vector<std::uint8_t> first_movement_frame(
        renderer.raw().begin(), renderer.raw().end());
    require(
        pakupaku::sha256_hex(first_movement_frame) ==
            "d786086a2f871adf11e9f000e5538bc9"
            "d0ed38f8c340b605422b8a9f2b0438a3",
        "checkpoint first-movement frame hash");

    for (int step = 22; step < 274; ++step) {
        state.step();
    }

    require(state.rng_state == 0x4885f938U,
            "life-loss checkpoint random state");
    require(state.lives == 2, "life-loss checkpoint lives");
    require(state.ready_banner, "life-loss checkpoint READY banner");
    require(state.score == 70 && state.pellets_remaining == 237,
            "life-loss checkpoint preserves board progress");
    require(state.ghost_mode == 1 && state.ghost_mode_phase == 2 &&
                state.ghost_mode_ticks == 240,
            "life-loss checkpoint global ghost mode state");
    require(state.player.actor.x == 40 && state.player.actor.y == 68 &&
                state.player.actor.sprite == 76,
            "life-loss checkpoint player reset");
    require(state.ghosts[0].actor.x == 40 &&
                state.ghosts[0].actor.y == 32 &&
                state.ghosts[0].actor.sprite == 6,
            "life-loss checkpoint red reset");
    require(state.ghosts[1].actor.x == 41 &&
                state.ghosts[1].actor.y == 39 &&
                state.ghosts[1].actor.sprite == 8,
            "life-loss checkpoint magenta reset");
    require(state.ghosts[2].actor.x == 34 &&
                state.ghosts[2].actor.y == 39 &&
                state.ghosts[2].actor.sprite == 20 &&
                state.ghosts[2].release_ticks == 30 &&
                state.ghosts[2].in_pen,
            "life-loss checkpoint cyan reset");
    require(state.ghosts[3].actor.x == 47 &&
                state.ghosts[3].actor.y == 39 &&
                state.ghosts[3].actor.sprite == 24 &&
                state.ghosts[3].release_ticks == 60 &&
                state.ghosts[3].in_pen,
            "life-loss checkpoint brown reset");

    pakupaku::render_game_frame(renderer, assets, state, false);
    const std::vector<std::uint8_t> life_loss_frame(
        renderer.raw().begin(), renderer.raw().end());
    require(
        pakupaku::sha256_hex(life_loss_frame) ==
            "d0038f3fa4fe07c9d7053c54700a054e"
            "3f01e02bb298f5ff1576efc349cb7a9e",
        "checkpoint life-loss frame hash");
}

}  // namespace

int main() {
    try {
        test_initial_left_corridor();
        test_ghost_rng_call_count();
        test_normal_ghost_collision_resets_life();
        test_frightened_ghost_collision_scores_and_returns_to_pen();
        test_original_data_checkpoint_when_available();
        std::cout << "pakupaku game tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
