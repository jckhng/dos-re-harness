#pragma once

#include "pakupaku/assets.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace pakupaku {

enum class Direction : std::uint8_t {
    up = 0,
    right = 1,
    down = 2,
    left = 3,
};

struct Actor {
    int x{};
    int y{};
    int sprite{};
    int previous_x{};
    int previous_y{};
};

struct Player {
    Actor actor;
    Direction direction{Direction::left};
    Direction requested_direction{Direction::left};
    int animation{};
};

struct Ghost {
    Actor actor;
    Direction direction{};
    int sprite_family{};
    int personality{};
    int mode{};
    int mode_ticks{};
    int release_ticks{};
    int target_x{};
    int target_y{};
    bool in_pen{};
    int animation{};
    bool animation_toggle{};
};

struct GameState {
    std::uint32_t score{};
    std::uint32_t high_score{80000};
    int lives{3};
    int level{1};
    int pellets_remaining{244};
    int frightened_ticks{};
    int update_divisor{6};
    int ghost_mode{};
    int ghost_mode_phase{};
    int ghost_mode_ticks{};
    int ghost_score{200};
    bool game_over{};
    bool ready_banner{};
    bool ghost_mode_started{};
    std::uint32_t rng_state{};
    std::array<std::uint8_t, 28 * 31> collision{};
    Player player;
    std::array<Ghost, 4> ghosts;

    static GameState initial(const Assets& assets);
    void request(Direction direction);
    void step();
    void step_player();
    void step_ghosts();
    std::string json() const;

private:
    bool passable(int cell_x, int cell_y) const;
    std::uint32_t bounded_random(std::uint32_t range);
    void add_score(std::uint32_t points);
    void advance_ghost_mode();
    void consume_player_cell();
    bool resolve_collisions();
    void reset_actors();
    void step_ghost(Ghost& ghost);
    void tick_ghost_mode();
};

Direction parse_direction(const std::string& value);

}  // namespace pakupaku
