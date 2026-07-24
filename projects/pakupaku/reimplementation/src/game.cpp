#include "pakupaku/game.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace pakupaku {
namespace {

int direction_value(Direction direction) {
    return static_cast<int>(direction);
}

struct GhostModeEntry {
    int mode;
    int ticks;
};

constexpr std::array<GhostModeEntry, 8> level_one_modes{{
    {0, 420}, {1, 1200}, {0, 420}, {1, 1200},
    {0, 300}, {1, 1200}, {0, 300}, {1, 1},
}};

constexpr std::array<GhostModeEntry, 8> level_two_to_four_modes{{
    {0, 420}, {1, 1200}, {0, 420}, {1, 1200},
    {0, 300}, {1, 65535}, {0, 1}, {1, 1},
}};

constexpr std::array<GhostModeEntry, 8> later_level_modes{{
    {0, 300}, {1, 1200}, {0, 300}, {1, 1200},
    {0, 300}, {1, 65535}, {0, 1}, {1, 1},
}};

const std::array<GhostModeEntry, 8>& mode_table(int level) {
    if (level == 1) {
        return level_one_modes;
    }
    if (level >= 2 && level <= 4) {
        return level_two_to_four_modes;
    }
    return later_level_modes;
}

}  // namespace

GameState GameState::initial(const Assets& assets) {
    GameState state;
    for (std::size_t index = 0; index < state.collision.size(); ++index) {
        const auto tile = assets.map_cells[index];
        state.collision[index] =
            tile == 32 || tile == 33 || tile == 40 ? tile : 0;
    }
    state.player = {
        {40, 68, 76, 40, 68}, Direction::left, Direction::left, 0};
    state.ghosts = {{
        {{40, 32, 6, 40, 32}, Direction::left, 0, 0, 0, 0, 0, 78, 1, false},
        {{41, 39, 8, 41, 39}, Direction::up, 8, 1, 0, 0, 0, 1, 1, false},
        {{34, 39, 20, 34, 39}, Direction::down, 16, 2, 0, 0, 30, 78, 85, false},
        {{47, 39, 24, 47, 39}, Direction::up, 24, 3, 0, 0, 60, 1, 85, false},
    }};
    return state;
}

void GameState::request(Direction direction) {
    player.requested_direction = direction;
}

bool GameState::passable(int cell_x, int cell_y) const {
    return cell_x >= 0 && cell_x < 28 && cell_y >= 0 && cell_y < 31 &&
           collision[static_cast<std::size_t>(cell_y * 28 + cell_x)] != 0;
}

void GameState::consume_player_cell() {
    const int cell_x = (player.actor.x + 1) / 3;
    const int cell_y = (player.actor.y + 1) / 3;
    if (cell_x < 0 || cell_x >= 28 || cell_y < 0 || cell_y >= 31) {
        return;
    }
    auto& cell = collision[static_cast<std::size_t>(cell_y * 28 + cell_x)];
    if (cell != 32 && cell != 33) {
        return;
    }
    const bool power_pellet = cell == 33;
    cell = 40;
    add_score(10);
    --pellets_remaining;
    for (auto& ghost : ghosts) {
        if (ghost.in_pen && ghost.release_ticks > 0) {
            --ghost.release_ticks;
            break;
        }
    }
    if (power_pellet) {
        frightened_ticks = 200;
        for (auto& ghost : ghosts) {
            if (!ghost.in_pen && ghost.mode != 3) {
                ghost.mode = 2;
                ghost.direction = static_cast<Direction>(
                    (direction_value(ghost.direction) + 2) & 3);
                ghost.mode_ticks = frightened_ticks;
            }
        }
    }
}

void GameState::add_score(std::uint32_t points) {
    const std::uint32_t old_score = score;
    score += points;
    high_score = std::max(score, high_score);
    if (old_score / 10000U < score / 10000U && lives < 5) {
        ++lives;
    }
}

std::uint32_t GameState::bounded_random(std::uint32_t range) {
    rng_state = rng_state * 0x08088405U + 1U;
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(rng_state) * range) >> 32U);
}

void GameState::step() {
    if (game_over) {
        return;
    }
    ready_banner = false;
    if (!ghost_mode_started) {
        ghost_mode_started = true;
        advance_ghost_mode();
    }
    step_player();
    step_ghosts();
    if (!resolve_collisions()) {
        tick_ghost_mode();
    }
}

void GameState::step_ghosts() {
    for (auto& ghost : ghosts) {
        step_ghost(ghost);
    }
}

void GameState::advance_ghost_mode() {
    const auto& table = mode_table(level);
    const auto& entry = table[static_cast<std::size_t>(ghost_mode_phase)];
    ghost_mode = entry.mode;
    ghost_mode_ticks = entry.ticks;
    for (auto& ghost : ghosts) {
        if (!ghost.in_pen && ghost.mode != 2 && ghost.mode != 3) {
            ghost.mode = ghost_mode;
        }
    }
    if (ghost_mode_phase < 7) {
        ++ghost_mode_phase;
    }
}

void GameState::tick_ghost_mode() {
    for (int tick = 0; tick < update_divisor / 2; ++tick) {
        if (ghost_mode_ticks > 0) {
            --ghost_mode_ticks;
            if (ghost_mode_ticks == 0) {
                advance_ghost_mode();
            }
        }
    }
}

bool GameState::resolve_collisions() {
    for (auto& ghost : ghosts) {
        if (std::abs(ghost.actor.x - player.actor.x) >= 2 ||
            std::abs(ghost.actor.y - player.actor.y) >= 2) {
            continue;
        }
        if (ghost.mode == 2) {
            add_score(static_cast<std::uint32_t>(ghost_score));
            ghost_score <<= 1;
            ghost.mode = 3;
        } else if (ghost.mode == 0 || ghost.mode == 1) {
            --lives;
            if (lives == 0) {
                game_over = true;
            } else {
                reset_actors();
                ghost_mode_ticks = 240;
                ready_banner = true;
            }
            return true;
        }
    }
    return false;
}

void GameState::reset_actors() {
    std::array<bool, 4> in_pen{};
    std::array<int, 4> mode_ticks{};
    for (std::size_t index = 0; index < ghosts.size(); ++index) {
        in_pen[index] = ghosts[index].in_pen;
        mode_ticks[index] = ghosts[index].mode_ticks;
    }

    player = {{40, 68, 76, 40, 68},
              Direction::left,
              Direction::left,
              0};
    ghosts = {{
        {{40, 32, 6, 40, 32}, Direction::left, 0, 0, 0, 0, 0, 78, 1, false},
        {{41, 39, 8, 41, 39}, Direction::up, 8, 1, 0, 0, 0, 1, 1, false},
        {{34, 39, 20, 34, 39}, Direction::down, 16, 2, 0, 0, 30, 78, 85, false},
        {{47, 39, 24, 47, 39}, Direction::up, 24, 3, 0, 0, 60, 1, 85, false},
    }};
    for (std::size_t index = 0; index < ghosts.size(); ++index) {
        ghosts[index].in_pen = in_pen[index];
        ghosts[index].mode_ticks = mode_ticks[index];
    }
}

void GameState::step_ghost(Ghost& ghost) {
    const int random = static_cast<int>(bounded_random(10));
    ghost.animation_toggle = !ghost.animation_toggle;

    auto& actor = ghost.actor;
    actor.previous_x = actor.x;
    actor.previous_y = actor.y;

    int x_mod = actor.x % 3;
    int y_mod = (actor.y + 1) % 3;
    int cell_x = (actor.x + 1) / 3;
    int cell_y = (actor.y + 1) / 3;
    ghost.in_pen = actor.x >= 33 && actor.x <= 52 &&
                   actor.y >= 38 && actor.y <= 44;

    if (ghost.in_pen) {
        if (ghost.mode == 3 && actor.y < 44) {
            ++actor.y;
            if (actor.y == 44) {
                ghost.mode = 0;
            }
        } else {
            if (ghost.release_ticks < 1) {
                if (actor.x >= 33 && actor.x <= 39) {
                    ghost.direction = Direction::right;
                } else if (actor.x >= 41 && actor.x <= 52) {
                    ghost.direction = Direction::left;
                } else if (actor.x == 40) {
                    ghost.direction = Direction::up;
                }
            } else if (actor.y == 38) {
                ghost.direction = Direction::down;
                ++actor.x;
            } else if (actor.y == 44) {
                ghost.direction = Direction::up;
                --actor.x;
            }

            switch (ghost.direction) {
                case Direction::up:
                    --actor.y;
                    break;
                case Direction::right:
                    ++actor.x;
                    break;
                case Direction::down:
                    ++actor.y;
                    break;
                case Direction::left:
                    --actor.x;
                    break;
            }
        }
    } else {
        if (ghost.direction == Direction::left && actor.x == 0 &&
            actor.y == 41) {
            actor.x = 81;
            actor.previous_x = actor.x;
        } else if (ghost.direction == Direction::right && actor.x == 81 &&
                   actor.y == 41) {
            actor.x = 0;
            actor.previous_x = actor.x;
        }

        int target_x = ghost.target_x;
        int target_y = ghost.target_y;
        int speed = 1;
        if (ghost.mode == 1) {
            target_x = player.actor.x;
            target_y = player.actor.y;
            if (ghost.personality == 1) {
                switch (player.direction) {
                    case Direction::up:
                        target_x -= 12;
                        target_y -= 12;
                        break;
                    case Direction::right:
                        target_x += 12;
                        break;
                    case Direction::down:
                        target_y += 12;
                        break;
                    case Direction::left:
                        target_x -= 12;
                        break;
                }
            } else if (ghost.personality == 2) {
                int projected_x = player.actor.x;
                int projected_y = player.actor.y;
                switch (player.direction) {
                    case Direction::up:
                        projected_x -= 6;
                        projected_y -= 6;
                        break;
                    case Direction::right:
                        projected_x += 6;
                        break;
                    case Direction::down:
                        projected_y += 6;
                        break;
                    case Direction::left:
                        projected_x -= 6;
                        break;
                }
                target_x = projected_x * 2 - ghosts[0].actor.x;
                target_y = projected_y * 2 - ghosts[0].actor.y;
            } else if (ghost.personality == 3 && random < 7) {
                target_x = ghost.target_x;
                target_y = ghost.target_y;
            }
        } else if (ghost.mode == 2) {
            target_x = actor.x - player.actor.x + actor.x;
            target_y = actor.y - player.actor.y + actor.y;
            ghost.mode_ticks -= update_divisor;
            if (ghost.mode_ticks < 1) {
                ghost.mode = ghost_mode;
            }
        } else if (ghost.mode == 3) {
            target_x = 40;
            target_y = 32;
            speed = 2;
            if ((actor.x == 40 || actor.x == 41) && actor.y > 30 &&
                actor.y < 44) {
                ghost.direction = Direction::down;
            }
        }

        x_mod = actor.x % 3;
        y_mod = (actor.y + 1) % 3;
        cell_x = (actor.x + 1) / 3;
        cell_y = (actor.y + 1) / 3;
        const int delta_x = target_x - actor.x;
        const int delta_y = target_y - actor.y;

        if (ghost.direction == Direction::up ||
            ghost.direction == Direction::down) {
            if (y_mod == 0) {
                const int forward_y =
                    ghost.direction == Direction::up ? cell_y - 1
                                                     : cell_y + 1;
                const bool forward_blocked = !passable(cell_x, forward_y);
                const bool special =
                    random >= 2 && (actor.x == 27 || actor.x == 54) &&
                    actor.y >= 27 && actor.y <= 55;
                if (std::abs(delta_y) < std::abs(delta_x) ||
                    forward_blocked || delta_y > 0 || special || random > 8) {
                    if (delta_x < 1) {
                        if (passable(cell_x - 1, cell_y)) {
                            ghost.direction = Direction::left;
                        } else if (passable(cell_x + 1, cell_y) &&
                                   (forward_blocked ||
                                    (special && actor.x == 27))) {
                            ghost.direction = Direction::right;
                        }
                    } else {
                        if (passable(cell_x + 1, cell_y)) {
                            ghost.direction = Direction::right;
                        } else if (passable(cell_x - 1, cell_y) &&
                                   (forward_blocked ||
                                    (special && actor.x == 54))) {
                            ghost.direction = Direction::left;
                        }
                    }
                }
            }
        } else if (x_mod == 0) {
            const int forward_x =
                ghost.direction == Direction::left ? cell_x - 1
                                                   : cell_x + 1;
            const bool forward_blocked = !passable(forward_x, cell_y);
            const bool allow_up =
                !(random >= 2 && actor.x >= 28 && actor.x <= 53 &&
                  (actor.y == 32 || actor.y == 68));
            if (std::abs(delta_x) < std::abs(delta_y) || forward_blocked ||
                delta_x > 0 || random > 8) {
                if (delta_y < 1) {
                    if (passable(cell_x, cell_y - 1) && allow_up) {
                        ghost.direction = Direction::up;
                    } else if (passable(cell_x, cell_y + 1) &&
                               forward_blocked) {
                        ghost.direction = Direction::down;
                    }
                } else {
                    if (passable(cell_x, cell_y + 1)) {
                        ghost.direction = Direction::down;
                    } else if (passable(cell_x, cell_y - 1) &&
                               forward_blocked && allow_up) {
                        ghost.direction = Direction::up;
                    }
                }
            }
        }

        const bool move =
            (ghost.mode != 2 &&
             (actor.y != 41 || (actor.x > 17 && actor.x < 63))) ||
            !ghost.animation_toggle;
        if (move) {
            switch (ghost.direction) {
                case Direction::up:
                    if (y_mod != 0 || passable(cell_x, cell_y - 1)) {
                        actor.y -= speed;
                    }
                    break;
                case Direction::right:
                    if (x_mod != 0 || passable(cell_x + 1, cell_y)) {
                        actor.x += speed;
                    }
                    break;
                case Direction::down:
                    if (y_mod != 0 || passable(cell_x, cell_y + 1)) {
                        actor.y += speed;
                    }
                    break;
                case Direction::left:
                    if (x_mod != 0 || passable(cell_x - 1, cell_y)) {
                        actor.x -= speed;
                    }
                    break;
            }
        }
    }

    int sprite_base = ghost.sprite_family;
    if (ghost.mode == 2) {
        sprite_base = 32;
    } else if (ghost.mode == 3) {
        sprite_base = 48;
    }
    actor.sprite =
        sprite_base + direction_value(ghost.direction) * 2 +
        ghost.animation / 4;
    ghost.animation = (ghost.animation + 1) & 7;
}

void GameState::step_player() {
    consume_player_cell();
    auto& actor = player.actor;
    actor.previous_x = actor.x;
    actor.previous_y = actor.y;

    const auto old_direction = player.direction;
    const int x_mod = actor.x % 3;
    const int y_mod = (actor.y + 1) % 3;
    const int cell_x = (actor.x + 1) / 3;
    const int cell_y = (actor.y + 1) / 3;

    if (player.direction == Direction::left && actor.x == 0 &&
        actor.y == 41) {
        actor.x = 81;
        actor.previous_x = actor.x;
    } else if (player.direction == Direction::right && actor.x == 81 &&
               actor.y == 41) {
        actor.x = 0;
        actor.previous_x = actor.x;
    }

    if (player.direction == Direction::up ||
        player.direction == Direction::down) {
        if (player.requested_direction == Direction::up ||
            player.requested_direction == Direction::down) {
            player.direction = player.requested_direction;
        } else if (y_mod == 0) {
            if (player.requested_direction == Direction::right &&
                passable(cell_x + 1, cell_y)) {
                player.direction = player.requested_direction;
            } else if (player.requested_direction == Direction::left &&
                       passable(cell_x - 1, cell_y)) {
                player.direction = player.requested_direction;
            }
        }
    } else {
        if (player.requested_direction == Direction::left ||
            player.requested_direction == Direction::right) {
            player.direction = player.requested_direction;
        } else if (x_mod == 0) {
            if (player.requested_direction == Direction::up &&
                passable(cell_x, cell_y - 1)) {
                player.direction = player.requested_direction;
            } else if (player.requested_direction == Direction::down &&
                       passable(cell_x, cell_y + 1)) {
                player.direction = player.requested_direction;
            }
        }
    }

    int distance = 1;
    if (player.direction != old_direction &&
        direction_value(player.direction) !=
            ((direction_value(old_direction) + 2) & 3)) {
        distance = 2;
    }
    bool blocked = false;
    switch (player.direction) {
        case Direction::up:
            if (y_mod == 0) {
                blocked = !passable(cell_x, cell_y - 1);
                if (!blocked) {
                    actor.y -= distance;
                }
            } else {
                --actor.y;
            }
            break;
        case Direction::right:
            if (x_mod == 0) {
                blocked = !passable(cell_x + 1, cell_y);
                if (!blocked) {
                    actor.x += distance;
                }
            } else {
                ++actor.x;
            }
            break;
        case Direction::down:
            if (y_mod == 0) {
                blocked = !passable(cell_x, cell_y + 1);
                if (!blocked) {
                    actor.y += distance;
                }
            } else {
                ++actor.y;
            }
            break;
        case Direction::left:
            if (x_mod == 0) {
                blocked = !passable(cell_x - 1, cell_y);
                if (!blocked) {
                    actor.x -= distance;
                }
            } else {
                --actor.x;
            }
            break;
    }
    if (blocked) {
        player.animation = 4;
    }
    actor.sprite =
        direction_value(player.direction) * 4 + 0x40 + player.animation / 2;
    player.animation = (player.animation + 1) & 7;
}

std::string GameState::json() const {
    std::ostringstream output;
    output << "{\n"
           << "  \"score\": " << score << ",\n"
           << "  \"high_score\": " << high_score << ",\n"
           << "  \"lives\": " << lives << ",\n"
           << "  \"level\": " << level << ",\n"
           << "  \"pellets_remaining\": " << pellets_remaining << ",\n"
           << "  \"ghost_score\": " << ghost_score << ",\n"
           << "  \"ghost_mode\": " << ghost_mode << ",\n"
           << "  \"ghost_mode_phase\": " << ghost_mode_phase << ",\n"
           << "  \"ghost_mode_ticks\": " << ghost_mode_ticks << ",\n"
           << "  \"game_over\": " << (game_over ? "true" : "false")
           << ",\n"
           << "  \"ready_banner\": "
           << (ready_banner ? "true" : "false") << ",\n"
           << "  \"rng_state\": " << rng_state << ",\n"
           << "  \"player_x\": " << player.actor.x << ",\n"
           << "  \"player_y\": " << player.actor.y << ",\n"
           << "  \"player_sprite\": " << player.actor.sprite << ",\n"
           << "  \"player_direction\": "
           << direction_value(player.direction) << ",\n"
           << "  \"player_requested_direction\": "
           << direction_value(player.requested_direction) << ",\n"
           << "  \"ghosts\": [\n";
    for (std::size_t index = 0; index < ghosts.size(); ++index) {
        const auto& ghost = ghosts[index];
        output << "    {\"x\": " << ghost.actor.x
               << ", \"y\": " << ghost.actor.y
               << ", \"sprite\": " << ghost.actor.sprite
               << ", \"direction\": " << direction_value(ghost.direction)
               << ", \"mode\": " << ghost.mode
               << ", \"mode_ticks\": " << ghost.mode_ticks
               << ", \"release_ticks\": " << ghost.release_ticks
               << ", \"in_pen\": "
               << (ghost.in_pen ? "true" : "false") << "}";
        if (index + 1 != ghosts.size()) {
            output << ',';
        }
        output << '\n';
    }
    output << "  ]\n"
           << "}\n";
    return output.str();
}

Direction parse_direction(const std::string& value) {
    if (value == "up") {
        return Direction::up;
    }
    if (value == "right") {
        return Direction::right;
    }
    if (value == "down") {
        return Direction::down;
    }
    if (value == "left") {
        return Direction::left;
    }
    throw std::runtime_error("direction must be up, right, down, or left");
}

}  // namespace pakupaku
