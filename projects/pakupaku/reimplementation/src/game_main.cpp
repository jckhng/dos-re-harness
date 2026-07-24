#include "pakupaku/assets.hpp"
#include "pakupaku/game.hpp"
#include "pakupaku/presenter.hpp"
#include "pakupaku/renderer.hpp"
#include "pakupaku/sha256.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct Arguments {
    std::filesystem::path data;
    std::filesystem::path raw;
    std::filesystem::path ppm;
    std::filesystem::path state_json;
    std::string scene{"map"};
    std::string direction{"left"};
    int steps{};
};

Arguments parse_arguments(int argc, char** argv) {
    Arguments result;
    for (int index = 1; index < argc; ++index) {
        const std::string option = argv[index];
        if (index + 1 >= argc) {
            throw std::runtime_error("missing value after " + option);
        }
        const std::string value = argv[++index];
        if (option == "--data") {
            result.data = value;
        } else if (option == "--raw") {
            result.raw = value;
        } else if (option == "--ppm") {
            result.ppm = value;
        } else if (option == "--state-json") {
            result.state_json = value;
        } else if (option == "--scene") {
            result.scene = value;
        } else if (option == "--direction") {
            result.direction = value;
        } else if (option == "--steps") {
            result.steps = std::stoi(value);
        } else {
            throw std::runtime_error("unknown option: " + option);
        }
    }
    if (result.data.empty() || result.raw.empty() || result.ppm.empty()) {
        throw std::runtime_error(
            "usage: pakupaku --data DIR --raw FRAME.bin --ppm FRAME.ppm "
            "[--scene map|ready|game] [--steps N] "
            "[--direction up|right|down|left] [--state-json STATE.json]");
    }
    if (result.steps < 0) {
        throw std::runtime_error("steps must not be negative");
    }
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto arguments = parse_arguments(argc, argv);
        auto assets = pakupaku::Assets::load_verified(arguments.data);
        auto state = pakupaku::GameState::initial(assets);
        pakupaku::Renderer renderer;

        if (arguments.scene == "map") {
            pakupaku::render_map_frame(renderer, assets);
        } else if (arguments.scene == "ready" ||
                   arguments.scene == "game") {
            if (arguments.scene == "game") {
                state.request(pakupaku::parse_direction(arguments.direction));
                for (int step = 0; step < arguments.steps; ++step) {
                    state.step();
                }
            }
            pakupaku::render_game_frame(
                renderer, assets, state, arguments.scene == "ready");
        } else {
            throw std::runtime_error("scene must be map, ready, or game");
        }

        renderer.write_raw(arguments.raw);
        renderer.write_ppm(arguments.ppm);
        if (!arguments.state_json.empty()) {
            std::ofstream stream(arguments.state_json);
            if (!stream) {
                throw std::runtime_error(
                    "cannot create " + arguments.state_json.string());
            }
            stream << state.json();
        }
        const std::vector<std::uint8_t> bytes(
            renderer.raw().begin(), renderer.raw().end());
        std::cout << state.json()
                  << "raw_sha256=" << pakupaku::sha256_hex(bytes) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "pakupaku: " << error.what() << '\n';
        return 1;
    }
}
