#include "pakupaku/assets.hpp"

#include "pakupaku/sha256.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>

namespace pakupaku {
namespace {

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw std::runtime_error("missing required asset: " + path.string());
    }
    return {std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>()};
}

std::vector<std::uint8_t>
read_verified(const std::filesystem::path& directory, const AssetFile& expected) {
    const auto path = directory / expected.name;
    auto bytes = read_file(path);
    if (bytes.size() != expected.size) {
        throw std::runtime_error(path.string() + ": size mismatch");
    }
    if (sha256_hex(bytes) != expected.sha256) {
        throw std::runtime_error(path.string() + ": SHA-256 mismatch");
    }
    return bytes;
}

}  // namespace

std::array<std::uint8_t, 28 * 31>
decode_map(const std::vector<std::uint8_t>& encoded) {
    std::array<std::uint8_t, 28 * 31> decoded{};
    std::size_t input = 0;
    std::size_t output = 0;
    while (input < encoded.size()) {
        const auto control = encoded[input++];
        if ((control & 0x80U) == 0) {
            if (output == decoded.size()) {
                throw std::runtime_error("MAP.DAT expands beyond 28x31 cells");
            }
            decoded[output++] = control;
            continue;
        }
        if (input == encoded.size()) {
            throw std::runtime_error("MAP.DAT ends inside a run");
        }
        const auto count = static_cast<std::size_t>(control & 0x7FU);
        const auto value = encoded[input++];
        if (count > decoded.size() - output) {
            throw std::runtime_error("MAP.DAT run expands beyond 28x31 cells");
        }
        for (std::size_t index = 0; index < count; ++index) {
            decoded[output++] = value;
        }
    }
    if (output != decoded.size()) {
        throw std::runtime_error("MAP.DAT does not expand to 28x31 cells");
    }
    return decoded;
}

Assets Assets::load_verified(const std::filesystem::path& directory) {
    Assets result;
    result.fonts = read_verified(directory, required_asset_files[0]);
    result.map = read_verified(directory, required_asset_files[1]);
    result.map_tiles = read_verified(directory, required_asset_files[2]);
    result.sprites = read_verified(directory, required_asset_files[3]);
    result.map_cells = decode_map(result.map);
    return result;
}

}  // namespace pakupaku
