#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pakupaku {

std::string sha256_hex(const std::vector<std::uint8_t>& data);

}  // namespace pakupaku
