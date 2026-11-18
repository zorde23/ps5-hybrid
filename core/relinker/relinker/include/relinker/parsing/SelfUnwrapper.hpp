#ifndef RELINKER_PARSING_SELFUNWRAPPER_HPP
#define RELINKER_PARSING_SELFUNWRAPPER_HPP

#include <cstdint>
#include <vector>

namespace Relinker {

inline constexpr std::uint64_t SelfMaxAlignmentPadding = 64ull * 1024 * 1024;

bool IsSelfContainer(const std::vector<std::uint8_t>& bytes);

std::vector<std::uint8_t> UnwrapSelf(const std::vector<std::uint8_t>& container, std::uint64_t maxAlignmentPadding = SelfMaxAlignmentPadding);

}

#endif
