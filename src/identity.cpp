// Distributed Compilation - identity mixing primitives.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/identity.hpp"

#include <cstddef>

namespace dc {

std::uint64_t mix64(std::uint64_t value) noexcept {
  value ^= value >> 33;
  value *= 0xFF51AFD7ED558CCDULL;
  value ^= value >> 33;
  value *= 0xC4CEB9FE1A85EC53ULL;
  value ^= value >> 33;
  return value;
}

std::uint64_t fnv1a64(const void* data, std::size_t size, std::uint64_t seed) noexcept {
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::uint64_t hash = seed;
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= static_cast<std::uint64_t>(bytes[i]);
    hash *= 1099511628211ULL;
  }
  return hash;
}

}  // namespace dc
