// Distributed Compilation - SHA-256 and CRC-32 content integrity primitives.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_DIGEST_HPP
#define DC_DIGEST_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace dc {

// 256-bit content digest. Rendered as lowercase hex (64 characters).
class Digest256 {
 public:
  static constexpr std::size_t kBytes = 32;

  Digest256() = default;

  const std::uint8_t* data() const noexcept { return bytes_.data(); }
  std::uint8_t* data() noexcept { return bytes_.data(); }
  std::array<std::uint8_t, kBytes>& raw() noexcept { return bytes_; }
  const std::array<std::uint8_t, kBytes>& raw() const noexcept { return bytes_; }

  std::string hex() const;
  static bool parse_hex(std::string_view text, Digest256& out);

  // The all-zero digest is the "absent" sentinel. A digest that claims to be a
  // real content identity must never be all zero.
  bool is_zero() const noexcept;

  friend bool operator==(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ == b.bytes_;
  }
  friend bool operator!=(const Digest256& a, const Digest256& b) noexcept {
    return !(a.bytes_ == b.bytes_);
  }
  friend bool operator<(const Digest256& a, const Digest256& b) noexcept {
    return a.bytes_ < b.bytes_;
  }

 private:
  std::array<std::uint8_t, kBytes> bytes_{};
};

// Streaming SHA-256. Deterministic, portable, no external dependency.
class Sha256 {
 public:
  Sha256();

  void update(std::span<const std::byte> data);
  void update(std::string_view data);
  void update(const void* data, std::size_t size);
  Digest256 finish();

 private:
  void compress(const std::uint8_t* block);

  std::uint32_t state_[8];
  std::uint64_t bit_count_;
  std::uint8_t buffer_[64];
  std::size_t buffer_len_;
};

Digest256 sha256(std::span<const std::byte> data);
Digest256 sha256(std::string_view data);
Digest256 sha256(const void* data, std::size_t size);

std::uint32_t crc32(const void* data, std::size_t size, std::uint32_t seed = 0);

// Hex helpers used by persistence and the CLI.
std::string to_hex(std::span<const std::byte> bytes);
bool from_hex(std::string_view text, std::string& out_bytes);

}  // namespace dc

#endif  // DC_DIGEST_HPP
