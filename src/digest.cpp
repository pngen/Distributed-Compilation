// Distributed Compilation - SHA-256, CRC-32 and hex primitives.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/digest.hpp"

#include <cstring>

namespace dc {
namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

inline std::uint32_t rotr(std::uint32_t value, unsigned bits) noexcept {
  return (value >> bits) | (value << (32u - bits));
}

inline std::uint32_t load_be32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

inline void store_be32(std::uint8_t* p, std::uint32_t value) noexcept {
  p[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  p[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  p[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  p[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

inline int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

Sha256::Sha256() : bit_count_(0), buffer_len_(0) {
  state_[0] = 0x6a09e667u;
  state_[1] = 0xbb67ae85u;
  state_[2] = 0x3c6ef372u;
  state_[3] = 0xa54ff53au;
  state_[4] = 0x510e527fu;
  state_[5] = 0x9b05688cu;
  state_[6] = 0x1f83d9abu;
  state_[7] = 0x5be0cd19u;
  std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const std::uint8_t* block) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) w[i] = load_be32(block + (i * 4));
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  bit_count_ += static_cast<std::uint64_t>(size) * 8u;
  std::size_t offset = 0;
  while (offset < size) {
    const std::size_t take = (size - offset) < (64 - buffer_len_) ? (size - offset) : (64 - buffer_len_);
    std::memcpy(buffer_ + buffer_len_, bytes + offset, take);
    buffer_len_ += take;
    offset += take;
    if (buffer_len_ == 64) {
      compress(buffer_);
      buffer_len_ = 0;
    }
  }
}

void Sha256::update(std::span<const std::byte> data) { update(data.data(), data.size()); }
void Sha256::update(std::string_view data) { update(data.data(), data.size()); }

Digest256 Sha256::finish() {
  const std::uint64_t bits = bit_count_;
  const std::uint8_t pad = 0x80;
  update(&pad, 1);
  const std::uint8_t zero = 0x00;
  while (buffer_len_ != 56) update(&zero, 1);
  std::uint8_t length_bytes[8];
  for (int i = 0; i < 8; ++i) {
    length_bytes[7 - i] = static_cast<std::uint8_t>((bits >> (i * 8)) & 0xFFu);
  }
  update(length_bytes, 8);

  Digest256 out;
  for (int i = 0; i < 8; ++i) store_be32(out.data() + (i * 4), state_[i]);
  return out;
}

Digest256 sha256(std::span<const std::byte> data) {
  Sha256 h;
  h.update(data);
  return h.finish();
}

Digest256 sha256(std::string_view data) {
  Sha256 h;
  h.update(data);
  return h.finish();
}

Digest256 sha256(const void* data, std::size_t size) {
  Sha256 h;
  h.update(data, size);
  return h.finish();
}

std::uint32_t crc32(const void* data, std::size_t size, std::uint32_t seed) {
  static std::uint32_t table[256];
  static bool initialised = false;
  if (!initialised) {
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
      table[i] = c;
    }
    initialised = true;
  }
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint32_t crc = seed ^ 0xFFFFFFFFu;
  for (std::size_t i = 0; i < size; ++i) {
    crc = table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFu;
}

std::string Digest256::hex() const {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.resize(kBytes * 2);
  for (std::size_t i = 0; i < kBytes; ++i) {
    out[i * 2] = digits[(bytes_[i] >> 4) & 0x0Fu];
    out[(i * 2) + 1] = digits[bytes_[i] & 0x0Fu];
  }
  return out;
}

bool Digest256::parse_hex(std::string_view text, Digest256& out) {
  if (text.size() != kBytes * 2) return false;
  Digest256 parsed;
  for (std::size_t i = 0; i < kBytes; ++i) {
    const int hi = hex_value(text[i * 2]);
    const int lo = hex_value(text[(i * 2) + 1]);
    if (hi < 0 || lo < 0) return false;
    parsed.bytes_[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  out = parsed;
  return true;
}

bool Digest256::is_zero() const noexcept {
  for (std::uint8_t byte : bytes_) {
    if (byte != 0) return false;
  }
  return true;
}

std::string to_hex(std::span<const std::byte> bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const auto value = static_cast<std::uint8_t>(bytes[i]);
    out[i * 2] = digits[(value >> 4) & 0x0Fu];
    out[(i * 2) + 1] = digits[value & 0x0Fu];
  }
  return out;
}

bool from_hex(std::string_view text, std::string& out_bytes) {
  if (text.size() % 2 != 0) return false;
  std::string parsed;
  parsed.resize(text.size() / 2);
  for (std::size_t i = 0; i < parsed.size(); ++i) {
    const int hi = hex_value(text[i * 2]);
    const int lo = hex_value(text[(i * 2) + 1]);
    if (hi < 0 || lo < 0) return false;
    parsed[i] = static_cast<char>((hi << 4) | lo);
  }
  out_bytes = std::move(parsed);
  return true;
}

}  // namespace dc
