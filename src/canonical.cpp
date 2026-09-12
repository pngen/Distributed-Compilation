// Distributed Compilation - canonical encoding implementation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/canonical.hpp"

#include <cstring>
#include <stdexcept>

namespace dc {
namespace {

inline void put_u8(std::vector<std::byte>& out, std::uint8_t value) {
  out.push_back(static_cast<std::byte>(value));
}

}  // namespace

void CanonicalWriter::require(std::size_t additional) const {
  // The writer is used on trusted, already-validated data, so an overflow here
  // is a programming error rather than a peer-driven condition; it is still
  // bounded so that a bug cannot exhaust memory silently.
  if (buffer_.size() + additional > limits_.max_total_bytes) {
    throw std::length_error("canonical record exceeds configured limit");
  }
}

void CanonicalWriter::domain(std::string_view tag) {
  if (tag.size() > limits_.max_domain_tag || tag.size() > 255) {
    throw std::length_error("canonical domain tag too long");
  }
  require(tag.size() + 1);
  put_u8(buffer_, static_cast<std::uint8_t>(tag.size()));
  for (char c : tag) put_u8(buffer_, static_cast<std::uint8_t>(static_cast<unsigned char>(c)));
}

void CanonicalWriter::u8(std::uint8_t value) {
  require(1);
  put_u8(buffer_, value);
}

void CanonicalWriter::boolean(bool value) {
  require(1);
  put_u8(buffer_, value ? 1u : 0u);
}

void CanonicalWriter::u16(std::uint16_t value) {
  require(2);
  put_u8(buffer_, static_cast<std::uint8_t>(value & 0xFFu));
  put_u8(buffer_, static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void CanonicalWriter::u32(std::uint32_t value) {
  require(4);
  for (int i = 0; i < 4; ++i) put_u8(buffer_, static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
}

void CanonicalWriter::u64(std::uint64_t value) {
  require(8);
  for (int i = 0; i < 8; ++i) put_u8(buffer_, static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
}

void CanonicalWriter::i64(std::int64_t value) { u64(static_cast<std::uint64_t>(value)); }

void CanonicalWriter::f64(double value) {
  std::uint64_t bits = 0;
  static_assert(sizeof(double) == sizeof(std::uint64_t), "unexpected double size");
  std::memcpy(&bits, &value, sizeof(bits));
  u64(bits);
}

void CanonicalWriter::str(std::string_view value) {
  if (value.size() > limits_.max_string_bytes) {
    throw std::length_error("canonical string exceeds configured limit");
  }
  require(value.size() + 4);
  u32(static_cast<std::uint32_t>(value.size()));
  for (char c : value) put_u8(buffer_, static_cast<std::uint8_t>(static_cast<unsigned char>(c)));
}

void CanonicalWriter::blob(std::span<const std::byte> value) {
  if (value.size() > limits_.max_blob_bytes) {
    throw std::length_error("canonical blob exceeds configured limit");
  }
  require(value.size() + 4);
  u32(static_cast<std::uint32_t>(value.size()));
  buffer_.insert(buffer_.end(), value.begin(), value.end());
}

void CanonicalWriter::digest(const Digest256& value) {
  require(Digest256::kBytes);
  const auto* raw = value.data();
  for (std::size_t i = 0; i < Digest256::kBytes; ++i) put_u8(buffer_, raw[i]);
}

void CanonicalWriter::list(std::uint32_t count) {
  if (count > limits_.max_items) {
    throw std::length_error("canonical collection exceeds configured limit");
  }
  u32(count);
}

void CanonicalWriter::present(bool has_value) { boolean(has_value); }

Digest256 CanonicalWriter::hash() const { return sha256(span()); }

// ---------------------------------------------------------------------------
// CanonicalReader
// ---------------------------------------------------------------------------

Status CanonicalReader::fail(ErrorCode code, std::string detail) {
  if (status_.ok()) status_ = Status::error(code, std::move(detail));
  return status_;
}

bool CanonicalReader::need(std::size_t count) {
  if (!status_.ok()) return false;
  if (count > remaining()) {
    fail(ErrorCode::Malformed, "canonical record truncated");
    return false;
  }
  return true;
}

bool CanonicalReader::read_u8(std::uint8_t& out) {
  if (!need(1)) return false;
  out = static_cast<std::uint8_t>(data_[pos_]);
  ++pos_;
  return true;
}

bool CanonicalReader::read_bool(bool& out) {
  std::uint8_t raw = 0;
  if (!read_u8(raw)) return false;
  if (raw > 1) {
    fail(ErrorCode::Malformed, "canonical boolean out of domain");
    return false;
  }
  out = raw == 1;
  return true;
}

bool CanonicalReader::read_u16(std::uint16_t& out) {
  if (!need(2)) return false;
  std::uint16_t value = 0;
  for (int i = 0; i < 2; ++i) {
    value = static_cast<std::uint16_t>(value | (static_cast<std::uint16_t>(static_cast<std::uint8_t>(data_[pos_ + i])) << (i * 8)));
  }
  pos_ += 2;
  out = value;
  return true;
}

bool CanonicalReader::read_u32(std::uint32_t& out) {
  if (!need(4)) return false;
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(data_[pos_ + i])) << (i * 8);
  }
  pos_ += 4;
  out = value;
  return true;
}

bool CanonicalReader::read_u64(std::uint64_t& out) {
  if (!need(8)) return false;
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(data_[pos_ + i])) << (i * 8);
  }
  pos_ += 8;
  out = value;
  return true;
}

bool CanonicalReader::read_i64(std::int64_t& out) {
  std::uint64_t raw = 0;
  if (!read_u64(raw)) return false;
  out = static_cast<std::int64_t>(raw);
  return true;
}

bool CanonicalReader::read_f64(double& out) {
  std::uint64_t bits = 0;
  if (!read_u64(bits)) return false;
  std::memcpy(&out, &bits, sizeof(out));
  return true;
}

bool CanonicalReader::read_str(std::string& out) {
  std::uint32_t length = 0;
  if (!read_u32(length)) return false;
  if (length > limits_.max_string_bytes) {
    fail(ErrorCode::LimitExceeded, "canonical string exceeds configured limit");
    return false;
  }
  if (!need(length)) return false;
  out.assign(reinterpret_cast<const char*>(data_.data() + pos_), length);
  pos_ += length;
  return true;
}

bool CanonicalReader::read_blob(std::vector<std::byte>& out) {
  std::uint32_t length = 0;
  if (!read_u32(length)) return false;
  if (length > limits_.max_blob_bytes) {
    fail(ErrorCode::LimitExceeded, "canonical blob exceeds configured limit");
    return false;
  }
  if (!need(length)) return false;
  out.assign(data_.begin() + static_cast<std::ptrdiff_t>(pos_),
             data_.begin() + static_cast<std::ptrdiff_t>(pos_ + length));
  pos_ += length;
  return true;
}

bool CanonicalReader::read_digest(Digest256& out) {
  if (!need(Digest256::kBytes)) return false;
  std::memcpy(out.data(), data_.data() + pos_, Digest256::kBytes);
  pos_ += Digest256::kBytes;
  return true;
}

bool CanonicalReader::read_list(std::uint32_t& count) {
  if (!read_u32(count)) return false;
  if (count > limits_.max_items) {
    fail(ErrorCode::LimitExceeded, "canonical collection exceeds configured limit");
    return false;
  }
  return true;
}

bool CanonicalReader::read_present(bool& has_value) { return read_bool(has_value); }

bool CanonicalReader::read_domain(std::string_view expected) {
  std::uint8_t length = 0;
  if (!read_u8(length)) return false;
  if (length > limits_.max_domain_tag) {
    fail(ErrorCode::Malformed, "canonical domain tag too long");
    return false;
  }
  if (!need(length)) return false;
  const std::string_view actual(reinterpret_cast<const char*>(data_.data() + pos_), length);
  pos_ += length;
  if (actual != expected) {
    fail(ErrorCode::Malformed, "canonical domain mismatch");
    return false;
  }
  return true;
}

bool CanonicalReader::skip(std::size_t count) {
  if (!need(count)) return false;
  pos_ += count;
  return true;
}

// ---------------------------------------------------------------------------
// Typed handle overloads. Decoding rejects the zero handle: absence is never a
// valid peer-supplied identity.
// ---------------------------------------------------------------------------
namespace {

template <class IdT>
bool read_handle(CanonicalReader& r, IdT& out) {
  std::uint64_t raw = 0;
  if (!r.read_u64(raw)) return false;
  if (!IdT::decode(raw, out)) {
    r.fail(ErrorCode::Malformed, "canonical identity handle is zero");
    return false;
  }
  return true;
}

template <class GenT>
bool read_generation(CanonicalReader& r, GenT& out) {
  std::uint64_t raw = 0;
  if (!r.read_u64(raw)) return false;
  out = GenT(raw);
  return true;
}

}  // namespace

#define DC_READ_ID(Name)                                        \
  bool CanonicalReader::read_id(Name& out) { return read_handle(*this, out); }

#define DC_READ_GEN(Name)                                              \
  bool CanonicalReader::read_gen(Name& out) { return read_generation(*this, out); }

DC_READ_ID(CompilationId)
DC_READ_ID(RequestId)
DC_READ_ID(WorkerId)
DC_READ_ID(WorkerBootId)
DC_READ_ID(SessionId)
DC_READ_ID(LeaseId)
DC_READ_ID(SourceId)
DC_READ_ID(IRId)
DC_READ_ID(DependencySetId)
DC_READ_ID(ToolchainId)
DC_READ_ID(TargetId)
DC_READ_ID(SpecializationId)
DC_READ_ID(CompilePolicyId)
DC_READ_ID(CacheEntryId)
DC_READ_ID(ArtifactId)
DC_READ_ID(ArtifactCommitId)
DC_READ_ID(EvidenceId)
DC_READ_ID(ProvenanceId)
DC_READ_ID(CompilationAttemptId)
DC_READ_ID(CompilationUnitId)
DC_READ_ID(IntermediateId)
DC_READ_ID(ValidationId)

DC_READ_GEN(CompilationGeneration)
DC_READ_GEN(CompilationAttemptGeneration)
DC_READ_GEN(CoordinatorEpoch)
DC_READ_GEN(WorkerGeneration)
DC_READ_GEN(LeaseGeneration)
DC_READ_GEN(SourceGeneration)
DC_READ_GEN(IRGeneration)
DC_READ_GEN(DependencyGeneration)
DC_READ_GEN(ToolchainGeneration)
DC_READ_GEN(TargetGeneration)
DC_READ_GEN(SpecializationGeneration)
DC_READ_GEN(CompilePolicyGeneration)
DC_READ_GEN(CacheGeneration)
DC_READ_GEN(ArtifactGeneration)
DC_READ_GEN(ArtifactCommitGeneration)
DC_READ_GEN(EvidenceGeneration)
DC_READ_GEN(ProvenanceGeneration)
DC_READ_GEN(IntermediateGeneration)
DC_READ_GEN(UnitGeneration)
DC_READ_GEN(RequestGeneration)

#undef DC_READ_ID
#undef DC_READ_GEN

void write_string_list(CanonicalWriter& w, const std::vector<std::string>& items) {
  w.list(static_cast<std::uint32_t>(items.size()));
  for (const auto& item : items) w.str(item);
}

bool read_string_list(CanonicalReader& r, std::vector<std::string>& out) {
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  out.clear();
  out.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    std::string item;
    if (!r.read_str(item)) return false;
    out.push_back(std::move(item));
  }
  return true;
}

}  // namespace dc
