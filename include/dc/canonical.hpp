// Distributed Compilation - canonical byte encoding used for all identity derivation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_CANONICAL_HPP
#define DC_CANONICAL_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "dc/digest.hpp"
#include "dc/identity.hpp"
#include "dc/types.hpp"

namespace dc {

// Hard bounds applied to every canonical record. These exist so that a hostile
// or corrupt peer cannot drive unbounded allocation through identity encoding.
struct CanonicalLimits {
  std::size_t max_string_bytes = 1u << 20;      // 1 MiB per string field
  std::size_t max_blob_bytes = 64u << 20;       // 64 MiB per blob field
  std::size_t max_items = 262144;               // list/collection element cap
  std::size_t max_total_bytes = 256u << 20;     // total encoded record cap
  std::size_t max_domain_tag = 64;              // domain separator length cap
};

// CanonicalWriter produces a deterministic, self-delimiting byte string.
//
// Rules that make identity derivation sound:
//   * every field is length-prefixed or fixed width, so concatenation is
//     unambiguous and cannot be made to collide by moving a delimiter;
//   * every logical record starts with a domain tag, so a Source record can
//     never hash equal to a Target record with identical payload bytes;
//   * integers are little-endian fixed width, floating point is encoded by bit
//     pattern, booleans are a single 0/1 byte;
//   * no container iteration order ever leaks in: callers must sort before
//     writing, and the writer counts elements explicitly.
class CanonicalWriter {
 public:
  explicit CanonicalWriter(const CanonicalLimits& limits = {}) : limits_(limits) {}

  void domain(std::string_view tag);

  void u8(std::uint8_t value);
  void boolean(bool value);
  void u16(std::uint16_t value);
  void u32(std::uint32_t value);
  void u64(std::uint64_t value);
  void i64(std::int64_t value);
  void f64(double value);

  void str(std::string_view value);
  void blob(std::span<const std::byte> value);
  void digest(const Digest256& value);

  // Writes an element count. Callers must bound the count themselves; the
  // writer rejects counts beyond CanonicalLimits::max_items.
  void list(std::uint32_t count);
  void present(bool has_value);

  template <class T, class Fn>
  void list_of(const std::vector<T>& items, Fn&& write_item) {
    list(static_cast<std::uint32_t>(items.size()));
    for (const auto& item : items) write_item(*this, item);
  }

  void id(CompilationId value) { u64(value.value()); }
  void id(RequestId value) { u64(value.value()); }
  void id(WorkerId value) { u64(value.value()); }
  void id(WorkerBootId value) { u64(value.value()); }
  void id(SessionId value) { u64(value.value()); }
  void id(LeaseId value) { u64(value.value()); }
  void id(SourceId value) { u64(value.value()); }
  void id(IRId value) { u64(value.value()); }
  void id(DependencySetId value) { u64(value.value()); }
  void id(ToolchainId value) { u64(value.value()); }
  void id(TargetId value) { u64(value.value()); }
  void id(SpecializationId value) { u64(value.value()); }
  void id(CompilePolicyId value) { u64(value.value()); }
  void id(CacheEntryId value) { u64(value.value()); }
  void id(ArtifactId value) { u64(value.value()); }
  void id(ArtifactCommitId value) { u64(value.value()); }
  void id(EvidenceId value) { u64(value.value()); }
  void id(ProvenanceId value) { u64(value.value()); }
  void id(CompilationAttemptId value) { u64(value.value()); }
  void id(CompilationUnitId value) { u64(value.value()); }
  void id(IntermediateId value) { u64(value.value()); }
  void id(ValidationId value) { u64(value.value()); }
  void gen(RequestGeneration value) { u64(value.value()); }

  void gen(CompilationGeneration value) { u64(value.value()); }
  void gen(CompilationAttemptGeneration value) { u64(value.value()); }
  void gen(CoordinatorEpoch value) { u64(value.value()); }
  void gen(WorkerGeneration value) { u64(value.value()); }
  void gen(LeaseGeneration value) { u64(value.value()); }
  void gen(SourceGeneration value) { u64(value.value()); }
  void gen(IRGeneration value) { u64(value.value()); }
  void gen(DependencyGeneration value) { u64(value.value()); }
  void gen(ToolchainGeneration value) { u64(value.value()); }
  void gen(TargetGeneration value) { u64(value.value()); }
  void gen(SpecializationGeneration value) { u64(value.value()); }
  void gen(CompilePolicyGeneration value) { u64(value.value()); }
  void gen(CacheGeneration value) { u64(value.value()); }
  void gen(ArtifactGeneration value) { u64(value.value()); }
  void gen(ArtifactCommitGeneration value) { u64(value.value()); }
  void gen(EvidenceGeneration value) { u64(value.value()); }
  void gen(ProvenanceGeneration value) { u64(value.value()); }
  void gen(IntermediateGeneration value) { u64(value.value()); }
  void gen(UnitGeneration value) { u64(value.value()); }

  std::size_t size() const noexcept { return buffer_.size(); }
  const std::vector<std::byte>& bytes() const noexcept { return buffer_; }
  std::span<const std::byte> span() const noexcept {
    return std::span<const std::byte>(buffer_.data(), buffer_.size());
  }

  // SHA-256 over the canonical byte string. This is the only sanctioned way to
  // turn a canonical record into an identity digest.
  Digest256 hash() const;

 private:
  void require(std::size_t additional) const;

  CanonicalLimits limits_;
  std::vector<std::byte> buffer_;
};

// CanonicalReader is the defensive counterpart. Every read is bounds checked
// against both the buffer end and the configured limits, and returns a typed
// failure rather than throwing or over-allocating.
class CanonicalReader {
 public:
  CanonicalReader(std::span<const std::byte> data, const CanonicalLimits& limits = {})
      : data_(data), limits_(limits) {}

  bool at_end() const noexcept { return pos_ == data_.size(); }
  std::size_t remaining() const noexcept { return data_.size() - pos_; }
  std::size_t position() const noexcept { return pos_; }
  const Status& status() const noexcept { return status_; }
  bool ok() const noexcept { return status_.ok(); }

  Status fail(ErrorCode code, std::string detail);

  bool read_u8(std::uint8_t& out);
  bool read_bool(bool& out);
  bool read_u16(std::uint16_t& out);
  bool read_u32(std::uint32_t& out);
  bool read_u64(std::uint64_t& out);
  bool read_i64(std::int64_t& out);
  bool read_f64(double& out);
  bool read_str(std::string& out);
  bool read_blob(std::vector<std::byte>& out);
  bool read_digest(Digest256& out);
  bool read_list(std::uint32_t& count);
  bool read_present(bool& has_value);
  bool read_domain(std::string_view expected);
  bool skip(std::size_t count);

  // Optional handle: the zero value is a legitimate "absent" marker for handle
  // fields that are only populated once a record reaches a later state (a
  // compilation with no current attempt, a worker with no live session).
  // Peer-supplied required handles must still use read_id, which rejects zero.
  template <class IdT>
  bool read_optional_id(IdT& out) {
    std::uint64_t raw = 0;
    if (!read_u64(raw)) return false;
    if (raw == 0) {
      out = IdT();
      return true;
    }
    if (!IdT::decode(raw, out)) {
      fail(ErrorCode::Malformed, "optional identity handle is out of domain");
      return false;
    }
    return true;
  }

  bool read_id(CompilationId& out);
  bool read_id(RequestId& out);
  bool read_id(WorkerId& out);
  bool read_id(WorkerBootId& out);
  bool read_id(SessionId& out);
  bool read_id(LeaseId& out);
  bool read_id(SourceId& out);
  bool read_id(IRId& out);
  bool read_id(DependencySetId& out);
  bool read_id(ToolchainId& out);
  bool read_id(TargetId& out);
  bool read_id(SpecializationId& out);
  bool read_id(CompilePolicyId& out);
  bool read_id(CacheEntryId& out);
  bool read_id(ArtifactId& out);
  bool read_id(ArtifactCommitId& out);
  bool read_id(EvidenceId& out);
  bool read_id(ProvenanceId& out);
  bool read_id(CompilationAttemptId& out);
  bool read_id(CompilationUnitId& out);
  bool read_id(IntermediateId& out);
  bool read_id(ValidationId& out);
  bool read_gen(RequestGeneration& out);

  bool read_gen(CompilationGeneration& out);
  bool read_gen(CompilationAttemptGeneration& out);
  bool read_gen(CoordinatorEpoch& out);
  bool read_gen(WorkerGeneration& out);
  bool read_gen(LeaseGeneration& out);
  bool read_gen(SourceGeneration& out);
  bool read_gen(IRGeneration& out);
  bool read_gen(DependencyGeneration& out);
  bool read_gen(ToolchainGeneration& out);
  bool read_gen(TargetGeneration& out);
  bool read_gen(SpecializationGeneration& out);
  bool read_gen(CompilePolicyGeneration& out);
  bool read_gen(CacheGeneration& out);
  bool read_gen(ArtifactGeneration& out);
  bool read_gen(ArtifactCommitGeneration& out);
  bool read_gen(EvidenceGeneration& out);
  bool read_gen(ProvenanceGeneration& out);
  bool read_gen(IntermediateGeneration& out);
  bool read_gen(UnitGeneration& out);

 private:
  bool need(std::size_t count);

  std::span<const std::byte> data_;
  std::size_t pos_ = 0;
  CanonicalLimits limits_;
  Status status_;
};

// Encoding helpers shared by every record type.
void write_string_list(CanonicalWriter& w, const std::vector<std::string>& items);
bool read_string_list(CanonicalReader& r, std::vector<std::string>& out);

}  // namespace dc

#endif  // DC_CANONICAL_HPP
