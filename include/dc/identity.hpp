// Distributed Compilation - strongly typed identity and generation domains.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_IDENTITY_HPP
#define DC_IDENTITY_HPP

#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <type_traits>

namespace dc {

// ---------------------------------------------------------------------------
// Id<Tag>: a 64-bit handle whose Tag makes it a distinct type.
//
// Identity handles are opaque coordinator-assigned or content-derived labels.
// They are deliberately NOT interchangeable with generational counters: mixing
// a WorkerId with a WorkerGeneration is a compile error, not a runtime bug.
// ---------------------------------------------------------------------------
template <class Tag, class Rep = std::uint64_t>
class Id {
 public:
  using rep_type = Rep;
  using tag_type = Tag;

  constexpr Id() noexcept = default;
  constexpr explicit Id(Rep value) noexcept : value_(value) {}

  constexpr Rep value() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }

  void reset() noexcept { value_ = 0; }

  // Decoding untrusted input: the zero handle means "absent" and is never a
  // valid peer-supplied identity.
  static bool decode(Rep raw, Id& out) noexcept {
    if (raw == 0) return false;
    out = Id(raw);
    return true;
  }

  friend constexpr bool operator==(Id a, Id b) noexcept { return a.value_ == b.value_; }
  friend constexpr bool operator!=(Id a, Id b) noexcept { return a.value_ != b.value_; }
  friend constexpr bool operator<(Id a, Id b) noexcept { return a.value_ < b.value_; }
  friend constexpr bool operator>(Id a, Id b) noexcept { return a.value_ > b.value_; }
  friend constexpr bool operator<=(Id a, Id b) noexcept { return a.value_ <= b.value_; }
  friend constexpr bool operator>=(Id a, Id b) noexcept { return a.value_ >= b.value_; }

 private:
  Rep value_ = 0;
};

// ---------------------------------------------------------------------------
// Gen<Tag>: a monotonically advancing generation counter for an authority
// domain. Generation zero always means "unset / not yet established".
// ---------------------------------------------------------------------------
template <class Tag>
class Gen {
 public:
  using tag_type = Tag;

  constexpr Gen() noexcept = default;
  constexpr explicit Gen(std::uint64_t value) noexcept : value_(value) {}

  constexpr std::uint64_t value() const noexcept { return value_; }
  constexpr bool is_zero() const noexcept { return value_ == 0; }
  constexpr bool is_set() const noexcept { return value_ != 0; }

  Gen next() const noexcept {
    return Gen(value_ == std::numeric_limits<std::uint64_t>::max() ? value_ : value_ + 1);
  }

  void set(std::uint64_t value) noexcept { value_ = value; }

  friend constexpr bool operator==(Gen a, Gen b) noexcept { return a.value_ == b.value_; }
  friend constexpr bool operator!=(Gen a, Gen b) noexcept { return a.value_ != b.value_; }
  friend constexpr bool operator<(Gen a, Gen b) noexcept { return a.value_ < b.value_; }
  friend constexpr bool operator>(Gen a, Gen b) noexcept { return a.value_ > b.value_; }
  friend constexpr bool operator<=(Gen a, Gen b) noexcept { return a.value_ <= b.value_; }
  friend constexpr bool operator>=(Gen a, Gen b) noexcept { return a.value_ >= b.value_; }

 private:
  std::uint64_t value_ = 0;
};

#define DC_DECLARE_ID(Name)      \
  struct Name##Tag;              \
  using Name = ::dc::Id<Name##Tag>

#define DC_DECLARE_GEN(Name)     \
  struct Name##Tag;              \
  using Name = ::dc::Gen<Name##Tag>

// Compilation transaction domain.
DC_DECLARE_ID(CompilationId);
DC_DECLARE_GEN(CompilationGeneration);
DC_DECLARE_ID(CompilationUnitId);
DC_DECLARE_GEN(UnitGeneration);
DC_DECLARE_ID(CompilationAttemptId);
DC_DECLARE_GEN(CompilationAttemptGeneration);
DC_DECLARE_GEN(CoordinatorEpoch);
DC_DECLARE_ID(RequestId);
DC_DECLARE_GEN(RequestGeneration);

// Participant domain.
DC_DECLARE_ID(WorkerId);
DC_DECLARE_ID(WorkerBootId);
DC_DECLARE_GEN(WorkerGeneration);
DC_DECLARE_ID(SessionId);
DC_DECLARE_ID(LeaseId);
DC_DECLARE_GEN(LeaseGeneration);

// Input domain.
DC_DECLARE_ID(SourceId);
DC_DECLARE_GEN(SourceGeneration);
DC_DECLARE_ID(IRId);
DC_DECLARE_GEN(IRGeneration);
DC_DECLARE_ID(DependencySetId);
DC_DECLARE_GEN(DependencyGeneration);
DC_DECLARE_ID(IntermediateId);
DC_DECLARE_GEN(IntermediateGeneration);

// Environment domain.
DC_DECLARE_ID(ToolchainId);
DC_DECLARE_GEN(ToolchainGeneration);
DC_DECLARE_ID(TargetId);
DC_DECLARE_GEN(TargetGeneration);
DC_DECLARE_ID(SpecializationId);
DC_DECLARE_GEN(SpecializationGeneration);
DC_DECLARE_ID(CompilePolicyId);
DC_DECLARE_GEN(CompilePolicyGeneration);

// Result domain.
DC_DECLARE_ID(CacheEntryId);
DC_DECLARE_GEN(CacheGeneration);
DC_DECLARE_ID(ArtifactId);
DC_DECLARE_GEN(ArtifactGeneration);
DC_DECLARE_ID(ArtifactCommitId);
DC_DECLARE_GEN(ArtifactCommitGeneration);

// Evidence domain.
DC_DECLARE_ID(EvidenceId);
DC_DECLARE_GEN(EvidenceGeneration);
DC_DECLARE_ID(ProvenanceId);
DC_DECLARE_GEN(ProvenanceGeneration);
DC_DECLARE_ID(ValidationId);

#undef DC_DECLARE_ID
#undef DC_DECLARE_GEN

// Stable 64-bit mixing used where an identity must be derived from canonical
// bytes without a full digest. Never used for content addressing.
std::uint64_t mix64(std::uint64_t value) noexcept;
std::uint64_t fnv1a64(const void* data, std::size_t size, std::uint64_t seed = 1469598103934665603ULL) noexcept;

}  // namespace dc

namespace std {

template <class Tag, class Rep>
struct hash<::dc::Id<Tag, Rep>> {
  std::size_t operator()(const ::dc::Id<Tag, Rep>& id) const noexcept {
    return static_cast<std::size_t>(::dc::mix64(static_cast<std::uint64_t>(id.value())));
  }
};

template <class Tag>
struct hash<::dc::Gen<Tag>> {
  std::size_t operator()(const ::dc::Gen<Tag>& gen) const noexcept {
    return static_cast<std::size_t>(::dc::mix64(gen.value() ^ 0x9E3779B97F4A7C15ULL));
  }
};

}  // namespace std

#endif  // DC_IDENTITY_HPP
