// Distributed Compilation - typed status and error domain.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#ifndef DC_TYPES_HPP
#define DC_TYPES_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include "dc/version.hpp"

namespace dc {

// Typed failure domain. Every refusal in the runtime carries one of these codes so
// that callers (and the CLI) can distinguish "refused because stale" from
// "refused because unsupported" without parsing prose.
enum class ErrorCode : std::uint16_t {
  Ok = 0,

  // Structural / input validation.
  InvalidArgument = 1,
  Malformed = 2,
  LimitExceeded = 3,
  Overflow = 4,
  Unsupported = 5,
  Unknown = 6,
  NotFound = 7,
  AlreadyExists = 8,
  Duplicate = 9,
  Internal = 10,
  IoError = 11,
  ProtocolViolation = 12,
  Unauthorized = 13,

  // Stale authority domain. Each of these means: the claim was well formed but
  // bound to a generation the coordinator no longer considers current.
  StaleEpoch = 20,
  StaleWorkerBoot = 21,
  StaleWorkerGeneration = 22,
  StaleLease = 23,
  StaleCompilation = 24,
  StaleAttempt = 25,
  StaleSource = 26,
  StaleIR = 27,
  StaleDependencies = 28,
  StaleToolchain = 29,
  StaleTarget = 30,
  StaleSpecialization = 31,
  StalePolicy = 32,
  StaleCache = 33,
  StaleRequest = 34,
  StaleSession = 35,

  // Eligibility / assignment.
  NotEligible = 40,
  NoEligibleWorker = 41,
  NotAssigned = 42,

  // Artifact authority.
  ArtifactMismatch = 50,
  ArtifactAlreadyCommitted = 51,
  ArtifactMissing = 52,
  IntegrityFailure = 53,
  ValidationFailure = 54,
  ProvenanceMissing = 55,
  ReproducibilityViolation = 56,
  FanInIncomplete = 57,
  Cancelled = 58,
  Fenced = 59,
  Ambiguous = 60,
  IllegalTransition = 61,

  // Cache domain.
  CacheMiss = 70,
  CacheStale = 71,
  CacheIncompatible = 72,
  CacheCorrupt = 73,
  CacheUnknown = 74,

  // Persistence domain.
  PersistenceCorrupt = 80,
  PersistenceTruncated = 81,
  SchemaMismatch = 82,
  PersistenceClosed = 83,

  // Transport domain.
  TransportFailure = 90,
  ConnectionClosed = 91,
  Timeout = 92,
  FrameTooLarge = 93,
  Shutdown = 94,
};

std::string_view to_string(ErrorCode code) noexcept;
bool is_stale(ErrorCode code) noexcept;

// A Status is either Ok, or a typed code plus a human-readable detail string.
// Detail strings are for diagnosis only; decisions must never depend on them.
class Status {
 public:
  Status() = default;

  static Status success() { return Status{}; }
  static Status error(ErrorCode code, std::string detail = {}) {
    Status s;
    s.code_ = code;
    s.detail_ = std::move(detail);
    return s;
  }

  bool ok() const noexcept { return code_ == ErrorCode::Ok; }
  explicit operator bool() const noexcept { return ok(); }

  ErrorCode code() const noexcept { return code_; }
  const std::string& detail() const noexcept { return detail_; }

  void set_detail(std::string detail) { detail_ = std::move(detail); }
  void prepend_context(std::string_view context);

  std::string describe() const;

 private:
  ErrorCode code_ = ErrorCode::Ok;
  std::string detail_;
};

// Result<T> carries either a value or a typed failure. T must be default
// constructible; value() is only meaningful when ok() is true.
template <class T>
class Result {
 public:
  Result() = default;
  Result(T value) : value_(std::move(value)) {}                     // NOLINT(google-explicit-constructor)
  Result(Status status) : status_(std::move(status)) {}             // NOLINT(google-explicit-constructor)

  static Result failure(ErrorCode code, std::string detail = {}) {
    return Result(Status::error(code, std::move(detail)));
  }

  bool ok() const noexcept { return status_.ok(); }
  explicit operator bool() const noexcept { return ok(); }

  const Status& status() const noexcept { return status_; }
  ErrorCode code() const noexcept { return status_.code(); }
  const std::string& detail() const noexcept { return status_.detail(); }

  T& value() noexcept { return value_; }
  const T& value() const noexcept { return value_; }

  T& operator*() noexcept { return value_; }
  const T& operator*() const noexcept { return value_; }
  T* operator->() noexcept { return &value_; }
  const T* operator->() const noexcept { return &value_; }

 private:
  Status status_;
  T value_{};
};

using VoidResult = Status;

// Monotonic logical sequence number, persisted across restarts.
using Seq = std::uint64_t;

// Unix epoch milliseconds. Never part of any identity digest.
using UnixMillis = std::int64_t;

}  // namespace dc

#endif  // DC_TYPES_HPP
