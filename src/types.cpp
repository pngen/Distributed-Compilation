// Distributed Compilation - status rendering.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/types.hpp"

namespace dc {

std::string_view to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::Ok: return "OK";
    case ErrorCode::InvalidArgument: return "InvalidArgument";
    case ErrorCode::Malformed: return "Malformed";
    case ErrorCode::LimitExceeded: return "LimitExceeded";
    case ErrorCode::Overflow: return "Overflow";
    case ErrorCode::Unsupported: return "Unsupported";
    case ErrorCode::Unknown: return "Unknown";
    case ErrorCode::NotFound: return "NotFound";
    case ErrorCode::AlreadyExists: return "AlreadyExists";
    case ErrorCode::Duplicate: return "Duplicate";
    case ErrorCode::Internal: return "Internal";
    case ErrorCode::IoError: return "IoError";
    case ErrorCode::ProtocolViolation: return "ProtocolViolation";
    case ErrorCode::Unauthorized: return "Unauthorized";
    case ErrorCode::StaleEpoch: return "StaleEpoch";
    case ErrorCode::StaleWorkerBoot: return "StaleWorkerBoot";
    case ErrorCode::StaleWorkerGeneration: return "StaleWorkerGeneration";
    case ErrorCode::StaleLease: return "StaleLease";
    case ErrorCode::StaleCompilation: return "StaleCompilation";
    case ErrorCode::StaleAttempt: return "StaleAttempt";
    case ErrorCode::StaleSource: return "StaleSource";
    case ErrorCode::StaleIR: return "StaleIR";
    case ErrorCode::StaleDependencies: return "StaleDependencies";
    case ErrorCode::StaleToolchain: return "StaleToolchain";
    case ErrorCode::StaleTarget: return "StaleTarget";
    case ErrorCode::StaleSpecialization: return "StaleSpecialization";
    case ErrorCode::StalePolicy: return "StalePolicy";
    case ErrorCode::StaleCache: return "StaleCache";
    case ErrorCode::StaleRequest: return "StaleRequest";
    case ErrorCode::StaleSession: return "StaleSession";
    case ErrorCode::NotEligible: return "NotEligible";
    case ErrorCode::NoEligibleWorker: return "NoEligibleWorker";
    case ErrorCode::NotAssigned: return "NotAssigned";
    case ErrorCode::ArtifactMismatch: return "ArtifactMismatch";
    case ErrorCode::ArtifactAlreadyCommitted: return "ArtifactAlreadyCommitted";
    case ErrorCode::ArtifactMissing: return "ArtifactMissing";
    case ErrorCode::IntegrityFailure: return "IntegrityFailure";
    case ErrorCode::ValidationFailure: return "ValidationFailure";
    case ErrorCode::ProvenanceMissing: return "ProvenanceMissing";
    case ErrorCode::ReproducibilityViolation: return "ReproducibilityViolation";
    case ErrorCode::FanInIncomplete: return "FanInIncomplete";
    case ErrorCode::Cancelled: return "Cancelled";
    case ErrorCode::Fenced: return "Fenced";
    case ErrorCode::Ambiguous: return "Ambiguous";
    case ErrorCode::IllegalTransition: return "IllegalTransition";
    case ErrorCode::CacheMiss: return "CacheMiss";
    case ErrorCode::CacheStale: return "CacheStale";
    case ErrorCode::CacheIncompatible: return "CacheIncompatible";
    case ErrorCode::CacheCorrupt: return "CacheCorrupt";
    case ErrorCode::CacheUnknown: return "CacheUnknown";
    case ErrorCode::PersistenceCorrupt: return "PersistenceCorrupt";
    case ErrorCode::PersistenceTruncated: return "PersistenceTruncated";
    case ErrorCode::SchemaMismatch: return "SchemaMismatch";
    case ErrorCode::PersistenceClosed: return "PersistenceClosed";
    case ErrorCode::TransportFailure: return "TransportFailure";
    case ErrorCode::ConnectionClosed: return "ConnectionClosed";
    case ErrorCode::Timeout: return "Timeout";
    case ErrorCode::FrameTooLarge: return "FrameTooLarge";
    case ErrorCode::Shutdown: return "Shutdown";
  }
  return "Unknown";
}

bool is_stale(ErrorCode code) noexcept {
  const auto value = static_cast<std::uint16_t>(code);
  return value >= 20 && value <= 35;
}

void Status::prepend_context(std::string_view context) {
  std::string combined;
  combined.reserve(context.size() + detail_.size() + 3);
  combined.append(context);
  if (!detail_.empty()) {
    combined.append(": ");
    combined.append(detail_);
  }
  detail_ = std::move(combined);
}

std::string Status::describe() const {
  std::string out(to_string(code_));
  if (!detail_.empty()) {
    out.append(": ");
    out.append(detail_);
  }
  return out;
}

}  // namespace dc
