// Distributed Compilation - wire protocol: framing and typed messages.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Every frame is length-prefixed and bounded. Every payload is a canonical
// record, so the same defensive decoder that protects persistence protects the
// network. A peer can therefore never make the coordinator allocate more than
// the configured frame bound, and an out-of-domain enum is a typed refusal.
#ifndef DC_WIRE_HPP
#define DC_WIRE_HPP

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "dc/codec.hpp"
#include "dc/coordinator.hpp"
#include "dc/model.hpp"
#include "dc/types.hpp"

namespace dc {

constexpr std::uint32_t kWireMagic = 0x31435044u;   // "DPC1"
constexpr std::size_t kWireHeaderBytes = 28;
constexpr std::uint32_t kMaxFrameBytes = 16u * 1024u * 1024u;

enum class Op : std::uint16_t {
  Invalid = 0,
  Hello = 1,
  RegisterWorker = 2,
  AdvertiseToolchain = 3,
  SubmitCompilation = 4,
  Query = 5,
  Assign = 6,
  BeginCompile = 7,
  ReportOutput = 8,
  ValidateOutput = 9,
  CommitArtifact = 10,
  FailAttempt = 11,
  CancelAttempt = 12,
  CacheQuery = 13,
  CacheReport = 14,
  Snapshot = 15,
  Audit = 16,
  Shutdown = 17,
  Response = 18,
  Error = 19,
  Heartbeat = 20,
  WorkerReady = 21,
  ValidateResponse = 22,
};

std::string_view to_string(Op op) noexcept;
bool parse_op(std::string_view text, Op& out) noexcept;

enum class SessionRole : std::uint8_t { Client = 0, Worker = 1, Admin = 2 };

struct Frame {
  Op op = Op::Invalid;
  std::uint64_t request_id = 0;
  std::vector<std::byte> payload;
};

Status encode_frame(const Frame& frame, std::vector<std::byte>& out);
Status decode_frame(std::span<const std::byte> bytes, Frame& out);

// --- payload codecs -------------------------------------------------------
struct HelloMessage {
  SessionRole role = SessionRole::Client;
  std::string name;
  std::uint32_t protocol_version = DC_PROTOCOL_VERSION;
};

struct RegisterWorkerMessage {
  std::string endpoint;
  std::string host;
  WorkerId worker_id;
  WorkerBootId boot_id;
  std::uint32_t max_inflight = 4;
  WorkerCapabilities capabilities;
};

struct ReadyMessage {
  SessionId session;
  WorkerId worker;
  WorkerBootId boot;
  WorkerGeneration generation;
  CoordinatorEpoch epoch;
  std::string detail;
};

struct SubmitMessage {
  CompilationRequest request;
  std::vector<Blob> blobs;
  bool dry_run = false;
  bool force_rebuild = false;
};

struct AssignMessage {
  Assignment assignment;
};

struct ReportOutputMessage {
  ReportOutput output;
};

struct FailAttemptMessage {
  AttemptFailure failure;
};

struct CancelMessage {
  ControlMessage control;
};

struct CommitMessage {
  ControlMessage control;
  ArtifactCommit commit;
};

struct CacheQueryMessage {
  Digest256 unit_identity;
};

struct CacheReportMessage {
  CacheDecision decision;
  CacheEntry entry;
};

struct ValidateMessage {
  std::uint32_t mode = 0;   // 0 = revalidate evidence, 1 = confirm artifact digest
  Digest256 subject;
  std::string nonce;
};

struct ValidateResponseMessage {
  std::uint32_t mode = 0;
  EvidenceClass evidence = EvidenceClass::Unknown;
  Digest256 capabilities_digest;
  Digest256 subject;
  std::string detail;
};

struct ResponseMessage {
  Op op = Op::Invalid;
  ErrorCode code = ErrorCode::Ok;
  std::string detail;
  std::vector<std::byte> payload;
};

struct SubmissionResponse {
  RequestId request_id;
  Digest256 request_identity;
  std::vector<UnitSubmission> units;
  bool all_committed = false;
  bool served_from_cache = false;
  bool duplicate_request = false;
};

struct CommitResponse {
  CommitOutcome outcome = CommitOutcome::Refused;
  ErrorCode error = ErrorCode::Ok;
  std::string detail;
  ArtifactCommit commit;
  ValidationReport validation;
  bool artifact_authoritative = false;
};

Status encode_submission_response(const SubmissionResponse&, std::vector<std::byte>& out);
bool decode_submission_response(std::span<const std::byte>, SubmissionResponse& out);
Status encode_commit_response(const CommitResponse&, std::vector<std::byte>& out);
bool decode_commit_response(std::span<const std::byte>, CommitResponse& out);

struct QueryMessage {
  std::uint32_t kind = 0;   // 0 compilation, 1 attempt, 2 audit, 3 workers, 4 cache, 5 job
  std::uint64_t id = 0;
  Digest256 identity;
};

Status encode_hello(const HelloMessage&, std::vector<std::byte>& out);
bool decode_hello(std::span<const std::byte>, HelloMessage& out);
Status encode_register_worker(const RegisterWorkerMessage&, std::vector<std::byte>& out);
bool decode_register_worker(std::span<const std::byte>, RegisterWorkerMessage& out);
Status encode_ready(const ReadyMessage&, std::vector<std::byte>& out);
bool decode_ready(std::span<const std::byte>, ReadyMessage& out);
Status encode_submit(const SubmitMessage&, std::vector<std::byte>& out);
bool decode_submit(std::span<const std::byte>, SubmitMessage& out);
Status encode_assignment(const Assignment&, std::vector<std::byte>& out);
bool decode_assignment(std::span<const std::byte>, Assignment& out);
Status encode_authority_claim(const AuthorityClaim&, std::vector<std::byte>& out);
bool decode_authority_claim(std::span<const std::byte>, AuthorityClaim& out);
Status encode_report_output(const ReportOutput&, std::vector<std::byte>& out);
bool decode_report_output(std::span<const std::byte>, ReportOutput& out);
Status encode_fail_attempt(const AttemptFailure&, std::vector<std::byte>& out);
bool decode_fail_attempt(std::span<const std::byte>, AttemptFailure& out);
Status encode_control(const ControlMessage&, std::vector<std::byte>& out);
bool decode_control(std::span<const std::byte>, ControlMessage& out);
Status encode_commit_message(const CommitMessage&, std::vector<std::byte>& out);
bool decode_commit_message(std::span<const std::byte>, CommitMessage& out);
Status encode_cache_query(const CacheQueryMessage&, std::vector<std::byte>& out);
bool decode_cache_query(std::span<const std::byte>, CacheQueryMessage& out);
Status encode_cache_report(const CacheReportMessage&, std::vector<std::byte>& out);
bool decode_cache_report(std::span<const std::byte>, CacheReportMessage& out);
Status encode_validate(const ValidateMessage&, std::vector<std::byte>& out);
bool decode_validate(std::span<const std::byte>, ValidateMessage& out);
Status encode_validate_response(const ValidateResponseMessage&, std::vector<std::byte>& out);
bool decode_validate_response(std::span<const std::byte>, ValidateResponseMessage& out);
Status encode_response(const ResponseMessage&, std::vector<std::byte>& out);
bool decode_response(std::span<const std::byte>, ResponseMessage& out);
Status encode_query(const QueryMessage&, std::vector<std::byte>& out);
bool decode_query(std::span<const std::byte>, QueryMessage& out);

// Explain rendering shared by the CLI and the coordinator response path.
std::string render_compilation(const CompilationRecord& record);
std::string render_attempt(const CompilationAttempt& attempt);
std::string render_worker(const WorkerRecord& worker);
std::string render_cache_decision(const CacheDecision& decision);
std::string render_commit(const ArtifactCommit& commit);
std::string render_provenance(const Provenance& provenance);

}  // namespace dc

#endif  // DC_WIRE_HPP
