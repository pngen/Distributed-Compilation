// Distributed Compilation - wire protocol implementation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/wire.hpp"

#include <algorithm>
#include <cstring>

#include "dc/digest.hpp"

namespace dc {
namespace {

void put_u16(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(static_cast<std::byte>(value & 0xFFu));
  out.push_back(static_cast<std::byte>((value >> 8) & 0xFFu));
}

void put_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
}

void put_u64(std::vector<std::byte>& out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::byte>((value >> (i * 8)) & 0xFFu));
}

std::uint16_t get_u16(const std::byte* p) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[0]) |
                                    (static_cast<std::uint16_t>(static_cast<std::uint8_t>(p[1])) << 8));
}

std::uint32_t get_u32(const std::byte* p) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(p[i])) << (i * 8);
  }
  return value;
}

std::uint64_t get_u64(const std::byte* p) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(p[i])) << (i * 8);
  }
  return value;
}

void write_control_record(CanonicalWriter& w, const ControlMessage& control) {
  w.domain("dc.msg.control.v1");
  w.id(control.session);
  w.u8(static_cast<std::uint8_t>(control.kind));
  w.id(control.compilation);
  w.gen(control.compilation_generation);
  w.id(control.attempt);
  w.gen(control.attempt_generation);
  w.id(control.lease);
  w.gen(control.lease_generation);
  w.id(control.commit);
  w.digest(control.artifact_digest);
  w.str(control.reason);
}

bool read_control_record(CanonicalReader& r, ControlMessage& control) {
  if (!r.read_domain("dc.msg.control.v1")) return false;
  if (!r.read_id(control.session)) return false;
  std::uint8_t kind = 0;
  if (!r.read_u8(kind)) return false;
  if (kind > static_cast<std::uint8_t>(ControlKind::Shutdown)) {
    r.fail(ErrorCode::Malformed, "control kind out of domain");
    return false;
  }
  control.kind = static_cast<ControlKind>(kind);
  if (!r.read_id(control.compilation)) return false;
  if (!r.read_gen(control.compilation_generation)) return false;
  if (!r.read_id(control.attempt)) return false;
  if (!r.read_gen(control.attempt_generation)) return false;
  if (!r.read_id(control.lease)) return false;
  if (!r.read_gen(control.lease_generation)) return false;
  if (!r.read_id(control.commit)) return false;
  if (!r.read_digest(control.artifact_digest)) return false;
  if (!r.read_str(control.reason)) return false;
  return true;
}

template <class WriterFn>
Status finish(WriterFn&& writer, std::vector<std::byte>& out) {
  CanonicalWriter w;
  writer(w);
  out.assign(w.bytes().begin(), w.bytes().end());
  return Status::success();
}

}  // namespace

std::string_view to_string(Op op) noexcept {
  switch (op) {
    case Op::Invalid: return "INVALID";
    case Op::Hello: return "HELLO";
    case Op::RegisterWorker: return "REGISTER_WORKER";
    case Op::AdvertiseToolchain: return "ADVERTISE_TOOLCHAIN";
    case Op::SubmitCompilation: return "SUBMIT_COMPILATION";
    case Op::Query: return "QUERY";
    case Op::Assign: return "ASSIGN";
    case Op::BeginCompile: return "BEGIN_COMPILE";
    case Op::ReportOutput: return "REPORT_OUTPUT";
    case Op::ValidateOutput: return "VALIDATE_OUTPUT";
    case Op::CommitArtifact: return "COMMIT_ARTIFACT";
    case Op::FailAttempt: return "FAIL_ATTEMPT";
    case Op::CancelAttempt: return "CANCEL_ATTEMPT";
    case Op::CacheQuery: return "CACHE_QUERY";
    case Op::CacheReport: return "CACHE_REPORT";
    case Op::Snapshot: return "SNAPSHOT";
    case Op::Audit: return "AUDIT";
    case Op::Shutdown: return "SHUTDOWN";
    case Op::Response: return "RESPONSE";
    case Op::Error: return "ERROR";
    case Op::Heartbeat: return "HEARTBEAT";
    case Op::WorkerReady: return "WORKER_READY";
    case Op::ValidateResponse: return "VALIDATE_RESPONSE";
  }
  return "INVALID";
}

bool parse_op(std::string_view text, Op& out) noexcept {
  for (std::uint16_t value = 1; value <= static_cast<std::uint16_t>(Op::ValidateResponse); ++value) {
    const auto candidate = static_cast<Op>(value);
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

Status encode_frame(const Frame& frame, std::vector<std::byte>& out) {
  if (frame.payload.size() > kMaxFrameBytes) {
    return Status::error(ErrorCode::FrameTooLarge, "frame payload exceeds the protocol bound");
  }
  out.clear();
  out.reserve(kWireHeaderBytes + frame.payload.size());
  put_u32(out, static_cast<std::uint32_t>(kWireHeaderBytes - 4 + frame.payload.size()));
  put_u32(out, kWireMagic);
  put_u16(out, static_cast<std::uint16_t>(DC_PROTOCOL_VERSION));
  put_u16(out, static_cast<std::uint16_t>(frame.op));
  put_u64(out, frame.request_id);
  put_u32(out, static_cast<std::uint32_t>(frame.payload.size()));
  put_u32(out, 0);
  out.insert(out.end(), frame.payload.begin(), frame.payload.end());
  return Status::success();
}

Status decode_frame(std::span<const std::byte> bytes, Frame& out) {
  if (bytes.size() < kWireHeaderBytes) {
    return Status::error(ErrorCode::Malformed, "frame is shorter than the header");
  }
  const std::byte* p = bytes.data();
  const std::uint32_t total_length = get_u32(p);
  if (get_u32(p + 4) != kWireMagic) {
    return Status::error(ErrorCode::ProtocolViolation, "frame magic mismatch");
  }
  const std::uint16_t version = get_u16(p + 8);
  if (version != DC_PROTOCOL_VERSION) {
    return Status::error(ErrorCode::Unsupported,
                         "protocol version " + std::to_string(version) + " is not supported");
  }
  const std::uint16_t raw_op = get_u16(p + 10);
  if (raw_op == 0 || raw_op > static_cast<std::uint16_t>(Op::ValidateResponse)) {
    return Status::error(ErrorCode::ProtocolViolation, "op code out of domain");
  }
  if (get_u32(p + 24) != 0) {
    return Status::error(ErrorCode::ProtocolViolation, "reserved frame flags must be zero");
  }
  const std::uint32_t payload_length = get_u32(p + 20);
  if (total_length != kWireHeaderBytes - 4 + payload_length) {
    return Status::error(ErrorCode::ProtocolViolation, "frame length fields disagree");
  }
  if (bytes.size() != kWireHeaderBytes + payload_length) {
    return Status::error(ErrorCode::Malformed, "frame body length mismatch");
  }
  Frame frame;
  frame.op = static_cast<Op>(raw_op);
  frame.request_id = get_u64(p + 12);
  frame.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kWireHeaderBytes), bytes.end());
  out = std::move(frame);
  return Status::success();
}

// ---------------------------------------------------------------------------
// Message payloads
// ---------------------------------------------------------------------------
Status encode_hello(const HelloMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.hello.v1");
        w.u8(static_cast<std::uint8_t>(message.role));
        w.str(message.name);
        w.u32(message.protocol_version);
      },
      out);
}

bool decode_hello(std::span<const std::byte> bytes, HelloMessage& out) {
  CanonicalReader r(bytes);
  HelloMessage message;
  if (!r.read_domain("dc.msg.hello.v1")) return false;
  std::uint8_t role = 0;
  if (!r.read_u8(role)) return false;
  if (role > static_cast<std::uint8_t>(SessionRole::Admin)) {
    r.fail(ErrorCode::Malformed, "session role out of domain");
    return false;
  }
  message.role = static_cast<SessionRole>(role);
  if (!r.read_str(message.name)) return false;
  if (!r.read_u32(message.protocol_version)) return false;
  if (message.protocol_version != DC_PROTOCOL_VERSION) {
    r.fail(ErrorCode::Unsupported, "hello protocol version mismatch");
    return false;
  }
  out = std::move(message);
  return r.at_end();
}

Status encode_register_worker(const RegisterWorkerMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.register-worker.v1");
        w.str(message.endpoint);
        w.str(message.host);
        w.id(message.worker_id);
        w.id(message.boot_id);
        w.u32(message.max_inflight);
        encode_capabilities(w, message.capabilities);
      },
      out);
}

bool decode_register_worker(std::span<const std::byte> bytes, RegisterWorkerMessage& out) {
  CanonicalReader r(bytes);
  RegisterWorkerMessage message;
  if (!r.read_domain("dc.msg.register-worker.v1")) return false;
  if (!r.read_str(message.endpoint)) return false;
  if (!r.read_str(message.host)) return false;
  if (!r.read_id(message.worker_id)) return false;
  if (!r.read_id(message.boot_id)) return false;
  if (!r.read_u32(message.max_inflight)) return false;
  if (message.max_inflight == 0 || message.max_inflight > 64) {
    r.fail(ErrorCode::LimitExceeded, "max_inflight out of bounds");
    return false;
  }
  if (!decode_capabilities(r, message.capabilities)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_ready(const ReadyMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.ready.v1");
        w.id(message.session);
        w.id(message.worker);
        w.id(message.boot);
        w.gen(message.generation);
        w.gen(message.epoch);
        w.str(message.detail);
      },
      out);
}

bool decode_ready(std::span<const std::byte> bytes, ReadyMessage& out) {
  CanonicalReader r(bytes);
  ReadyMessage message;
  if (!r.read_domain("dc.msg.ready.v1")) return false;
  if (!r.read_id(message.session)) return false;
  if (!r.read_id(message.worker)) return false;
  if (!r.read_id(message.boot)) return false;
  if (!r.read_gen(message.generation)) return false;
  if (!r.read_gen(message.epoch)) return false;
  if (!r.read_str(message.detail)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_submit(const SubmitMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.submit.v1");
        encode_request(w, message.request);
        w.boolean(message.dry_run);
        w.boolean(message.force_rebuild);
        w.list(static_cast<std::uint32_t>(message.blobs.size()));
        for (const auto& blob : message.blobs) {
          w.digest(blob.digest);
          w.blob(blob.bytes);
        }
      },
      out);
}

bool decode_submit(std::span<const std::byte> bytes, SubmitMessage& out) {
  CanonicalReader r(bytes);
  SubmitMessage message;
  if (!r.read_domain("dc.msg.submit.v1")) return false;
  if (!decode_request(r, message.request)) return false;
  if (!r.read_bool(message.dry_run)) return false;
  if (!r.read_bool(message.force_rebuild)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  if (count > 65536) {
    r.fail(ErrorCode::LimitExceeded, "submission blob count out of bounds");
    return false;
  }
  message.blobs.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_digest(message.blobs[i].digest)) return false;
    if (!r.read_blob(message.blobs[i].bytes)) return false;
    const Digest256 actual = sha256(std::span<const std::byte>(message.blobs[i].bytes.data(),
                                                               message.blobs[i].bytes.size()));
    if (actual != message.blobs[i].digest) {
      r.fail(ErrorCode::IntegrityFailure, "submitted blob does not match its declared digest");
      return false;
    }
  }
  out = std::move(message);
  return r.at_end();
}

Status encode_authority_claim(const AuthorityClaim& claim, std::vector<std::byte>& out) {
  return finish([&claim](CanonicalWriter& w) { write_authority_claim(w, claim); }, out);
}

bool decode_authority_claim(std::span<const std::byte> bytes, AuthorityClaim& out) {
  CanonicalReader r(bytes);
  AuthorityClaim claim;
  if (!read_authority_claim(r, claim)) return false;
  out = claim;
  return r.at_end();
}

Status encode_assignment(const Assignment& assignment, std::vector<std::byte>& out) {
  return finish(
      [&assignment](CanonicalWriter& w) {
        w.domain("dc.msg.assign.v1");
        w.id(assignment.session);
        w.id(assignment.worker);
        w.id(assignment.worker_boot);
        w.gen(assignment.worker_generation);
        write_authority_claim(w, assignment.claim);
        w.id(assignment.compilation);
        w.gen(assignment.compilation_generation);
        w.id(assignment.unit);
        w.gen(assignment.unit_generation);
        w.id(assignment.attempt);
        w.gen(assignment.attempt_generation);
        w.u32(assignment.unit_index);
        w.u8(static_cast<std::uint8_t>(assignment.kind));
        w.u8(static_cast<std::uint8_t>(assignment.output_kind));
        w.str(assignment.logical_name);
        w.list(static_cast<std::uint32_t>(assignment.sources.size()));
        for (const auto& source : assignment.sources) {
          w.str(source.logical_name);
          w.u8(static_cast<std::uint8_t>(source.format));
          w.str(source.language_mode);
          w.blob(std::span<const std::byte>(source.bytes.data(), source.bytes.size()));
        }
        w.list(static_cast<std::uint32_t>(assignment.dependencies.size()));
        for (const auto& dep : assignment.dependencies) {
          w.str(dep.name);
          w.u8(static_cast<std::uint8_t>(dep.kind));
          w.blob(std::span<const std::byte>(dep.bytes.data(), dep.bytes.size()));
        }
        write_string_list(w, assignment.flags);
        w.list(static_cast<std::uint32_t>(assignment.children.size()));
        for (const auto& child : assignment.children) {
          w.str(child.logical_name);
          w.u8(static_cast<std::uint8_t>(child.kind));
          w.blob(std::span<const std::byte>(child.bytes.data(), child.bytes.size()));
        }
        encode_toolchain(w, assignment.toolchain);
        encode_target(w, assignment.target);
        encode_specialization(w, assignment.specialization);
        encode_policy(w, assignment.policy);
        encode_environment(w, assignment.environment);
        encode_validation_requirements(w, assignment.validation);
        w.u64(assignment.max_compile_millis);
        w.boolean(assignment.speculative);
        encode_lease(w, assignment.lease);
      },
      out);
}

bool decode_assignment(std::span<const std::byte> bytes, Assignment& out) {
  CanonicalReader r(bytes);
  Assignment assignment;
  if (!r.read_domain("dc.msg.assign.v1")) return false;
  if (!r.read_id(assignment.session)) return false;
  if (!r.read_id(assignment.worker)) return false;
  if (!r.read_id(assignment.worker_boot)) return false;
  if (!r.read_gen(assignment.worker_generation)) return false;
  if (!read_authority_claim(r, assignment.claim)) return false;
  if (!r.read_id(assignment.compilation)) return false;
  if (!r.read_gen(assignment.compilation_generation)) return false;
  if (!r.read_id(assignment.unit)) return false;
  if (!r.read_gen(assignment.unit_generation)) return false;
  if (!r.read_id(assignment.attempt)) return false;
  if (!r.read_gen(assignment.attempt_generation)) return false;
  if (!r.read_u32(assignment.unit_index)) return false;
  std::uint8_t kind = 0;
  if (!r.read_u8(kind)) return false;
  if (kind > static_cast<std::uint8_t>(UnitKind::Link)) {
    r.fail(ErrorCode::Malformed, "unit kind out of domain");
    return false;
  }
  assignment.kind = static_cast<UnitKind>(kind);
  std::uint8_t output_kind = 0;
  if (!r.read_u8(output_kind)) return false;
  if (output_kind > static_cast<std::uint8_t>(OutputKind::PreprocessedSource)) {
    r.fail(ErrorCode::Malformed, "output kind out of domain");
    return false;
  }
  assignment.output_kind = static_cast<OutputKind>(output_kind);
  if (!r.read_str(assignment.logical_name)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  if (count > 4096) {
    r.fail(ErrorCode::LimitExceeded, "assignment source count out of bounds");
    return false;
  }
  assignment.sources.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(assignment.sources[i].logical_name)) return false;
    std::uint8_t format = 0;
    if (!r.read_u8(format)) return false;
    if (format > static_cast<std::uint8_t>(InputFormat::Other)) {
      r.fail(ErrorCode::Malformed, "input format out of domain");
      return false;
    }
    assignment.sources[i].format = static_cast<InputFormat>(format);
    if (!r.read_str(assignment.sources[i].language_mode)) return false;
    if (!r.read_blob(assignment.sources[i].bytes)) return false;
  }
  if (!r.read_list(count)) return false;
  if (count > 65536) {
    r.fail(ErrorCode::LimitExceeded, "assignment dependency count out of bounds");
    return false;
  }
  assignment.dependencies.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(assignment.dependencies[i].name)) return false;
    std::uint8_t dep_kind = 0;
    if (!r.read_u8(dep_kind)) return false;
    if (dep_kind > static_cast<std::uint8_t>(DependencyKind::Other)) {
      r.fail(ErrorCode::Malformed, "dependency kind out of domain");
      return false;
    }
    assignment.dependencies[i].kind = static_cast<DependencyKind>(dep_kind);
    if (!r.read_blob(assignment.dependencies[i].bytes)) return false;
  }
  if (!read_string_list(r, assignment.flags)) return false;
  if (!r.read_list(count)) return false;
  if (count > 4096) {
    r.fail(ErrorCode::LimitExceeded, "assignment child count out of bounds");
    return false;
  }
  assignment.children.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(assignment.children[i].logical_name)) return false;
    std::uint8_t child_kind = 0;
    if (!r.read_u8(child_kind)) return false;
    if (child_kind > static_cast<std::uint8_t>(OutputKind::PreprocessedSource)) {
      r.fail(ErrorCode::Malformed, "child output kind out of domain");
      return false;
    }
    assignment.children[i].kind = static_cast<OutputKind>(child_kind);
    if (!r.read_blob(assignment.children[i].bytes)) return false;
  }
  if (!decode_toolchain(r, assignment.toolchain)) return false;
  if (!decode_target(r, assignment.target)) return false;
  if (!decode_specialization(r, assignment.specialization)) return false;
  if (!decode_policy(r, assignment.policy)) return false;
  if (!decode_environment(r, assignment.environment)) return false;
  if (!decode_validation_requirements(r, assignment.validation)) return false;
  if (!r.read_u64(assignment.max_compile_millis)) return false;
  if (!r.read_bool(assignment.speculative)) return false;
  if (!decode_lease(r, assignment.lease)) return false;
  out = std::move(assignment);
  return r.at_end();
}

Status encode_report_output(const ReportOutput& output, std::vector<std::byte>& out) {
  return finish(
      [&output](CanonicalWriter& w) {
        w.domain("dc.msg.report-output.v1");
        write_authority_claim(w, output.claim);
        w.u8(static_cast<std::uint8_t>(output.kind));
        w.str(output.logical_name);
        w.digest(output.declared_digest);
        w.blob(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
        encode_validation_report(w, output.worker_validation);
        w.str(output.compiler_invocation);
        w.str(output.compiler_version_string);
        w.u64(output.compiler_wall_millis);
        w.u32(static_cast<std::uint32_t>(output.exit_code));
      },
      out);
}

bool decode_report_output(std::span<const std::byte> bytes, ReportOutput& out) {
  CanonicalReader r(bytes);
  ReportOutput output;
  if (!r.read_domain("dc.msg.report-output.v1")) return false;
  if (!read_authority_claim(r, output.claim)) return false;
  std::uint8_t kind = 0;
  if (!r.read_u8(kind)) return false;
  if (kind > static_cast<std::uint8_t>(OutputKind::PreprocessedSource)) {
    r.fail(ErrorCode::Malformed, "output kind out of domain");
    return false;
  }
  output.kind = static_cast<OutputKind>(kind);
  if (!r.read_str(output.logical_name)) return false;
  if (!r.read_digest(output.declared_digest)) return false;
  if (!r.read_blob(output.bytes)) return false;
  if (!decode_validation_report(r, output.worker_validation)) return false;
  if (!r.read_str(output.compiler_invocation)) return false;
  if (!r.read_str(output.compiler_version_string)) return false;
  if (!r.read_u64(output.compiler_wall_millis)) return false;
  std::uint32_t exit_code = 0;
  if (!r.read_u32(exit_code)) return false;
  output.exit_code = static_cast<int>(exit_code);
  out = std::move(output);
  return r.at_end();
}

Status encode_fail_attempt(const AttemptFailure& failure, std::vector<std::byte>& out) {
  return finish(
      [&failure](CanonicalWriter& w) {
        w.domain("dc.msg.fail-attempt.v1");
        write_authority_claim(w, failure.claim);
        w.u16(static_cast<std::uint16_t>(failure.code));
        w.str(failure.detail);
        w.boolean(failure.produced_candidate);
      },
      out);
}

bool decode_fail_attempt(std::span<const std::byte> bytes, AttemptFailure& out) {
  CanonicalReader r(bytes);
  AttemptFailure failure;
  if (!r.read_domain("dc.msg.fail-attempt.v1")) return false;
  if (!read_authority_claim(r, failure.claim)) return false;
  std::uint16_t code = 0;
  if (!r.read_u16(code)) return false;
  if (code > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "failure code out of domain");
    return false;
  }
  failure.code = static_cast<ErrorCode>(code);
  if (!r.read_str(failure.detail)) return false;
  if (!r.read_bool(failure.produced_candidate)) return false;
  out = std::move(failure);
  return r.at_end();
}

Status encode_control(const ControlMessage& control, std::vector<std::byte>& out) {
  return finish([&control](CanonicalWriter& w) { write_control_record(w, control); }, out);
}

bool decode_control(std::span<const std::byte> bytes, ControlMessage& out) {
  CanonicalReader r(bytes);
  ControlMessage control;
  if (!read_control_record(r, control)) return false;
  out = std::move(control);
  return r.at_end();
}

Status encode_commit_message(const CommitMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.commit.v1");
        write_control_record(w, message.control);
        encode_commit(w, message.commit);
      },
      out);
}

bool decode_commit_message(std::span<const std::byte> bytes, CommitMessage& out) {
  CanonicalReader r(bytes);
  CommitMessage message;
  if (!r.read_domain("dc.msg.commit.v1")) return false;
  if (!read_control_record(r, message.control)) return false;
  if (!decode_commit(r, message.commit)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_cache_query(const CacheQueryMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.cache-query.v1");
        w.digest(message.unit_identity);
      },
      out);
}

bool decode_cache_query(std::span<const std::byte> bytes, CacheQueryMessage& out) {
  CanonicalReader r(bytes);
  CacheQueryMessage message;
  if (!r.read_domain("dc.msg.cache-query.v1")) return false;
  if (!r.read_digest(message.unit_identity)) return false;
  out = message;
  return r.at_end();
}

Status encode_cache_report(const CacheReportMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.cache-report.v1");
        w.u8(static_cast<std::uint8_t>(message.decision.outcome));
        w.str(message.decision.reason);
        w.boolean(message.decision.generation_drift);
        w.id(message.decision.entry);
        w.list(static_cast<std::uint32_t>(message.decision.mismatches.size()));
        for (const auto& mismatch : message.decision.mismatches) {
          w.str(mismatch.dimension);
          w.str(mismatch.expected);
          w.str(mismatch.actual);
        }
        w.boolean(!message.entry.unit_identity.is_zero());
        if (!message.entry.unit_identity.is_zero()) encode_cache_entry(w, message.entry);
      },
      out);
}

bool decode_cache_report(std::span<const std::byte> bytes, CacheReportMessage& out) {
  CanonicalReader r(bytes);
  CacheReportMessage message;
  if (!r.read_domain("dc.msg.cache-report.v1")) return false;
  std::uint8_t outcome = 0;
  if (!r.read_u8(outcome)) return false;
  if (outcome > static_cast<std::uint8_t>(CacheOutcome::Miss)) {
    r.fail(ErrorCode::Malformed, "cache outcome out of domain");
    return false;
  }
  message.decision.outcome = static_cast<CacheOutcome>(outcome);
  if (!r.read_str(message.decision.reason)) return false;
  if (!r.read_bool(message.decision.generation_drift)) return false;
  if (!r.read_id(message.decision.entry)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  if (count > 1024) {
    r.fail(ErrorCode::LimitExceeded, "cache mismatch count out of bounds");
    return false;
  }
  message.decision.mismatches.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(message.decision.mismatches[i].dimension)) return false;
    if (!r.read_str(message.decision.mismatches[i].expected)) return false;
    if (!r.read_str(message.decision.mismatches[i].actual)) return false;
  }
  bool has_entry = false;
  if (!r.read_bool(has_entry)) return false;
  if (has_entry && !decode_cache_entry(r, message.entry)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_validate(const ValidateMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.validate.v1");
        w.u32(message.mode);
        w.digest(message.subject);
        w.str(message.nonce);
      },
      out);
}

bool decode_validate(std::span<const std::byte> bytes, ValidateMessage& out) {
  CanonicalReader r(bytes);
  ValidateMessage message;
  if (!r.read_domain("dc.msg.validate.v1")) return false;
  if (!r.read_u32(message.mode)) return false;
  if (message.mode > 1) {
    r.fail(ErrorCode::Malformed, "validate mode out of domain");
    return false;
  }
  if (!r.read_digest(message.subject)) return false;
  if (!r.read_str(message.nonce)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_validate_response(const ValidateResponseMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.validate-response.v1");
        w.u32(message.mode);
        w.u8(static_cast<std::uint8_t>(message.evidence));
        w.digest(message.capabilities_digest);
        w.digest(message.subject);
        w.str(message.detail);
      },
      out);
}

bool decode_validate_response(std::span<const std::byte> bytes, ValidateResponseMessage& out) {
  CanonicalReader r(bytes);
  ValidateResponseMessage message;
  if (!r.read_domain("dc.msg.validate-response.v1")) return false;
  if (!r.read_u32(message.mode)) return false;
  if (message.mode > 1) {
    r.fail(ErrorCode::Malformed, "validate mode out of domain");
    return false;
  }
  std::uint8_t evidence = 0;
  if (!r.read_u8(evidence)) return false;
  if (evidence > static_cast<std::uint8_t>(EvidenceClass::Unsupported)) {
    r.fail(ErrorCode::Malformed, "evidence class out of domain");
    return false;
  }
  message.evidence = static_cast<EvidenceClass>(evidence);
  if (!r.read_digest(message.capabilities_digest)) return false;
  if (!r.read_digest(message.subject)) return false;
  if (!r.read_str(message.detail)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_response(const ResponseMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.response.v1");
        w.u16(static_cast<std::uint16_t>(message.op));
        w.u16(static_cast<std::uint16_t>(message.code));
        w.str(message.detail);
        w.blob(std::span<const std::byte>(message.payload.data(), message.payload.size()));
      },
      out);
}

bool decode_response(std::span<const std::byte> bytes, ResponseMessage& out) {
  CanonicalReader r(bytes);
  ResponseMessage message;
  if (!r.read_domain("dc.msg.response.v1")) return false;
  std::uint16_t op = 0;
  std::uint16_t code = 0;
  if (!r.read_u16(op)) return false;
  if (!r.read_u16(code)) return false;
  if (op > static_cast<std::uint16_t>(Op::ValidateResponse) || code > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "response header out of domain");
    return false;
  }
  message.op = static_cast<Op>(op);
  message.code = static_cast<ErrorCode>(code);
  if (!r.read_str(message.detail)) return false;
  if (!r.read_blob(message.payload)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_submission_response(const SubmissionResponse& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.submission-response.v1");
        w.id(message.request_id);
        w.digest(message.request_identity);
        w.boolean(message.all_committed);
        w.boolean(message.served_from_cache);
        w.boolean(message.duplicate_request);
        w.list(static_cast<std::uint32_t>(message.units.size()));
        for (const auto& unit : message.units) {
          w.u32(unit.index);
          w.id(unit.compilation);
          w.id(unit.unit);
          w.gen(unit.unit_generation);
          w.digest(unit.unit_identity);
          w.u8(static_cast<std::uint8_t>(unit.state));
          w.u8(static_cast<std::uint8_t>(unit.cache.outcome));
          w.str(unit.cache.reason);
          w.boolean(unit.committed);
          w.boolean(unit.scheduled);
          w.str(unit.detail);
          w.boolean(!unit.commit.id.is_zero());
          if (!unit.commit.id.is_zero()) encode_commit(w, unit.commit);
        }
      },
      out);
}

bool decode_submission_response(std::span<const std::byte> bytes, SubmissionResponse& out) {
  CanonicalReader r(bytes);
  SubmissionResponse message;
  if (!r.read_domain("dc.msg.submission-response.v1")) return false;
  if (!r.read_id(message.request_id)) return false;
  if (!r.read_digest(message.request_identity)) return false;
  if (!r.read_bool(message.all_committed)) return false;
  if (!r.read_bool(message.served_from_cache)) return false;
  if (!r.read_bool(message.duplicate_request)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  if (count > 65536) {
    r.fail(ErrorCode::LimitExceeded, "submission response unit count out of bounds");
    return false;
  }
  message.units.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    UnitSubmission& unit = message.units[i];
    if (!r.read_u32(unit.index)) return false;
    if (!r.read_id(unit.compilation)) return false;
    if (!r.read_id(unit.unit)) return false;
    if (!r.read_gen(unit.unit_generation)) return false;
    if (!r.read_digest(unit.unit_identity)) return false;
    std::uint8_t state = 0;
    if (!r.read_u8(state)) return false;
    if (state > static_cast<std::uint8_t>(CompilationState::Retired)) {
      r.fail(ErrorCode::Malformed, "compilation state out of domain");
      return false;
    }
    unit.state = static_cast<CompilationState>(state);
    std::uint8_t outcome = 0;
    if (!r.read_u8(outcome)) return false;
    if (outcome > static_cast<std::uint8_t>(CacheOutcome::Miss)) {
      r.fail(ErrorCode::Malformed, "cache outcome out of domain");
      return false;
    }
    unit.cache.outcome = static_cast<CacheOutcome>(outcome);
    if (!r.read_str(unit.cache.reason)) return false;
    if (!r.read_bool(unit.committed)) return false;
    if (!r.read_bool(unit.scheduled)) return false;
    if (!r.read_str(unit.detail)) return false;
    bool has_commit = false;
    if (!r.read_bool(has_commit)) return false;
    if (has_commit && !decode_commit(r, unit.commit)) return false;
  }
  out = std::move(message);
  return r.at_end();
}

Status encode_commit_response(const CommitResponse& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.commit-response.v1");
        w.u8(static_cast<std::uint8_t>(message.outcome));
        w.u16(static_cast<std::uint16_t>(message.error));
        w.str(message.detail);
        w.boolean(message.artifact_authoritative);
        w.boolean(!message.commit.id.is_zero());
        if (!message.commit.id.is_zero()) encode_commit(w, message.commit);
        encode_validation_report(w, message.validation);
      },
      out);
}

bool decode_commit_response(std::span<const std::byte> bytes, CommitResponse& out) {
  CanonicalReader r(bytes);
  CommitResponse message;
  if (!r.read_domain("dc.msg.commit-response.v1")) return false;
  std::uint8_t outcome = 0;
  if (!r.read_u8(outcome)) return false;
  if (outcome > static_cast<std::uint8_t>(CommitOutcome::ReproducibilityViolation)) {
    r.fail(ErrorCode::Malformed, "commit outcome out of domain");
    return false;
  }
  message.outcome = static_cast<CommitOutcome>(outcome);
  std::uint16_t error = 0;
  if (!r.read_u16(error)) return false;
  if (error > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "commit error out of domain");
    return false;
  }
  message.error = static_cast<ErrorCode>(error);
  if (!r.read_str(message.detail)) return false;
  if (!r.read_bool(message.artifact_authoritative)) return false;
  bool has_commit = false;
  if (!r.read_bool(has_commit)) return false;
  if (has_commit && !decode_commit(r, message.commit)) return false;
  if (!decode_validation_report(r, message.validation)) return false;
  out = std::move(message);
  return r.at_end();
}

Status encode_query(const QueryMessage& message, std::vector<std::byte>& out) {
  return finish(
      [&message](CanonicalWriter& w) {
        w.domain("dc.msg.query.v1");
        w.u32(message.kind);
        w.u64(message.id);
        w.digest(message.identity);
      },
      out);
}

bool decode_query(std::span<const std::byte> bytes, QueryMessage& out) {
  CanonicalReader r(bytes);
  QueryMessage message;
  if (!r.read_domain("dc.msg.query.v1")) return false;
  if (!r.read_u32(message.kind)) return false;
  if (message.kind > 9) {
    r.fail(ErrorCode::Malformed, "query kind out of domain");
    return false;
  }
  if (!r.read_u64(message.id)) return false;
  if (!r.read_digest(message.identity)) return false;
  out = std::move(message);
  return r.at_end();
}

// ---------------------------------------------------------------------------
// Deterministic rendering helpers
// ---------------------------------------------------------------------------
std::string render_compilation(const CompilationRecord& record) {
  std::string out;
  out += "compilation " + std::to_string(record.id.value()) + "\n";
  out += "  generation " + std::to_string(record.generation.value()) + "\n";
  out += "  state " + std::string(to_string(record.state)) + "\n";
  out += "  unit " + std::to_string(record.unit.value()) + " index " + std::to_string(record.unit_index) + "\n";
  out += "  output " + std::string(to_string(record.output_kind)) + "\n";
  out += "  reproducibility " + std::string(to_string(record.reproducibility)) + "\n";
  out += "  unit identity " + record.unit_identity.hex() + "\n";
  out += "  request identity " + record.request_identity.hex() + "\n";
  out += "  source identity " + record.source_identity.hex() + "\n";
  out += "  dependency identity " + record.dependency_identity.hex() + "\n";
  out += "  toolchain identity " + record.toolchain_identity.hex() + "\n";
  out += "  target identity " + record.target_identity.hex() + "\n";
  out += "  specialization identity " + record.specialization_identity.hex() + "\n";
  out += "  policy identity " + record.policy_identity.hex() + "\n";
  out += "  attempts " + std::to_string(record.attempts.size());
  for (CompilationAttemptId id : record.attempts) out += " " + std::to_string(id.value());
  out += "\n";
  out += "  cache hit " + std::string(record.cache_hit ? "yes" : "no") + "\n";
  if (record.reproducibility_violation) out += "  reproducibility violation yes\n";
  if (record.failure != ErrorCode::Ok) out += "  failure " + std::string(to_string(record.failure)) + "\n";
  return out;
}

std::string render_attempt(const CompilationAttempt& attempt) {
  std::string out;
  out += "attempt " + std::to_string(attempt.id.value()) + "\n";
  out += "  generation " + std::to_string(attempt.generation.value()) + "\n";
  out += "  compilation " + std::to_string(attempt.compilation.value()) + "\n";
  out += "  state " + std::string(to_string(attempt.state)) + "\n";
  out += "  ordinal " + std::to_string(attempt.ordinal) + "\n";
  out += "  worker " + std::to_string(attempt.worker.value()) + " boot " +
         std::to_string(attempt.worker_boot.value()) + "\n";
  out += "  lease " + std::to_string(attempt.lease.value()) + " generation " +
         std::to_string(attempt.lease_generation.value()) + "\n";
  out += "  epoch " + std::to_string(attempt.epoch.value()) + "\n";
  if (!attempt.candidate.digest.is_zero()) {
    out += "  candidate " + attempt.candidate.digest.hex() + " size " +
           std::to_string(attempt.candidate.size) + "\n";
  }
  if (attempt.failure != ErrorCode::Ok) {
    out += "  failure " + std::string(to_string(attempt.failure)) + " " + attempt.failure_detail + "\n";
  }
  if (!attempt.validation.checks.empty()) {
    out += "  validation " + std::string(to_string(attempt.validation.aggregate)) + "\n";
    for (const auto& check : attempt.validation.checks) {
      out += "    " + check.check + ": " + std::string(to_string(check.outcome)) + " " + check.detail + "\n";
    }
  }
  return out;
}

std::string render_worker(const WorkerRecord& worker) {
  std::string out;
  out += "worker " + std::to_string(worker.id.value()) + "\n";
  out += "  boot " + std::to_string(worker.boot.value()) + " generation " +
         std::to_string(worker.generation.value()) + "\n";
  out += "  endpoint " + worker.endpoint + " host " + worker.host + "\n";
  out += "  health " + std::string(to_string(worker.health)) + (worker.ready ? " ready" : " not-ready") + "\n";
  out += "  fenced " + std::string(worker.fenced ? "yes" : "no") + "\n";
  out += "  evidence " + std::string(to_string(worker.capabilities.evidence)) + "\n";
  out += "  toolchains " + std::to_string(worker.capabilities.toolchains.size()) + " targets " +
         std::to_string(worker.capabilities.targets.size()) + "\n";
  for (const auto& toolchain : worker.capabilities.toolchains) {
    out += "    toolchain " + std::string(to_string(toolchain.family)) + " " + toolchain.version_string +
           " identity " + toolchain.identity_digest.hex().substr(0, 16) + " evidence " +
           std::string(to_string(toolchain.evidence)) + "\n";
  }
  for (const auto& target : worker.capabilities.targets) {
    out += "    target " + target.triple + " identity " + target.identity_digest.hex().substr(0, 16) + "\n";
  }
  out += "  in-flight " + std::to_string(worker.in_flight) + " completed " +
         std::to_string(worker.completed_units) + " failed " + std::to_string(worker.failed_units) + "\n";
  return out;
}

std::string render_cache_decision(const CacheDecision& decision) {
  std::string out;
  out += "cache outcome " + std::string(to_string(decision.outcome)) + "\n";
  out += "  entry " + std::to_string(decision.entry.value()) + "\n";
  out += "  reason " + decision.reason + "\n";
  if (decision.generation_drift) out += "  generation drift observed\n";
  for (const auto& mismatch : decision.mismatches) {
    out += "  mismatch " + mismatch.dimension + ": expected " + mismatch.expected + " actual " +
           mismatch.actual + "\n";
  }
  return out;
}

std::string render_commit(const ArtifactCommit& commit) {
  std::string out;
  out += "commit " + std::to_string(commit.id.value()) + "\n";
  out += "  compilation " + std::to_string(commit.compilation.value()) + " generation " +
         std::to_string(commit.compilation_generation.value()) + "\n";
  out += "  artifact digest " + commit.artifact_digest.hex() + "\n";
  out += "  epoch " + std::to_string(commit.epoch.value()) + "\n";
  out += "  worker " + std::to_string(commit.worker.value()) + " boot " +
         std::to_string(commit.worker_boot.value()) + "\n";
  out += "  attempt " + std::to_string(commit.attempt.value()) + "\n";
  out += "  provenance " + std::to_string(commit.provenance.value()) + " validation " +
         std::to_string(commit.validation.value()) + "\n";
  if (commit.deduplicated) out += "  deduplicated yes\n";
  if (commit.superseded) out += "  superseded yes\n";
  return out;
}

std::string render_provenance(const Provenance& provenance) {
  std::string out;
  out += "provenance " + std::to_string(provenance.id.value()) + "\n";
  out += "  evidence " + std::string(to_string(provenance.evidence)) + "\n";
  out += "  compilation " + std::to_string(provenance.compilation.value()) + " attempt " +
         std::to_string(provenance.attempt.value()) + "\n";
  out += "  worker " + std::to_string(provenance.worker.value()) + " boot " +
         std::to_string(provenance.worker_boot.value()) + "\n";
  out += "  epoch " + std::to_string(provenance.epoch.value()) + "\n";
  out += "  artifact " + provenance.artifact.digest.hex() + " size " +
         std::to_string(provenance.artifact.size) + "\n";
  out += "  toolchain " + provenance.toolchain_identity.hex() + "\n";
  out += "  target " + provenance.target_identity.hex() + "\n";
  out += "  dependencies " + provenance.dependency_identity.hex() + "\n";
  out += "  source " + provenance.source_identity.hex() + "\n";
  out += "  compiler " + provenance.compiler_version_string + "\n";
  out += "  invocation " + provenance.compiler_invocation + "\n";
  return out;
}

}  // namespace dc
