// Distributed Compilation - dc_cli: inspection, submission and proof.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <cstdio>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "app_common.hpp"
#include "client.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/persistence.hpp"
#include "dc/process.hpp"
#include "dc/wire.hpp"

// Implemented in dc_cli_demo.cpp, dc_cli_cuda.cpp and dc_cli_proof.cpp.
int run_demo_command(const dc::app::Arguments& arguments, const std::string& scenario);
int run_cuda_proof(const dc::app::Arguments& arguments);
int run_verify_command(const dc::app::Arguments& arguments);

namespace {

using namespace dc;
using namespace dc::app;

std::string usage() {
  return
      "usage: dc_cli [--coordinator host:port] <command> [options]\n"
      "\n"
      "  worker list | worker show <id>\n"
      "  toolchain list [--discover] [--synthetic] [--cuda]\n"
      "  toolchain show <index>\n"
      "  compile submit --source <file> [--source <file> ...] [--link] [--output <kind>]\n"
      "                 [--toolchain <family|path|auto>] [--target <triple|sm_120>]\n"
      "                 [--flag <flag>] [--spec <name>=<value>] [--dep <name>=<file>]\n"
      "                 [--include-dir <dir>] [--repro required|preferred|not-required]\n"
      "                 [--cache read-write|read-only|bypass] [--force-rebuild] [--dry-run]\n"
      "                 [--smoke-stdout <text>] [--no-wait]\n"
      "  compile show <compilation-id>\n"
      "  compile explain <compilation-id>\n"
      "  attempt list | attempt show <id>\n"
      "  cache query <unit-identity-hex> | cache explain <compilation-id>\n"
      "  artifact show <compilation-id> | artifact verify <compilation-id> [--output <file>]\n"
      "  provenance list | provenance show <provenance-id>\n"
      "  reproducibility show <compilation-id>\n"
      "  cancel <compilation-id>\n"
      "  snapshot | audit | state info\n"
      "  verify [--offline]\n"
      "  probe-process --exe <path> [--arg X] [--cwd DIR] [--env K=V] [--inherit-env]\n"
      "  demo <native|multiprocess|synthetic|cache|cuda|all> [--only <case>]\n"
      "  cuda-proof [--toolkit <root>] [--arch sm_120]\n";
}

// ---------------------------------------------------------------------------
// Local (offline) request construction, used by submit and by verify
// ---------------------------------------------------------------------------
struct BuiltRequest {
  CompilationRequest request;
  std::vector<Blob> blobs;
  std::vector<std::string> notes;
};

Result<BuiltRequest> build_request(const Arguments& arguments, const DiscoveryResult& discovered) {
  BuiltRequest built;
  const std::vector<std::string> sources = arguments.all("source");
  if (sources.empty()) {
    return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument, "at least one --source is required"));
  }

  OutputKind requested_output = OutputKind::Object;
  const std::string output_hint = arguments.get("output", "object");
  if (output_hint == "exe" || output_hint == "executable") {
    requested_output = OutputKind::Executable;
  } else if (output_hint == "cubin") {
    requested_output = OutputKind::Cubin;
  } else if (output_hint == "ptx") {
    requested_output = OutputKind::Ptx;
  } else if (output_hint == "asm" || output_hint == "assembly") {
    requested_output = OutputKind::Assembly;
  }
  InputFormat first_format = InputFormat::Unknown;
  if (!sources.empty()) first_format = input_format_from_extension(sources.front());

  const ToolchainIdentity* toolchain =
      pick_toolchain_for(discovered.toolchains, arguments.get("toolchain", "auto"), first_format,
                         requested_output, arguments.has("cuda"));
  if (toolchain == nullptr) {
    return Result<BuiltRequest>(Status::error(ErrorCode::NotFound,
                                              "no toolchain can perform this compilation; pass --toolchain"));
  }
  std::string target_selector = arguments.get("target");
  if (target_selector.empty()) {
    target_selector = toolchain->family == CompilerFamily::NvidiaNvcc ? "sm_120" : "x86_64-pc-windows-msvc";
  }
  const TargetIdentity* target = pick_target(discovered.targets, target_selector);
  if (target == nullptr) {
    return Result<BuiltRequest>(Status::error(ErrorCode::NotFound, "no target matched the selector"));
  }

  built.request.toolchain = *toolchain;
  built.request.target = *target;
  built.request.request_id = RequestId(mix64(static_cast<std::uint64_t>(SystemClock().now()) ^
                                             static_cast<std::uint64_t>(sources.size())));
  built.request.authority_generation = Digest256{};

  OutputKind output_kind = OutputKind::Object;
  const std::string output_text = arguments.get("output", "object");
  if (output_text == "exe" || output_text == "executable") {
    output_kind = OutputKind::Executable;
  } else if (output_text == "obj" || output_text == "object") {
    output_kind = OutputKind::Object;
  } else if (output_text == "cubin") {
    output_kind = OutputKind::Cubin;
  } else if (output_text == "ptx") {
    output_kind = OutputKind::Ptx;
  } else if (output_text == "asm" || output_text == "assembly") {
    output_kind = OutputKind::Assembly;
  } else if (output_text == "static" || output_text == "static-library") {
    output_kind = OutputKind::StaticLibrary;
  } else if (!parse_output_kind(output_text, output_kind)) {
    return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument, "unknown output kind: " + output_text));
  }

  ReproducibilityRequirement reproducibility = ReproducibilityRequirement::Preferred;
  const std::string repro_text = arguments.get("repro", "preferred");
  if (!parse_reproducibility(repro_text == "not-required" ? "NOT_REQUIRED"
                                                          : (repro_text == "required" ? "REQUIRED" : "PREFERRED"),
                             reproducibility)) {
    return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument, "unknown reproducibility mode"));
  }
  built.request.policy.reproducibility = reproducibility;
  const std::string cache_text = arguments.get("cache", "read-write");
  CachePolicy cache_policy = CachePolicy::ReadWrite;
  parse_cache_policy(cache_text == "read-only" ? "READ_ONLY" : (cache_text == "bypass" ? "BYPASS" : "READ_WRITE"),
                     cache_policy);
  built.request.policy.cache = cache_policy;
  built.request.policy.require_provable_toolchain = !arguments.has("allow-synthetic");
  built.request.policy.allow_speculative_duplication = arguments.has("speculative");
  built.request.policy.negative_cache_enabled = arguments.has("negative-cache");

  for (const auto& flag : arguments.all("flag")) built.request.flags.push_back(flag);
  for (const auto& spec : arguments.all("spec")) {
    const std::size_t equals = spec.find('=');
    if (equals == std::string::npos) {
      return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument, "--spec must be name=value"));
    }
    const std::string name = spec.substr(0, equals);
    const std::string value = spec.substr(equals + 1);
    try {
      const long long parsed = std::stoll(value);
      built.request.specialization.fields.push_back(SpecField::make_signed(name, parsed));
    } catch (...) {
      built.request.specialization.fields.push_back(SpecField::make_text(name, value));
    }
  }

  if (arguments.has("smoke-stdout")) {
    built.request.validation.require_smoke_test = true;
    built.request.validation.smoke_expected_stdout = arguments.get("smoke-stdout");
  }

  // Units: one compile unit per source, plus an optional link unit.
  std::vector<std::string> include_dirs = arguments.all("include-dir");
  std::uint32_t index = 0;
  std::vector<std::pair<std::uint32_t, std::string>> compile_units;
  for (const auto& source_path : sources) {
    Blob blob;
    std::string error;
    if (!read_blob_file(source_path, blob, 64ull * 1024 * 1024, error)) {
      return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument, "cannot read source: " + error));
    }
    CompilationUnitSpec unit;
    unit.index = index++;
    std::filesystem::path path(source_path);
    unit.logical_name = path.filename().string();
    unit.kind = UnitKind::Compile;
    unit.output_kind = output_kind == OutputKind::Executable ? OutputKind::Object : output_kind;
    UnitSource unit_source;
    unit_source.logical_name = unit.logical_name;
    unit_source.format = input_format_from_extension(unit.logical_name);
    unit_source.language_mode = unit_source.format == InputFormat::Source &&
                                        unit.logical_name.find(".cu") != std::string::npos
                                    ? "cuda-c++17"
                                    : "c++20";
    unit_source.content = ref_of(blob);
    unit.sources.push_back(unit_source);
    built.blobs.push_back(std::move(blob));
    compile_units.emplace_back(unit.index, unit.logical_name);
    built.request.units.push_back(std::move(unit));
  }

  // Explicit dependencies.
  std::vector<std::pair<std::string, std::string>> dependency_specs;
  for (const auto& dep : arguments.all("dep")) {
    const std::size_t equals = dep.find('=');
    if (equals == std::string::npos) {
      return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument, "--dep must be name=file"));
    }
    dependency_specs.emplace_back(dep.substr(0, equals), dep.substr(equals + 1));
  }

  // Quoted-include discovery, bounded and deterministic.
  if (!include_dirs.empty()) {
    const std::size_t max_files = 512;
    const std::size_t max_depth = 16;
    std::set<std::string> seen;
    std::vector<std::pair<std::string, std::filesystem::path>> queue;
    for (const auto& unit : built.request.units) {
      for (const auto& source : unit.sources) queue.emplace_back(source.logical_name, std::filesystem::path());
    }
    for (std::size_t cursor = 0; cursor < queue.size() && seen.size() < max_files; ++cursor) {
      const std::string name = queue[cursor].first;
      if (name.find("..") != std::string::npos) continue;
      std::filesystem::path resolved;
      if (!queue[cursor].second.empty()) {
        resolved = queue[cursor].second;
      } else {
        for (const auto& dir : include_dirs) {
          const std::filesystem::path candidate = std::filesystem::path(dir) / name;
          std::error_code ec;
          if (std::filesystem::is_regular_file(candidate, ec) && !ec) {
            resolved = candidate;
            break;
          }
        }
      }
      if (resolved.empty()) continue;
      Blob blob;
      std::string error;
      if (!read_blob_file(resolved, blob, 16ull * 1024 * 1024, error)) continue;
      const std::string text(reinterpret_cast<const char*>(blob.bytes.data()), blob.bytes.size());
      std::size_t cursor_in_text = 0;
      while (true) {
        const std::size_t at = text.find("#include \"", cursor_in_text);
        if (at == std::string::npos) break;
        const std::size_t begin = at + 10;
        const std::size_t end = text.find('"', begin);
        if (end == std::string::npos) break;
        cursor_in_text = end + 1;
        const std::string included = text.substr(begin, end - begin);
        if (included.empty() || included.size() > 260) continue;
        std::size_t depth = 0;
        for (char c : included) {
          if (c == '/' || c == '\\') ++depth;
        }
        if (depth > max_depth) continue;
        if (!seen.insert(included).second) continue;
        if (seen.size() > max_files) break;
        queue.emplace_back(included, std::filesystem::path());
        dependency_specs.emplace_back(included, (std::filesystem::path(resolved).parent_path() / included).string());
        const Digest256 digest = blob.digest;
        (void)digest;
      }
      if (!resolved.empty() && seen.insert(resolved.filename().string()).second) {
        // record the scanned file itself when it is not already a dependency
      }
    }
    built.notes.push_back("include scan resolved " + std::to_string(seen.size()) + " names");
  }

  for (const auto& dep : dependency_specs) {
    Blob blob;
    std::string error;
    if (!read_blob_file(dep.second, blob, 64ull * 1024 * 1024, error)) {
      return Result<BuiltRequest>(Status::error(ErrorCode::InvalidArgument,
                                                "cannot read dependency '" + dep.first + "': " + error));
    }
    DependencyEntry entry;
    entry.name = dep.first;
    entry.kind = DependencyKind::Header;
    entry.content = ref_of(blob);
    built.request.dependencies.entries.push_back(entry);
    built.blobs.push_back(std::move(blob));
    for (auto& unit : built.request.units) {
      DependencyEntry copy = entry;
      unit.dependencies.push_back(copy);
    }
  }

  if (arguments.has("link")) {
    CompilationUnitSpec link;
    link.index = index++;
    link.logical_name = "link:artifact";
    link.kind = UnitKind::Link;
    link.output_kind = output_kind;
    for (const auto& compile : compile_units) link.child_units.push_back(compile.first);
    // A link unit carries no source of its own: its identity binds the child
    // unit identities, and its payload arrives as committed child artifacts.
    built.request.units.push_back(std::move(link));
  }

  Status canonical = canonicalize(built.request);
  if (!canonical.ok()) return Result<BuiltRequest>(canonical);
  return Result<BuiltRequest>(std::move(built));
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------
int command_submit(const Arguments& arguments, const std::string& endpoint) {
  DiscoveryOptions options;
  options.msvc_roots = default_msvc_roots();
  options.cuda_roots = arguments.has("no-cuda") ? std::vector<std::filesystem::path>{} : default_cuda_roots();
  options.include_synthetic = arguments.has("allow-synthetic");
  for (const auto& architecture : arguments.all("cuda-arch")) options.cuda_architectures.push_back(architecture);
  if (options.cuda_architectures.empty()) options.cuda_architectures.push_back("sm_120");
  const DiscoveryResult discovered = discover_toolchains(options);

  auto built = build_request(arguments, discovered);
  if (!built.ok()) {
    emit_error("dc_cli: " + built.status().describe());
    return 2;
  }
  for (const auto& note : built.value().notes) emit("note: " + note);

  auto client = Client::connect(endpoint, SessionRole::Client, "dc-cli");
  if (!client.ok()) {
    emit_error("dc_cli: cannot connect to " + endpoint + ": " + client.status().describe());
    return 3;
  }

  SubmitMessage message;
  message.request = built.value().request;
  message.blobs = built.value().blobs;
  message.dry_run = arguments.has("dry-run");
  message.force_rebuild = arguments.has("force-rebuild");
  std::vector<std::byte> payload;
  encode_submit(message, payload);

  emit("canonical request identity: " + built.value().request.request_identity.hex());
  emit("toolchain identity: " + built.value().request.toolchain.identity_digest.hex() + " (" +
       std::string(to_string(built.value().request.toolchain.family)) + " " +
       built.value().request.toolchain.version_string + ")");
  emit("target identity: " + built.value().request.target.identity_digest.hex() + " (" +
       built.value().request.target.triple + ")");

  auto response = client.value().call(Op::SubmitCompilation, payload);
  if (!response.ok()) {
    emit_error("dc_cli: submission failed: " + response.status().describe());
    return 4;
  }
  ResponseMessage reply = response.value();
  if (reply.code != ErrorCode::Ok) {
    emit_error("dc_cli: submission refused: " + std::string(to_string(reply.code)) + ": " + reply.detail);
    return 4;
  }
  SubmissionResponse submission;
  if (!decode_submission_response(std::span<const std::byte>(reply.payload.data(), reply.payload.size()),
                                  submission)) {
    emit_error("dc_cli: malformed submission response");
    return 4;
  }
  for (const auto& unit : submission.units) {
    emit("unit " + std::to_string(unit.index) + " compilation=" + std::to_string(unit.compilation.value()) +
         " unit-identity=" + unit.unit_identity.hex() + " state=" +
         std::string(to_string(unit.state)) + " cache=" + std::string(to_string(unit.cache.outcome)));
    emit("  detail: " + unit.detail);
    if (unit.committed) {
      emit("  authoritative artifact: " + unit.commit.artifact_digest.hex());
    }
  }
  if (submission.served_from_cache) emit("served from validated cache reuse");
  if (submission.all_committed) {
    emit("DC_CLI_SUBMIT committed=yes");
    client.value().close();
    return 0;
  }
  if (arguments.has("dry-run") || arguments.has("no-wait")) {
    emit("DC_CLI_SUBMIT committed=no (not waiting)");
    client.value().close();
    return 0;
  }

  // Wait for completion by polling compilation state.
  const std::uint64_t deadline = static_cast<std::uint64_t>(SystemClock().now()) + 300000;
  bool all_committed = false;
  bool failed = false;
  std::string failure_detail;
  while (static_cast<std::uint64_t>(SystemClock().now()) < deadline) {
    all_committed = true;
    failed = false;
    for (const auto& unit : submission.units) {
      QueryMessage query;
      query.kind = 0;
      query.id = unit.compilation.value();
      std::vector<std::byte> query_payload;
      encode_query(query, query_payload);
      auto record = client.value().call(Op::Query, query_payload);
      if (!record.ok()) {
        emit_error("dc_cli: query failed: " + record.status().describe());
        failed = true;
        failure_detail = record.status().describe();
        break;
      }
      ResponseMessage query_reply = record.value();
      if (query_reply.code != ErrorCode::Ok) {
        failed = true;
        failure_detail = query_reply.detail;
        break;
      }
      const std::string text(reinterpret_cast<const char*>(query_reply.payload.data()),
                             query_reply.payload.size());
      if (text.find("state Committed") != std::string::npos) continue;
      if (text.find("state Failed") != std::string::npos || text.find("state Cancelled") != std::string::npos ||
          text.find("state Ambiguous") != std::string::npos) {
        failed = true;
        failure_detail = text;
        break;
      }
      all_committed = false;
    }
    if (all_committed || failed) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }

  client.value().close();
  if (failed) {
    emit_error("dc_cli: compilation did not complete: " + failure_detail);
    return 5;
  }
  if (!all_committed) {
    emit_error("dc_cli: compilation did not complete before the wait deadline");
    return 5;
  }
  for (const auto& unit : submission.units) {
    QueryMessage query;
    query.kind = 0;
    query.id = unit.compilation.value();
    std::vector<std::byte> query_payload;
    encode_query(query, query_payload);
    auto record = client.value().call(Op::Query, query_payload);
    (void)record;
  }
  emit("DC_CLI_SUBMIT committed=yes");
  return 0;
}

int command_query(const Arguments& arguments, const std::string& endpoint, std::uint32_t kind) {
  auto client = Client::connect(endpoint, SessionRole::Client, "dc-cli");
  if (!client.ok()) {
    emit_error("dc_cli: cannot connect to " + endpoint + ": " + client.status().describe());
    return 3;
  }
  QueryMessage query;
  query.kind = kind;
  if (!arguments.positional.empty()) {
    try {
      query.id = static_cast<std::uint64_t>(std::stoull(arguments.positional.front()));
    } catch (...) {
      emit_error("dc_cli: identifier must be numeric");
      return 2;
    }
  }
  std::vector<std::byte> payload;
  encode_query(query, payload);
  auto response = client.value().call(Op::Query, payload);
  if (!response.ok()) {
    emit_error("dc_cli: " + response.status().describe());
    return 4;
  }
  ResponseMessage reply = response.value();
  if (reply.code != ErrorCode::Ok) {
    emit_error("dc_cli: " + std::string(to_string(reply.code)) + ": " + reply.detail);
    return 4;
  }
  const std::string text(reinterpret_cast<const char*>(reply.payload.data()), reply.payload.size());
  std::fwrite(text.data(), 1, text.size(), stdout);
  std::fflush(stdout);
  client.value().close();
  return 0;
}

int command_cache_query(const Arguments& arguments, const std::string& endpoint) {
  if (arguments.positional.empty()) {
    emit_error("dc_cli: cache query requires a unit identity digest");
    return 2;
  }
  Digest256 identity;
  if (!Digest256::parse_hex(arguments.positional.front(), identity)) {
    emit_error("dc_cli: unit identity must be 64 hex characters");
    return 2;
  }
  auto client = Client::connect(endpoint, SessionRole::Client, "dc-cli");
  if (!client.ok()) {
    emit_error("dc_cli: cannot connect to " + endpoint + ": " + client.status().describe());
    return 3;
  }
  CacheQueryMessage message;
  message.unit_identity = identity;
  std::vector<std::byte> payload;
  encode_cache_query(message, payload);
  auto response = client.value().call(Op::CacheQuery, payload);
  if (!response.ok()) {
    emit_error("dc_cli: " + response.status().describe());
    return 4;
  }
  CacheReportMessage report;
  if (!decode_cache_report(std::span<const std::byte>(response.value().payload.data(),
                                                      response.value().payload.size()),
                           report)) {
    emit_error("dc_cli: malformed cache report");
    return 4;
  }
  const std::string rendered = render_cache_decision(report.decision);
  std::fwrite(rendered.data(), 1, rendered.size(), stdout);
  std::fflush(stdout);
  client.value().close();
  return report.decision.reusable() ? 0 : 1;
}

int command_artifact(const Arguments& arguments, const std::string& endpoint, bool verify_only) {
  if (arguments.positional.empty()) {
    emit_error("dc_cli: artifact command requires a compilation id");
    return 2;
  }
  std::uint64_t id = 0;
  try {
    id = static_cast<std::uint64_t>(std::stoull(arguments.positional.front()));
  } catch (...) {
    emit_error("dc_cli: compilation id must be numeric");
    return 2;
  }
  auto client = Client::connect(endpoint, SessionRole::Client, "dc-cli");
  if (!client.ok()) {
    emit_error("dc_cli: cannot connect to " + endpoint + ": " + client.status().describe());
    return 3;
  }
  QueryMessage query;
  query.kind = 8;
  query.id = id;
  std::vector<std::byte> payload;
  encode_query(query, payload);
  auto response = client.value().call(Op::Query, payload);
  if (!response.ok()) {
    emit_error("dc_cli: " + response.status().describe());
    return 4;
  }
  ResponseMessage reply = response.value();
  if (reply.code != ErrorCode::Ok) {
    emit_error("dc_cli: " + std::string(to_string(reply.code)) + ": " + reply.detail);
    return 4;
  }
  const Digest256 digest = sha256(std::span<const std::byte>(reply.payload.data(), reply.payload.size()));
  emit("artifact bytes: " + std::to_string(reply.payload.size()));
  emit("artifact digest: " + digest.hex());
  if (!verify_only) {
    const std::string output = arguments.get("output");
    if (!output.empty()) {
      Status written = write_file_atomic(output, std::span<const std::byte>(reply.payload.data(),
                                                                            reply.payload.size()),
                                         false);
      if (!written.ok()) {
        emit_error("dc_cli: cannot write artifact: " + written.describe());
        return 5;
      }
      emit("artifact written to " + output);
    }
  }
  client.value().close();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Arguments arguments = Arguments::parse(argc, argv, 1);
  if (arguments.positional.empty()) {
    emit(usage());
    return 2;
  }
  const std::string endpoint = arguments.get("coordinator", "127.0.0.1:9600");
  const std::string command = arguments.positional.front();
  std::vector<std::string> rest(arguments.positional.begin() + 1, arguments.positional.end());
  Arguments sub = arguments;
  sub.positional = rest;

  if (command == "help" || command == "--help") {
    emit(usage());
    return 0;
  }
  if (command == "compile") {
    if (rest.empty()) {
      emit_error("dc_cli: compile requires submit|show|explain");
      return 2;
    }
    if (rest.front() == "submit") {
      Arguments submit_args = arguments;
      submit_args.positional.clear();
      return command_submit(submit_args, endpoint);
    }
    if (rest.front() == "show") return command_query(sub, endpoint, 0);
    if (rest.front() == "explain") return command_query(sub, endpoint, 9);
    emit_error("dc_cli: unknown compile subcommand");
    return 2;
  }
  if (command == "attempt") {
    if (!rest.empty() && rest.front() == "list") return command_query(sub, endpoint, 2);
    return command_query(sub, endpoint, 1);
  }
  if (command == "worker") {
    if (!rest.empty() && rest.front() == "show") return command_query(sub, endpoint, 3);
    return command_query(sub, endpoint, 3);
  }
  if (command == "cache") {
    if (!rest.empty() && rest.front() == "query") return command_cache_query(sub, endpoint);
    return command_query(sub, endpoint, 4);
  }
  if (command == "artifact") {
    if (!rest.empty() && rest.front() == "verify") return command_artifact(sub, endpoint, true);
    return command_artifact(sub, endpoint, false);
  }
  if (command == "provenance") {
    if (!rest.empty() && rest.front() == "show") return command_query(sub, endpoint, 6);
    return command_query(sub, endpoint, 6);
  }
  if (command == "reproducibility") return command_query(sub, endpoint, 0);
  if (command == "audit") {
    auto client = Client::connect(endpoint, SessionRole::Client, "dc-cli");
    if (!client.ok()) {
      emit_error("dc_cli: cannot connect: " + client.status().describe());
      return 3;
    }
    std::vector<std::byte> empty;
    auto response = client.value().call(Op::Audit, empty);
    if (!response.ok()) {
      emit_error("dc_cli: " + response.status().describe());
      return 4;
    }
    const std::string text(reinterpret_cast<const char*>(response.value().payload.data()),
                           response.value().payload.size());
    std::fwrite(text.data(), 1, text.size(), stdout);
    const bool clean = response.value().code == ErrorCode::Ok;
    client.value().close();
    emit(clean ? "DC_CLI_AUDIT clean=yes" : "DC_CLI_AUDIT clean=no");
    return clean ? 0 : 6;
  }
  if (command == "snapshot") {
    auto client = Client::connect(endpoint, SessionRole::Admin, "dc-cli");
    if (!client.ok()) {
      emit_error("dc_cli: cannot connect: " + client.status().describe());
      return 3;
    }
    std::vector<std::byte> empty;
    auto response = client.value().call(Op::Snapshot, empty);
    if (!response.ok()) {
      emit_error("dc_cli: " + response.status().describe());
      return 4;
    }
    client.value().close();
    emit(response.value().code == ErrorCode::Ok ? "snapshot written" : "snapshot failed: " + response.value().detail);
    return response.value().code == ErrorCode::Ok ? 0 : 4;
  }
  if (command == "cancel") {
    if (rest.empty()) {
      emit_error("dc_cli: cancel requires a compilation id");
      return 2;
    }
    auto client = Client::connect(endpoint, SessionRole::Admin, "dc-cli");
    if (!client.ok()) {
      emit_error("dc_cli: cannot connect: " + client.status().describe());
      return 3;
    }
    ControlMessage control;
    control.compilation = CompilationId(static_cast<std::uint64_t>(std::stoull(rest.front())));
    control.reason = arguments.get("reason", "operator cancellation");
    std::vector<std::byte> payload;
    encode_control(control, payload);
    auto response = client.value().call(Op::CancelAttempt, payload);
    if (!response.ok()) {
      emit_error("dc_cli: " + response.status().describe());
      return 4;
    }
    client.value().close();
    emit(response.value().code == ErrorCode::Ok ? "cancellation requested"
                                                : "cancellation refused: " + response.value().detail);
    return response.value().code == ErrorCode::Ok ? 0 : 4;
  }
  if (command == "state") {
    Arguments local = arguments;
    const std::string state_dir = local.get("state", ".dcstate");
    const std::string action = rest.empty() ? "info" : rest.front();
    if (action != "info") {
      emit_error("dc_cli: unknown state subcommand");
      return 2;
    }
    PersistentStore store;
    PersistentStore::Options options;
    options.root = state_dir;
    std::vector<JournalRecord> records;
    std::vector<std::byte> snapshot;
    auto opened = store.open(options, records, snapshot);
    if (!opened.ok()) {
      emit_error("dc_cli: cannot open state: " + opened.status().describe());
      return 4;
    }
    emit("state root: " + std::filesystem::absolute(state_dir).string());
    emit("snapshot loaded: " + std::string(opened.value().snapshot_loaded ? "yes" : "no"));
    emit("snapshot seq: " + std::to_string(opened.value().snapshot_seq));
    emit("journal records applied: " + std::to_string(opened.value().records_applied));
    emit("journal records skipped: " + std::to_string(opened.value().records_skipped));
    emit("torn tail recovered: " + std::string(opened.value().torn_tail ? "yes" : "no"));
    for (const auto& note : opened.value().notes) emit("note: " + note);
    store.close();
    return 0;
  }
  if (command == "toolchain") {
    DiscoveryOptions options;
    options.msvc_roots = default_msvc_roots();
    options.cuda_roots = arguments.has("no-cuda") ? std::vector<std::filesystem::path>{} : default_cuda_roots();
    options.include_synthetic = arguments.has("synthetic");
    for (const auto& architecture : arguments.all("cuda-arch")) options.cuda_architectures.push_back(architecture);
    if (options.cuda_architectures.empty()) options.cuda_architectures.push_back("sm_120");
    const DiscoveryResult discovered = discover_toolchains(options);
    if (!rest.empty() && rest.front() == "show") {
      std::size_t index = 0;
      try {
        index = static_cast<std::size_t>(std::stoull(rest.size() > 1 ? rest[1] : "0"));
      } catch (...) {
        index = 0;
      }
      if (index >= discovered.toolchains.size()) {
        emit_error("dc_cli: toolchain index out of range");
        return 2;
      }
      const ToolchainIdentity& toolchain = discovered.toolchains[index];
      emit("toolchain id " + std::to_string(toolchain.id.value()) + " family " +
           std::string(to_string(toolchain.family)) + " version " + toolchain.version_string);
      emit("  identity " + toolchain.identity_digest.hex());
      emit("  evidence " + std::string(to_string(toolchain.evidence)));
      emit("  compiler " + std::string(to_string(toolchain.compiler.state)) + " " +
           toolchain.compiler.path);
      if (toolchain.compiler.state == BinaryIdState::Known) {
        emit("  compiler digest " + toolchain.compiler.digest.hex() + " size " +
             std::to_string(toolchain.compiler.size));
      }
      for (const auto& component : toolchain.sdk) {
        emit("  sdk " + component.name + " " + component.version);
      }
      for (const auto& kv : toolchain.configuration) emit("  config " + kv.first + "=" + kv.second);
      return 0;
    }
    std::size_t index = 0;
    for (const auto& toolchain : discovered.toolchains) {
      emit(std::to_string(index++) + ": " + std::string(to_string(toolchain.family)) + " " +
           toolchain.version_string + " evidence=" + std::string(to_string(toolchain.evidence)) +
           " identity=" + toolchain.identity_digest.hex().substr(0, 16));
    }
    for (const auto& target : discovered.targets) {
      emit("target: " + target.triple +
           (target.accelerator.architecture.empty() ? "" : " " + target.accelerator.architecture) +
           " evidence=" + std::string(to_string(target.evidence)));
    }
    for (const auto& note : discovered.notes) emit("note: " + note);
    return 0;
  }
  if (command == "verify") return run_verify_command(sub);
  if (command == "probe-process") {
    // Diagnostic for the subprocess layer: runs one child process with an
    // explicit environment and reports exactly what the runtime observed.
    const std::string exe = arguments.get("exe");
    if (exe.empty()) {
      emit_error("dc_cli: probe-process requires --exe");
      return 2;
    }
    ProcessSpec spec;
    spec.executable = exe;
    spec.arguments = arguments.all("arg");
    const std::string cwd = arguments.get("cwd");
    if (!cwd.empty()) spec.working_directory = cwd;
    spec.inherit_environment = arguments.has("inherit-env");
    for (const auto& kv : arguments.all("env")) {
      const std::size_t equals = kv.find('=');
      if (equals == std::string::npos) continue;
      spec.environment.emplace_back(kv.substr(0, equals), kv.substr(equals + 1));
    }
    spec.timeout_millis = 30000;
    spec.max_output_bytes = 1u << 20;
    const ProcessResult result = run_process(spec);
    emit("started=" + std::string(result.started ? "yes" : "no"));
    emit("exit_code=" + std::to_string(result.exit_code));
    emit("timed_out=" + std::string(result.timed_out ? "yes" : "no"));
    emit("wall_millis=" + std::to_string(result.wall_millis));
    emit("describe=" + result.describe());
    if (!result.stdout_text.empty()) emit("stdout=" + result.stdout_text.substr(0, 500));
    if (!result.stderr_text.empty()) emit("stderr=" + result.stderr_text.substr(0, 500));
    return result.succeeded() ? 0 : 1;
  }
  if (command == "demo") {
    const std::string scenario = rest.empty() ? "all" : rest.front();
    return run_demo_command(sub, scenario);
  }
  if (command == "cuda-proof") return run_cuda_proof(sub);

  emit_error("dc_cli: unknown command '" + command + "'");
  emit(usage());
  return 2;
}
