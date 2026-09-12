// Distributed Compilation - real multi-process end-to-end proof.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// This driver starts a real coordinator process and two real worker processes,
// submits real compilation work over real TCP, kills a worker during an active
// compile, replays a stale authority claim from a restarted boot, restarts the
// coordinator, and audits the result. Nothing here is simulated: every step
// observes live processes over a socket.
#ifdef _WIN32
#define FD_SETSIZE 1024
#include <winsock2.h>
#include <tlhelp32.h>
#include <windows.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "app_common.hpp"
#include "client.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/net.hpp"
#include "dc/persistence.hpp"
#include "dc/process.hpp"
#include "dc/wire.hpp"

namespace {

using namespace dc;
using namespace dc::app;

struct CaseResult {
  std::string name;
  bool passed = false;
  std::string detail;
};

struct Harness {
  std::vector<CaseResult> results;
  int failures = 0;
  std::string only;
  bool skipping = false;

  void begin(const std::string& name) {
    if (!only.empty() && only != name) {
      skipping = true;
      return;
    }
    skipping = false;
    emit("[BEGIN] " + name);
    std::fflush(stdout);
  }
  void phase(const std::string& value) {
    if (skipping) return;
    emit("[PHASE] " + value);
    std::fflush(stdout);
  }
  bool check(bool passed, const std::string& detail = {}) {
    if (skipping) return passed;
    results.push_back(CaseResult{passed ? "ok" : "fail", passed, detail});
    if (!passed) ++failures;
    emit(std::string(passed ? "[PASS] " : "[FAIL] ") + (detail.empty() ? std::string("ok") : detail));
    std::fflush(stdout);
    return passed;
  }
};

std::string read_text_file(const std::filesystem::path& path) {
  std::vector<std::byte> bytes;
  if (!read_file_bounded(path, 1u << 20, bytes).ok()) return {};
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

bool wait_for_file_text(const std::filesystem::path& path, const std::string& marker,
                        std::uint32_t timeout_millis) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_millis);
  while (std::chrono::steady_clock::now() < deadline) {
    if (read_text_file(path).find(marker) != std::string::npos) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return false;
}

std::string field(const std::string& text, const std::string& key) {
  const std::size_t at = text.find(key + "=");
  if (at == std::string::npos) return {};
  const std::size_t begin = at + key.size() + 1;
  std::size_t end = begin;
  while (end < text.size() && text[end] != ' ' && text[end] != '\r' && text[end] != '\n') ++end;
  return text.substr(begin, end - begin);
}

std::uint64_t number_field(const std::string& text, const std::string& key) {
  const std::string value = field(text, key);
  if (value.empty()) return 0;
  try {
    return std::stoull(value);
  } catch (...) {
    return 0;
  }
}

#ifdef _WIN32
std::set<std::uint32_t> processes_named(const std::vector<std::string>& names) {
  std::set<std::uint32_t> found;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return found;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry) != 0) {
    do {
      const std::wstring wide(entry.szExeFile);
      std::string narrow;
      narrow.reserve(wide.size());
      for (wchar_t c : wide) {
        // Process names are ASCII; anything else cannot match a compiler name.
        narrow.push_back(c >= 0 && c < 128 ? static_cast<char>(c) : '?');
      }
      for (const auto& name : names) {
        if (narrow == name) found.insert(entry.th32ProcessID);
      }
    } while (Process32NextW(snapshot, &entry) != 0);
  }
  CloseHandle(snapshot);
  return found;
}
#else
std::set<std::uint32_t> processes_named(const std::vector<std::string>&) { return {}; }
#endif

struct Service {
  std::filesystem::path ready_file;
  std::unique_ptr<ChildProcess> process;
  std::string label;

  bool start(const std::filesystem::path& exe, const std::vector<std::string>& arguments) {
    ProcessSpec spec;
    spec.executable = exe;
    spec.arguments = arguments;
    spec.inherit_environment = true;
    spec.timeout_millis = 30u * 60u * 1000u;
    spec.max_output_bytes = 4u << 20;
    auto started = ChildProcess::start(spec);
    if (!started.ok()) return false;
    process = std::move(started.value());
    return true;
  }
  bool wait_ready(const std::string& marker, std::uint32_t timeout_millis) {
    return wait_for_file_text(ready_file, marker, timeout_millis);
  }
  void kill() {
    if (!process) return;
    process->terminate();
    process->wait(20000);
    process.reset();
  }
};

// Waits until a predicate holds, but aborts early when the given services have
// all exited: a lost worker must surface as a diagnosis, never as a hang.
template <class Predicate>
bool wait_until(Predicate&& predicate, std::uint32_t timeout_millis,
                const std::vector<Service*>& required) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_millis);
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) return true;
    bool any_alive = false;
    for (const Service* service : required) {
      if (service->process && service->process->running()) any_alive = true;
    }
    if (!required.empty() && !any_alive) return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return predicate();
}

int query_text(Client& client, std::uint32_t kind, std::uint64_t id, std::string& out) {
  QueryMessage query;
  query.kind = kind;
  query.id = id;
  std::vector<std::byte> payload;
  encode_query(query, payload);
  auto response = client.call(Op::Query, payload);
  if (!response.ok()) return 1;
  if (response.value().code != ErrorCode::Ok) {
    out = response.value().detail;
    return 2;
  }
  out.assign(reinterpret_cast<const char*>(response.value().payload.data()), response.value().payload.size());
  return 0;
}

Blob text_blob(const std::string& text) {
  Blob blob;
  blob.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                    reinterpret_cast<const std::byte*>(text.data()) + text.size());
  blob.digest = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
  return blob;
}

// A translation unit heavy enough that an in-flight compile is observable, but
// which is a genuine compilation rather than an artificial delay.
std::string heavy_source() {
  std::string text = "#include <cstdint>\n";
  text += "template <int N> struct Fib { static constexpr unsigned long long value = Fib<N-1>::value + Fib<N-2>::value; };\n";
  text += "template <> struct Fib<0> { static constexpr unsigned long long value = 0; };\n";
  text += "template <> struct Fib<1> { static constexpr unsigned long long value = 1; };\n";
  for (int i = 0; i < 80; ++i) {
    const std::string index = std::to_string(i);
    text += "template <int N> struct Sum" + index + " { static constexpr unsigned long long value = Sum" + index +
            "<N-1>::value + (unsigned long long)(N * 3) + Sum" + index + "<N-2>::value; };\n";
    text += "template <> struct Sum" + index + "<0> { static constexpr unsigned long long value = 1; };\n";
    text += "template <> struct Sum" + index + "<1> { static constexpr unsigned long long value = 2; };\n";
  }
  text += "extern \"C\" unsigned long long dc_heavy_value() {\n";
  text += "  unsigned long long total = Fib<32>::value;\n";
  for (int i = 0; i < 80; ++i) {
    text += "  total += Sum" + std::to_string(i) + "<48>::value;\n";
  }
  text += "  return total;\n}\n";
  return text;
}

std::string simple_source() {
  return "#include <cstdio>\n"
         "extern \"C\" int dc_simple_add(int a, int b) { return a + b; }\n";
}

std::string mutated_source() {
  return "#include <cstdio>\n"
         "extern \"C\" int dc_simple_add(int a, int b) { return a + b + 1; }\n";
}

std::string main_source() {
  return "#include <cstdio>\n"
         "extern \"C\" int dc_simple_add(int a, int b);\n"
         "int main() { std::printf(\"dc-ok %d\\n\", dc_simple_add(20, 22)); return 0; }\n";
}

struct DemoContext {
  Client* client = nullptr;
  const ToolchainIdentity* toolchain = nullptr;
  const TargetIdentity* target = nullptr;
  std::string endpoint;
};

struct SubmitOutcome {
  Status status;
  SubmissionResponse response;
  CompilationId root = CompilationId(0);
};

// Builds and submits a request from (logical name, source text) pairs plus an
// optional link unit, then waits for the root unit to reach a terminal state.
SubmitOutcome submit_units(DemoContext& context, const std::vector<std::pair<std::string, std::string>>& units,
                           bool link, bool smoke_test, bool wait) {
  SubmitOutcome outcome;
  SubmitMessage message;
  message.request.toolchain = *context.toolchain;
  message.request.target = *context.target;
  message.request.request_id = RequestId(static_cast<std::uint64_t>(SystemClock().now()));
  message.request.policy.reproducibility = ReproducibilityRequirement::Preferred;
  message.request.policy.cache = CachePolicy::ReadWrite;
  message.request.policy.max_attempts_per_unit = 3;
  message.request.validation.require_smoke_test = smoke_test;
  if (smoke_test) message.request.validation.smoke_expected_stdout = "dc-ok 42";

  std::uint32_t index = 0;
  for (const auto& unit_text : units) {
    const Blob blob = text_blob(unit_text.second);
    CompilationUnitSpec unit;
    unit.index = index++;
    unit.logical_name = unit_text.first;
    unit.kind = UnitKind::Compile;
    unit.output_kind = link ? OutputKind::Object : OutputKind::Object;
    UnitSource source;
    source.logical_name = unit_text.first;
    source.format = InputFormat::Source;
    source.language_mode = "c++20";
    source.content.digest = blob.digest;
    source.content.size = blob.bytes.size();
    unit.sources.push_back(source);
    message.request.units.push_back(unit);
    message.blobs.push_back(blob);
  }
  if (link) {
    CompilationUnitSpec link_unit;
    link_unit.index = index;
    link_unit.logical_name = "link:demo";
    link_unit.kind = UnitKind::Link;
    link_unit.output_kind = OutputKind::Executable;
    for (std::uint32_t i = 0; i < index; ++i) link_unit.child_units.push_back(i);
    message.request.units.push_back(link_unit);
  }

  Status canonical = canonicalize(message.request);
  if (!canonical.ok()) {
    outcome.status = canonical;
    return outcome;
  }
  outcome.root = derive_compilation_id(
      message.request.units.back().identity_digest);

  std::vector<std::byte> payload;
  encode_submit(message, payload);
  auto response = context.client->call(Op::SubmitCompilation, payload);
  if (!response.ok()) {
    outcome.status = response.status();
    return outcome;
  }
  if (response.value().code != ErrorCode::Ok) {
    outcome.status = Status::error(response.value().code, response.value().detail);
    return outcome;
  }
  if (!decode_submission_response(std::span<const std::byte>(response.value().payload.data(),
                                                             response.value().payload.size()),
                                  outcome.response)) {
    outcome.status = Status::error(ErrorCode::Malformed, "malformed submission response");
    return outcome;
  }
  outcome.status = Status::success();
  if (!wait) return outcome;

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(420);
  while (std::chrono::steady_clock::now() < deadline) {
    std::string text;
    if (query_text(*context.client, 0, outcome.root.value(), text) == 0) {
      if (text.find("state Committed") != std::string::npos) return outcome;
      if (text.find("state Failed") != std::string::npos ||
          text.find("state Cancelled") != std::string::npos ||
          text.find("state Fenced") != std::string::npos) {
        std::string explanation;
        query_text(*context.client, 9, outcome.root.value(), explanation);
        outcome.status = Status::error(ErrorCode::ValidationFailure, explanation);
        return outcome;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  outcome.status = Status::error(ErrorCode::Timeout, "root unit did not reach a terminal state");
  return outcome;
}

}  // namespace

int run_demo_command(const Arguments& arguments, const std::string& scenario) {
  using namespace dc;
  using namespace dc::app;

  if (scenario != "multiprocess" && scenario != "all") {
    emit_error("dc_cli demo: supported scenarios are 'multiprocess' and 'all'");
    return 2;
  }
  const std::filesystem::path bin = arguments.get("bin", executable_directory().string());
  const std::filesystem::path root = arguments.get("work", unique_temp_path("dc-demo").string());
  const bool keep = arguments.has("keep");
  const bool verbose = arguments.has("verbose");

  const std::filesystem::path coordinator_exe = bin / "dc_coordinator.exe";
  const std::filesystem::path worker_exe = bin / "dc_worker.exe";
  if (!std::filesystem::exists(coordinator_exe) || !std::filesystem::exists(worker_exe)) {
    emit_error("dc_cli demo: dc_coordinator.exe and dc_worker.exe must be next to dc_cli.exe");
    return 3;
  }
  if (!ensure_directory(root).ok()) {
    emit_error("dc_cli demo: cannot create the work directory");
    return 3;
  }
  Status network = initialize_network();
  if (!network.ok()) {
    emit_error("dc_cli demo: " + network.describe());
    return 3;
  }

  Harness harness;
  harness.only = arguments.get("only");

  const std::set<std::uint32_t> baseline_compilers = processes_named({"cl.exe", "link.exe", "nvcc.exe"});

  Service coordinator;
  coordinator.label = "coordinator";
  coordinator.ready_file = root / "coordinator.ready";
  Service alpha;
  alpha.label = "alpha";
  alpha.ready_file = root / "alpha.ready";
  Service beta;
  beta.label = "beta";
  beta.ready_file = root / "beta.ready";

  const std::filesystem::path state_dir = root / "state";
  const std::filesystem::path scratch_alpha = root / "scratch-alpha";
  const std::filesystem::path scratch_beta = root / "scratch-beta";
  const std::filesystem::path claim_log = root / "alpha-claims.log";
  const std::filesystem::path coordinator_log = root / "coordinator.log";

  std::string endpoint;
  std::string alpha_worker_id;
  std::string alpha_boot_id;

  const auto start_coordinator = [&]() -> bool {
    std::error_code ec;
    std::filesystem::remove(coordinator.ready_file, ec);
    std::vector<std::string> args = {"--state", state_dir.string(), "--listen",
                                     arguments.get("listen", "127.0.0.1:0"), "--ready-file",
                                     coordinator.ready_file.string(), "--snapshot-every", "64",
                                     "--log", coordinator_log.string()};
    if (verbose) args.push_back("--verbose");
    if (!coordinator.start(coordinator_exe, args)) return false;
    if (!coordinator.wait_ready("DC_COORDINATOR_READY", 40000)) return false;
    const std::string port = field(read_text_file(coordinator.ready_file), "port");
    if (port.empty()) return false;
    endpoint = "127.0.0.1:" + port;
    return true;
  };

  const auto start_worker = [&](Service& worker, const std::string& name,
                                const std::filesystem::path& scratch, bool with_claim_log) -> bool {
    std::error_code ec;
    std::filesystem::remove(worker.ready_file, ec);
    std::vector<std::string> args = {"--coordinator", endpoint, "--name", name, "--max-inflight", "2",
                                     "--scratch", scratch.string(), "--ready-file", worker.ready_file.string(),
                                     "--log", (root / (name + ".log")).string()};
    if (with_claim_log) {
      args.push_back("--claim-log");
      args.push_back(claim_log.string());
    }
    if (verbose) args.push_back("--verbose");
    if (!worker.start(worker_exe, args)) return false;
    return worker.wait_ready("DC_WORKER_REGISTERED", 90000);
  };

  const auto stop_all = [&]() {
    alpha.kill();
    beta.kill();
    coordinator.kill();
  };

  harness.begin("coordinator starts and publishes its endpoint");
  harness.phase("SETUP");
  if (!harness.check(start_coordinator(), endpoint)) {
    stop_all();
    if (!keep) (void)remove_tree_quiet(root);
    return 4;
  }

  harness.begin("two workers register and advertise real toolchains");
  harness.phase("REGISTER");
  const bool alpha_started = start_worker(alpha, "alpha", scratch_alpha, true);
  const bool beta_started = start_worker(beta, "beta", scratch_beta, false);
  const std::string alpha_text = read_text_file(alpha.ready_file);
  alpha_worker_id = field(alpha_text, "worker");
  alpha_boot_id = field(alpha_text, "boot");
  harness.check(alpha_started && beta_started && !alpha_worker_id.empty() && !alpha_boot_id.empty(),
                "alpha=" + alpha_worker_id + "/" + alpha_boot_id);

  auto session = Client::connect(endpoint, SessionRole::Client, "demo");
  if (!session.ok()) {
    emit_error("dc_cli demo: cannot open a client session: " + session.status().describe());
    stop_all();
    if (!keep) (void)remove_tree_quiet(root);
    return 4;
  }
  Client& cli = session.value();

  const auto ready_workers = [&]() -> std::size_t {
    std::string text;
    if (query_text(cli, 3, 0, text) != 0) return 0;
    std::size_t count = 0;
    std::size_t cursor = 0;
    while ((cursor = text.find(" ready", cursor)) != std::string::npos) {
      ++count;
      cursor += 6;
    }
    return count;
  };

  harness.begin("worker capability evidence is accepted and both workers are ready");
  harness.phase("REGISTER");
  {
    std::size_t count = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    while (std::chrono::steady_clock::now() < deadline) {
      count = ready_workers();
      if (count >= 2) break;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    harness.check(count >= 2, "ready workers=" + std::to_string(count));
  }

  DiscoveryOptions discovery;
  discovery.msvc_roots = default_msvc_roots();
  discovery.cuda_roots = {};
  discovery.compute_binary_digests = true;
  const DiscoveryResult discovered = discover_toolchains(discovery);
  const ToolchainIdentity* toolchain = pick_toolchain_for(discovered.toolchains, "auto", InputFormat::Source,
                                                          OutputKind::Object, false);
  harness.begin("a real MSVC toolchain identity is discoverable by the client");
  harness.phase("CANONICALIZE");
  if (!harness.check(toolchain != nullptr, toolchain != nullptr ? toolchain->version_string : "no MSVC found")) {
    stop_all();
    if (!keep) (void)remove_tree_quiet(root);
    return 5;
  }
  const TargetIdentity* target = nullptr;
  for (const auto& candidate : discovered.targets) {
    if (candidate.triple == "x86_64-pc-windows-msvc") target = &candidate;
  }
  if (target == nullptr) target = &discovered.targets.front();

  DemoContext context;
  context.client = &cli;
  context.toolchain = toolchain;
  context.target = target;
  context.endpoint = endpoint;

  harness.begin("equivalent requests derive an identical canonical identity");
  harness.phase("CANONICALIZE");
  {
    SubmitMessage probe;
    probe.request.toolchain = *toolchain;
    probe.request.target = *target;
    probe.request.request_id = RequestId(1);
    const Blob blob = text_blob(simple_source());
    CompilationUnitSpec unit;
    unit.index = 0;
    unit.logical_name = "simple.cpp";
    unit.kind = UnitKind::Compile;
    unit.output_kind = OutputKind::Object;
    UnitSource source;
    source.logical_name = "simple.cpp";
    source.format = InputFormat::Source;
    source.language_mode = "c++20";
    source.content.digest = blob.digest;
    source.content.size = blob.bytes.size();
    unit.sources.push_back(source);
    probe.request.units.push_back(unit);
    SubmitMessage other = probe;
    other.request.request_id = RequestId(999);
    const Status first = canonicalize(probe.request);
    const Status second = canonicalize(other.request);
    harness.check(first.ok() && second.ok() &&
                      probe.request.request_identity == other.request.request_identity,
                  probe.request.request_identity.hex());
  }

  harness.begin("a real C++ translation unit compiles on a worker process and commits");
  harness.phase("COMPILE");
  SubmitOutcome first = submit_units(context, {{"simple.cpp", simple_source()}}, false, false, true);
  CompilationId first_compilation = first.root;
  harness.check(first.status.ok(), first.status.ok() ? "committed" : first.status.describe());

  harness.begin("the coordinator validates the produced object before authority");
  harness.phase("VALIDATE");
  {
    std::string text;
    query_text(cli, 9, first_compilation.value(), text);
    const bool committed = text.find("state: Committed") != std::string::npos;
    const bool validated =
        text.find("validation: PASS") != std::string::npos && text.find("format: PASS") != std::string::npos;
    harness.check(committed && validated,
                  committed ? (validated ? "object validated (digest, format, target metadata) and committed"
                                         : "committed without full validation evidence")
                            : text);
  }

  harness.begin("an identical resubmission is served from validated cache reuse");
  harness.phase("CACHE");
  {
    SubmitOutcome second = submit_units(context, {{"simple.cpp", simple_source()}}, false, false, true);
    harness.check(second.status.ok() && second.response.served_from_cache,
                  second.status.ok() ? "cache hit validated" : second.status.describe());
    harness.check(second.root == first_compilation, "same logical compilation identity");
  }

  harness.begin("changed source content yields a different identity and a new compile");
  harness.phase("CACHE");
  {
    SubmitOutcome third = submit_units(context, {{"simple.cpp", mutated_source()}}, false, false, true);
    harness.check(third.status.ok() && third.root != first_compilation,
                  third.status.ok() ? "new identity derived" : third.status.describe());
  }

  harness.begin("fan-out to two compile units and fan-in to one authoritative executable");
  harness.phase("ASSIGN");
  SubmitOutcome linked =
      submit_units(context, {{"simple.cpp", simple_source()}, {"main.cpp", main_source()}}, true, true, true);
  harness.check(linked.status.ok(), linked.status.ok() ? "linked and committed" : linked.status.describe());

  harness.begin("the coordinator executed the linked artifact and matched its output");
  harness.phase("VALIDATE");
  {
    std::string text;
    query_text(cli, 9, linked.root.value(), text);
    harness.check(text.find("smoke_test: PASS") != std::string::npos,
                  text.find("smoke_test") != std::string::npos ? "the coordinator executed the artifact"
                                                               : "no smoke test evidence: " + text);
  }

  harness.begin("worker death during an active compile fences the old boot");
  harness.phase("KILL");
  CompilationId heavy_compilation(0);
  {
    SubmitMessage message;
    message.request.toolchain = *toolchain;
    message.request.target = *target;
    message.request.request_id = RequestId(9101);
    message.request.policy.reproducibility = ReproducibilityRequirement::Preferred;
    message.request.policy.max_attempts_per_unit = 3;
    const Blob blob = text_blob(heavy_source());
    CompilationUnitSpec unit;
    unit.index = 0;
    unit.logical_name = "heavy.cpp";
    unit.kind = UnitKind::Compile;
    unit.output_kind = OutputKind::Object;
    UnitSource source;
    source.logical_name = "heavy.cpp";
    source.format = InputFormat::Source;
    source.language_mode = "c++20";
    source.content.digest = blob.digest;
    source.content.size = blob.bytes.size();
    unit.sources.push_back(source);
    message.request.units.push_back(unit);
    message.blobs.push_back(blob);
    canonicalize(message.request);
    heavy_compilation = derive_compilation_id(message.request.units.front().identity_digest);

    std::vector<std::byte> payload;
    encode_submit(message, payload);
    auto response = cli.call(Op::SubmitCompilation, payload);
    bool running_seen = false;
    if (response.ok() && response.value().code == ErrorCode::Ok) {
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
      while (std::chrono::steady_clock::now() < deadline) {
        std::string text;
        query_text(cli, 0, heavy_compilation.value(), text);
        if (text.find("state Running") != std::string::npos) {
          running_seen = true;
          break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
      }
    }
    harness.check(running_seen, running_seen ? "observed an in-flight attempt" : "no in-flight attempt observed");

    const std::string claims = read_text_file(claim_log);
    harness.check(!claims.empty(), "the worker recorded its authority claim");

    alpha.kill();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    std::string workers_text;
    query_text(cli, 3, 0, workers_text);
    harness.check(workers_text.find("FENCED") != std::string::npos, "the dead worker is fenced");
  }

  harness.begin("a stale completion claim from a restarted boot is refused");
  harness.phase("VERIFY");
  {
    const std::string claims = read_text_file(claim_log);
    const std::uint64_t attempt_id = number_field(claims, "attempt");
    const std::uint64_t compilation_id = number_field(claims, "compilation");
    const std::uint64_t unit_id = number_field(claims, "unit");
    bool rejected = false;
    std::string detail = "no captured claim to replay";
    if (attempt_id != 0 && compilation_id != 0) {
      auto rogue = Client::connect(endpoint, SessionRole::Worker, "alpha-restarted");
      if (rogue.ok()) {
        RegisterWorkerMessage registration;
        registration.endpoint = endpoint;
        registration.host = "local";
        registration.worker_id = WorkerId(std::stoull(alpha_worker_id));
        // A restarted worker always presents a fresh boot identity.
        registration.boot_id = WorkerBootId(std::stoull(alpha_boot_id) ^ 0x5DEECE66Dull);
        registration.max_inflight = 1;
        registration.capabilities.evidence = EvidenceClass::Unknown;
        registration.capabilities.host = "local";
        canonicalize(registration.capabilities);
        std::vector<std::byte> payload;
        encode_register_worker(registration, payload);
        auto registered = rogue.value().call(Op::RegisterWorker, payload);
        if (registered.ok() && registered.value().code == ErrorCode::Ok) {
          AuthorityClaim claim;
          claim.epoch = CoordinatorEpoch(1);
          claim.compilation = CompilationId(compilation_id);
          claim.compilation_generation = CompilationGeneration(1);
          claim.unit = CompilationUnitId(unit_id == 0 ? 1 : unit_id);
          claim.unit_generation = UnitGeneration(1);
          claim.attempt = CompilationAttemptId(attempt_id);
          claim.attempt_generation = CompilationAttemptGeneration(1);
          claim.worker = registration.worker_id;
          claim.worker_boot = WorkerBootId(std::stoull(alpha_boot_id));
          claim.worker_generation = WorkerGeneration(1);
          claim.lease = LeaseId(1);
          claim.lease_generation = LeaseGeneration(1);
          std::vector<std::byte> claim_payload;
          encode_authority_claim(claim, claim_payload);
          auto replay = rogue.value().call(Op::BeginCompile, claim_payload);
          if (replay.ok() && replay.value().code != ErrorCode::Ok) {
            rejected = true;
            detail = std::string(to_string(replay.value().code)) + ": " + replay.value().detail;
          } else if (replay.ok()) {
            detail = "the coordinator accepted a claim bound to a superseded boot";
          } else {
            detail = replay.status().describe();
          }
        } else {
          detail = registered.ok() ? registered.value().detail : registered.status().describe();
        }
        rogue.value().close();
      } else {
        detail = rogue.status().describe();
      }
    }
    harness.check(rejected, detail);
  }

  harness.begin("the interrupted work is reassigned and completes through fresh authority");
  harness.phase("REASSIGN");
  {
    bool committed = false;
    std::string last;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(420);
    while (std::chrono::steady_clock::now() < deadline) {
      std::string text;
      query_text(cli, 0, heavy_compilation.value(), text);
      last = text;
      if (text.find("state Committed") != std::string::npos) {
        committed = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    harness.check(committed, committed ? "recovered through a fresh attempt generation" : last);
  }

  const Digest256 retained_digest = [&]() -> Digest256 {
    auto commit_query = cli.call(Op::Query, [&] {
      QueryMessage query;
      query.kind = 7;
      std::vector<std::byte> payload;
      encode_query(query, payload);
      return payload;
    }());
    std::string commits;
    if (commit_query.ok()) {
      commits.assign(reinterpret_cast<const char*>(commit_query.value().payload.data()),
                     commit_query.value().payload.size());
    }
    (void)commits;
    QueryMessage artifact_query;
    artifact_query.kind = 8;
    artifact_query.id = first_compilation.value();
    std::vector<std::byte> payload;
    encode_query(artifact_query, payload);
    auto artifact = cli.call(Op::Query, payload);
    if (!artifact.ok() || artifact.value().code != ErrorCode::Ok) return Digest256{};
    return sha256(std::span<const std::byte>(artifact.value().payload.data(), artifact.value().payload.size()));
  }();

  // A worker that exits before it is asked to must be reported, never ignored.
  for (Service* service : {&alpha, &beta}) {
    if (service->process && !service->process->running()) {
      const ProcessResult result = service->process->wait(5000);
      service->process.reset();
      harness.begin("worker '" + service->label + "' stayed alive through the compile phase");
      harness.phase("VERIFY");
      harness.check(false, "exited early: exit=" + std::to_string(result.exit_code) + " stderr=" +
                               result.stderr_text.substr(0, 400));
    }
  }

  harness.begin("coordinator restart advances the epoch");
  harness.phase("RESTART");
  {
    cli.close();
    stop_all();
    harness.check(start_coordinator(), "restarted with the same state directory");
    const std::string epoch = field(read_text_file(coordinator.ready_file), "epoch");
    harness.check(!epoch.empty() && std::stoull(epoch) >= 2, "epoch " + epoch);
  }

  harness.begin("previously committed artifacts are retained across the restart");
  harness.phase("RECOVER");
  {
    auto restarted = Client::connect(endpoint, SessionRole::Client, "demo");
    bool retained = false;
    std::string detail = "cannot reconnect after the restart";
    if (restarted.ok()) {
      QueryMessage query;
      query.kind = 8;
      query.id = first_compilation.value();
      std::vector<std::byte> payload;
      encode_query(query, payload);
      auto artifact = restarted.value().call(Op::Query, payload);
      if (artifact.ok() && artifact.value().code == ErrorCode::Ok) {
        const Digest256 digest =
            sha256(std::span<const std::byte>(artifact.value().payload.data(), artifact.value().payload.size()));
        retained = !retained_digest.is_zero() && digest == retained_digest;
        detail = retained ? "artifact digest unchanged" : "artifact digest changed across restart";
      } else {
        detail = artifact.ok() ? artifact.value().detail : artifact.status().describe();
      }
      restarted.value().close();
    }
    harness.check(retained, detail);
  }

  harness.begin("stale claims cannot commit after the restart");
  harness.phase("RECOVER");
  {
    const std::string claims = read_text_file(claim_log);
    const std::uint64_t attempt_id = number_field(claims, "attempt");
    const std::uint64_t compilation_id = number_field(claims, "compilation");
    bool rejected = false;
    std::string detail = "no captured claim to replay";
    if (attempt_id != 0) {
      auto rogue = Client::connect(endpoint, SessionRole::Worker, "stale-session");
      if (rogue.ok()) {
        RegisterWorkerMessage registration;
        registration.endpoint = endpoint;
        registration.host = "local";
        registration.worker_id = WorkerId(std::stoull(alpha_worker_id));
        registration.boot_id = WorkerBootId(4242);
        registration.max_inflight = 1;
        registration.capabilities.evidence = EvidenceClass::Unknown;
        canonicalize(registration.capabilities);
        std::vector<std::byte> payload;
        encode_register_worker(registration, payload);
        auto registered = rogue.value().call(Op::RegisterWorker, payload);
        if (registered.ok() && registered.value().code == ErrorCode::Ok) {
          AuthorityClaim claim;
          claim.epoch = CoordinatorEpoch(1);
          claim.compilation = CompilationId(compilation_id == 0 ? 1 : compilation_id);
          claim.compilation_generation = CompilationGeneration(1);
          claim.unit = CompilationUnitId(1);
          claim.unit_generation = UnitGeneration(1);
          claim.attempt = CompilationAttemptId(attempt_id);
          claim.attempt_generation = CompilationAttemptGeneration(1);
          claim.worker = registration.worker_id;
          claim.worker_boot = registration.boot_id;
          claim.worker_generation = WorkerGeneration(1);
          claim.lease = LeaseId(1);
          claim.lease_generation = LeaseGeneration(1);
          std::vector<std::byte> claim_payload;
          encode_authority_claim(claim, claim_payload);
          auto replay = rogue.value().call(Op::BeginCompile, claim_payload);
          rejected = replay.ok() && replay.value().code != ErrorCode::Ok;
          detail = replay.ok() ? (rejected ? std::string(to_string(replay.value().code)) + ": " +
                                                 replay.value().detail
                                           : "accepted a pre-restart claim")
                               : replay.status().describe();
        } else {
          detail = registered.ok() ? registered.value().detail : registered.status().describe();
        }
        rogue.value().close();
      } else {
        detail = rogue.status().describe();
      }
    }
    harness.check(rejected, detail);
  }

  harness.begin("workers re-register with fresh boots and new work completes");
  harness.phase("RECOVER");
  {
    const bool alpha_again = start_worker(alpha, "alpha", scratch_alpha, false);
    const bool beta_again = start_worker(beta, "beta", scratch_beta, false);
    const std::string text = read_text_file(alpha.ready_file);
    const std::string new_boot = field(text, "boot");
    harness.check(alpha_again && beta_again && !new_boot.empty() && new_boot != alpha_boot_id,
                  "new boot " + new_boot + " (previous " + alpha_boot_id + ")");

    auto client = Client::connect(endpoint, SessionRole::Client, "demo");
    DemoContext fresh;
    fresh.client = client.ok() ? &client.value() : nullptr;
    fresh.toolchain = toolchain;
    fresh.target = target;
    SubmitOutcome outcome;
    if (fresh.client != nullptr) {
      std::size_t count = 0;
      const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
      while (std::chrono::steady_clock::now() < deadline) {
        std::string workers_text;
        query_text(*fresh.client, 3, 0, workers_text);
        count = 0;
        std::size_t cursor = 0;
        while ((cursor = workers_text.find(" ready", cursor)) != std::string::npos) {
          ++count;
          cursor += 6;
        }
        if (count >= 2) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      outcome = submit_units(fresh, {{"after-restart.cpp", simple_source()}}, false, false, true);
    } else {
      outcome.status = client.status();
    }
    harness.check(outcome.status.ok(),
                  outcome.status.ok() ? "completed under the new epoch" : outcome.status.describe());
    if (client.ok()) client.value().close();
  }

  harness.begin("invariant audit reports zero violations");
  harness.phase("VERIFY");
  {
    auto client = Client::connect(endpoint, SessionRole::Client, "demo");
    bool clean = false;
    std::string text;
    if (client.ok()) {
      std::vector<std::byte> empty;
      auto response = client.value().call(Op::Audit, empty);
      if (response.ok()) {
        text.assign(reinterpret_cast<const char*>(response.value().payload.data()),
                    response.value().payload.size());
        clean = response.value().code == ErrorCode::Ok && text.find("clean=true") != std::string::npos;
      } else {
        text = response.status().describe();
      }
      client.value().close();
    }
    harness.check(clean, clean ? "audit clean" : text);
  }

  harness.begin("clean shutdown of every governed process");
  harness.phase("SHUTDOWN");
  {
    auto client = Client::connect(endpoint, SessionRole::Admin, "demo");
    if (client.ok()) {
      std::vector<std::byte> empty;
      (void)client.value().call(Op::Shutdown, empty);
      client.value().close();
    }
    bool exited = false;
    std::string detail = "coordinator process handle was lost";
    if (coordinator.process) {
      const ProcessResult result = coordinator.process->wait(40000);
      coordinator.process.reset();
      exited = result.started && !result.timed_out;
      detail = "coordinator exit=" + std::to_string(result.exit_code);
    }
    harness.check(exited, detail);
    alpha.kill();
    beta.kill();
  }

  harness.begin("zero leaked compiler child processes");
  harness.phase("SHUTDOWN");
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(800));
    const std::set<std::uint32_t> after = processes_named({"cl.exe", "link.exe", "nvcc.exe"});
    std::size_t leaked = 0;
    for (std::uint32_t pid : after) {
      if (baseline_compilers.count(pid) == 0) ++leaked;
    }
    harness.check(leaked == 0, leaked == 0 ? "no orphaned compiler processes"
                                           : "leaked compiler processes: " + std::to_string(leaked));
  }

  stop_all();
  shutdown_network();
  if (!keep) (void)remove_tree_quiet(root);

  emit("DC_CLI_DEMO cases=" + std::to_string(harness.results.size()) + " failures=" +
       std::to_string(harness.failures) + (harness.failures == 0 ? " ok=yes" : " ok=no"));
  std::fflush(stdout);
  return harness.failures == 0 ? 0 : 1;
}

