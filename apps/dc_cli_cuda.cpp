// Distributed Compilation - real CUDA compilation and execution proof.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// This compiles a real CUDA kernel with a real nvcc for a real SM architecture,
// commits the resulting device image through the normal compilation
// transaction, then loads and executes it on the physical GPU. Where more than
// one CUDA toolkit is installed, both are exercised and their toolchain
// identities are shown to be distinct, so a cache entry produced by one toolkit
// can never satisfy the other.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "app_common.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"
#include "dc/persistence.hpp"
#include "dc/process.hpp"
#include "dc/wire.hpp"

namespace {

using namespace dc;
using namespace dc::app;

const char* kKernelSource =
    "extern \"C\" __global__ void vecadd(const float* a, const float* b, float* c, int n) {\n"
    "  int i = blockIdx.x * blockDim.x + threadIdx.x;\n"
    "  if (i < n) c[i] = a[i] + b[i];\n"
    "}\n";

struct RunOutcome {
  Status status;
  CompilationId compilation = CompilationId(0);
  Digest256 artifact;
  bool reused = false;
};

RunOutcome compile_kernel(Coordinator& coordinator, const ToolchainIdentity& toolchain,
                          const TargetIdentity& target, SessionId session, const std::filesystem::path& scratch,
                          bool expect_reuse) {
  RunOutcome outcome;
  Blob source;
  const std::string text = kKernelSource;
  source.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                      reinterpret_cast<const std::byte*>(text.data()) + text.size());
  source.digest = sha256(std::span<const std::byte>(source.bytes.data(), source.bytes.size()));

  SubmissionBundle bundle;
  bundle.request.toolchain = toolchain;
  bundle.request.target = target;
  bundle.request.request_id = RequestId(77);
  bundle.request.policy.reproducibility = ReproducibilityRequirement::Preferred;
  CompilationUnitSpec unit;
  unit.index = 0;
  unit.logical_name = "vecadd.cu";
  unit.kind = UnitKind::Compile;
  unit.output_kind = OutputKind::Cubin;
  UnitSource unit_source;
  unit_source.logical_name = "vecadd.cu";
  unit_source.format = InputFormat::Source;
  unit_source.language_mode = "cuda-c++17";
  unit_source.content.digest = source.digest;
  unit_source.content.size = source.bytes.size();
  unit.sources.push_back(unit_source);
  bundle.request.units.push_back(unit);
  bundle.blobs.push_back(source);

  auto submitted = coordinator.submit(bundle);
  if (!submitted.ok()) {
    outcome.status = submitted.status();
    return outcome;
  }
  outcome.compilation = submitted.value().units.front().compilation;
  outcome.reused = submitted.value().served_from_cache;
  if (submitted.value().all_committed) {
    auto commit = coordinator.commit(outcome.compilation);
    if (commit.ok()) outcome.artifact = commit.value().artifact_digest;
    outcome.status = Status::success();
    return outcome;
  }
  if (expect_reuse && !submitted.value().served_from_cache) {
    outcome.status = Status::error(ErrorCode::CacheMiss, "expected validated cache reuse but the request missed");
    return outcome;
  }

  const std::vector<Assignment> assignments = coordinator.pump();
  const Assignment* chosen = nullptr;
  for (const auto& assignment : assignments) {
    if (assignment.compilation == outcome.compilation) chosen = &assignment;
  }
  if (chosen == nullptr) {
    outcome.status = Status::error(ErrorCode::NoEligibleWorker, "no assignment was produced");
    return outcome;
  }
  // Mirror the worker protocol: the lease must be acknowledged before a result
  // may be reported.
  Status begun = coordinator.begin_compile(chosen->claim);
  if (!begun.ok()) {
    outcome.status = begun;
    return outcome;
  }
  auto compiled = run_compile_unit(*chosen, toolchain, scratch, nullptr);
  if (!compiled.ok()) {
    outcome.status = compiled.status();
    return outcome;
  }
  ReportOutput output;
  output.claim = chosen->claim;
  output.kind = OutputKind::Cubin;
  output.logical_name = "vecadd.cubin";
  output.bytes = compiled.value().artifact;
  output.declared_digest = sha256(std::span<const std::byte>(output.bytes.data(), output.bytes.size()));
  output.compiler_invocation = compiled.value().invocation;
  output.compiler_version_string = compiled.value().compiler_version;
  output.compiler_wall_millis = compiled.value().wall_millis;
  auto decision = coordinator.report_output(session, output);
  if (!decision.ok()) {
    outcome.status = decision.status();
    return outcome;
  }
  if (decision.value().outcome != CommitOutcome::Committed) {
    outcome.status = Status::error(decision.value().error, decision.value().detail);
    return outcome;
  }
  outcome.artifact = decision.value().commit.artifact_digest;
  outcome.status = Status::success();
  return outcome;
}

}  // namespace

int run_cuda_proof(const Arguments& arguments) {
  const std::filesystem::path bin = arguments.get("bin", executable_directory().string());
  const std::filesystem::path probe = bin / "dc_cuda_probe.exe";
  if (!std::filesystem::exists(probe)) {
    emit_error("dc_cli cuda-proof: dc_cuda_probe.exe is not available (built only when a CUDA toolkit is found)");
    return 3;
  }

  DiscoveryOptions discovery;
  discovery.msvc_roots = default_msvc_roots();
  discovery.cuda_roots = default_cuda_roots();
  for (const auto& architecture : arguments.all("arch")) discovery.cuda_architectures.push_back(architecture);
  if (discovery.cuda_architectures.empty()) discovery.cuda_architectures.push_back("sm_120");
  const DiscoveryResult discovered = discover_toolchains(discovery);

  std::vector<const ToolchainIdentity*> cuda_toolchains;
  for (const auto& toolchain : discovered.toolchains) {
    if (toolchain.family == CompilerFamily::NvidiaNvcc) cuda_toolchains.push_back(&toolchain);
  }
  if (cuda_toolchains.empty()) {
    emit("DC_CUDA_PROOF ok=no reason=no_cuda_toolkit_found");
    return 3;
  }
  emit("cuda toolkits discovered: " + std::to_string(cuda_toolchains.size()));
  for (const auto* toolchain : cuda_toolchains) {
    emit("  toolkit " + toolchain->version_string + " identity " + toolchain->identity_digest.hex());
  }
  if (cuda_toolchains.size() > 1) {
    bool distinct = true;
    for (std::size_t i = 1; i < cuda_toolchains.size(); ++i) {
      if (cuda_toolchains[i]->identity_digest == cuda_toolchains[0]->identity_digest) distinct = false;
    }
    emit(std::string("toolkit identities distinct: ") + (distinct ? "yes" : "no"));
  }

  const TargetIdentity* cubin_target = nullptr;
  for (const auto& candidate : discovered.targets) {
    if (candidate.accelerator.vendor == AcceleratorVendor::Nvidia) {
      if (cubin_target == nullptr ||
          candidate.accelerator.device_runtime ==
              "cuda-" + cuda_toolchains.front()->version_string) {
        cubin_target = &candidate;
      }
    }
  }
  if (cubin_target == nullptr) {
    emit("DC_CUDA_PROOF ok=no reason=no_cubin_target");
    return 3;
  }

  const std::filesystem::path root = arguments.get("work", unique_temp_path("dc-cuda").string());
  const std::filesystem::path state_dir = root / "state";
  const std::filesystem::path scratch = root / "scratch";
  if (!ensure_directory(state_dir).ok() || !ensure_directory(scratch).ok()) {
    emit_error("dc_cli cuda-proof: cannot create the working directory");
    return 3;
  }

  CoordinatorConfig config;
  config.state_root = state_dir;
  config.enable_persistence = true;
  Coordinator coordinator;
  Status opened = coordinator.open(config);
  if (!opened.ok()) {
    emit_error("dc_cli cuda-proof: cannot open the coordinator: " + opened.describe());
    return 3;
  }

  const ToolchainIdentity& toolchain = *cuda_toolchains.front();
  WorkerCapabilities capabilities;
  capabilities.toolchains = {toolchain};
  capabilities.targets = {*cubin_target};
  capabilities.input_formats = {InputFormat::Source};
  capabilities.logical_cores = 8;
  capabilities.memory_bytes = 16ull * 1024 * 1024 * 1024;
  capabilities.scratch_bytes = 16ull * 1024 * 1024 * 1024;
  capabilities.max_artifact_bytes = 64ull * 1024 * 1024;
  capabilities.filesystem_isolation = true;
  capabilities.sandbox = true;
  capabilities.deterministic_build = true;
  capabilities.trusted = true;
  capabilities.evidence = EvidenceClass::Real;
  capabilities.host = "local";
  canonicalize(capabilities);

  WorkerRegistration registration;
  registration.endpoint = "local";
  registration.host = "local";
  registration.worker_id = WorkerId(5001);
  registration.boot_id = WorkerBootId(6001);
  registration.max_inflight = 1;
  registration.capabilities = capabilities;
  auto registered = coordinator.register_worker(registration);
  if (!registered.ok()) {
    emit_error("dc_cli cuda-proof: worker registration refused: " + registered.status().describe());
    coordinator.close();
    (void)remove_tree_quiet(root);
    return 4;
  }
  (void)coordinator.mark_ready(registered.value().session);

  RunOutcome first = compile_kernel(coordinator, toolchain, *cubin_target, registered.value().session, scratch, false);
  if (!first.status.ok()) {
    emit("DC_CUDA_PROOF ok=no reason=compilation_failed detail=" + first.status.describe());
    coordinator.close();
    (void)remove_tree_quiet(root);
    return 5;
  }
  emit("cuda compilation committed: " + first.artifact.hex());

  auto artifact = coordinator.artifact_bytes(first.compilation);
  if (!artifact.ok()) {
    emit("DC_CUDA_PROOF ok=no reason=artifact_unavailable");
    coordinator.close();
    (void)remove_tree_quiet(root);
    return 5;
  }
  const std::filesystem::path cubin_path = root / "vecadd.cubin";
  Status written = write_file_atomic(cubin_path,
                                     std::span<const std::byte>(artifact.value().data(), artifact.value().size()),
                                     false);
  if (!written.ok()) {
    emit("DC_CUDA_PROOF ok=no reason=cannot_write_cubin");
    coordinator.close();
    (void)remove_tree_quiet(root);
    return 5;
  }
  emit("device image bytes: " + std::to_string(artifact.value().size()));

  ProcessSpec probe_spec;
  probe_spec.executable = probe;
  probe_spec.arguments = {cubin_path.string(), arguments.get("elements", "1048576")};
  probe_spec.inherit_environment = true;
  probe_spec.timeout_millis = 60000;
  probe_spec.max_output_bytes = 1u << 20;
  const ProcessResult probe_result = run_process(probe_spec);
  std::fwrite(probe_result.stdout_text.data(), 1, probe_result.stdout_text.size(), stdout);
  if (!probe_result.stderr_text.empty()) {
    std::fwrite(probe_result.stderr_text.data(), 1, probe_result.stderr_text.size(), stderr);
  }
  std::fflush(stdout);
  const bool executed = probe_result.started && probe_result.exit_code == 0;

  bool second_reused = false;
  if (cuda_toolchains.size() > 1) {
    const ToolchainIdentity& other = *cuda_toolchains[1];
    WorkerCapabilities other_caps = capabilities;
    other_caps.toolchains = {other};
    canonicalize(other_caps);
    WorkerRegistration other_registration;
    other_registration.endpoint = "local-2";
    other_registration.host = "local";
    other_registration.worker_id = WorkerId(5002);
    other_registration.boot_id = WorkerBootId(6002);
    other_registration.max_inflight = 1;
    other_registration.capabilities = other_caps;
    auto other_worker = coordinator.register_worker(other_registration);
    if (other_worker.ok()) {
      (void)coordinator.mark_ready(other_worker.value().session);
      const TargetIdentity* other_target = cubin_target;
      for (const auto& candidate : discovered.targets) {
        if (candidate.accelerator.vendor == AcceleratorVendor::Nvidia &&
            candidate.accelerator.device_runtime == "cuda-" + other.version_string) {
          other_target = &candidate;
        }
      }
      RunOutcome cross = compile_kernel(coordinator, other, *other_target, other_worker.value().session, scratch,
                                        false);
      second_reused = cross.reused;
      emit(std::string("cross-toolkit cache reuse: ") + (second_reused ? "REUSED" : "none") +
           " (second toolkit " + other.version_string + ")");
    }
  } else {
    RunOutcome again = compile_kernel(coordinator, toolchain, *cubin_target, registered.value().session, scratch,
                                      true);
    second_reused = again.reused;
    emit(std::string("repeat compilation reused validated cache: ") + (second_reused ? "yes" : "no"));
  }

  const AuditReport audit = coordinator.audit();
  emit("audit clean: " + std::string(audit.clean ? "yes" : "no"));

  coordinator.close();
  (void)remove_tree_quiet(root);

  const bool ok = executed && audit.clean && (cuda_toolchains.size() > 1 ? !second_reused : true);
  emit(std::string("DC_CUDA_PROOF ok=") + (ok ? "yes" : "no"));
  return ok ? 0 : 1;
}
