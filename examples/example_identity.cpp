// Distributed Compilation - example: canonical request identity.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// Demonstrates that identity is content-derived: reordering order-insensitive
// inputs does not change it, while changing any semantic input does.
#include <cstdio>
#include <string>
#include <vector>

#include "dc/codec.hpp"
#include "dc/compiler.hpp"
#include "dc/coordinator.hpp"

using namespace dc;

namespace {

void line(const std::string& text) { std::printf("%s\n", text.c_str()); }

Blob make_blob(const std::string& text) {
  Blob blob;
  blob.bytes.assign(reinterpret_cast<const std::byte*>(text.data()),
                    reinterpret_cast<const std::byte*>(text.data()) + text.size());
  blob.digest = sha256(std::span<const std::byte>(blob.bytes.data(), blob.bytes.size()));
  return blob;
}

ToolchainIdentity pick_toolchain() {
  DiscoveryOptions options;
  options.include_synthetic = true;
  options.cuda_roots = {};
  DiscoveryResult discovered = discover_toolchains(options);
  for (const auto& candidate : discovered.toolchains) {
    if (candidate.family == CompilerFamily::Msvc) return candidate;
  }
  return discovered.toolchains.front();
}

TargetIdentity pick_target() {
  DiscoveryOptions options;
  options.include_synthetic = true;
  options.cuda_roots = {};
  for (const auto& candidate : discover_toolchains(options).targets) {
    if (candidate.triple == "x86_64-pc-windows-msvc") return candidate;
  }
  return discover_toolchains(options).targets.front();
}

SubmissionBundle build(const std::vector<DependencyEntry>& dependencies, const std::vector<Blob>& blobs,
                       const std::string& source_text) {
  SubmissionBundle bundle;
  bundle.request.toolchain = pick_toolchain();
  bundle.request.target = pick_target();
  bundle.request.request_id = RequestId(1);
  bundle.request.policy.require_provable_toolchain = false;
  bundle.request.specialization.fields.push_back(SpecField::make_signed("tile", 128));
  bundle.request.specialization.fields.push_back(SpecField::make_text("dtype", "fp16"));
  const Blob source = make_blob(source_text);
  CompilationUnitSpec unit;
  unit.index = 0;
  unit.logical_name = "kernel.cpp";
  unit.kind = UnitKind::Compile;
  unit.output_kind = OutputKind::Assembly;
  UnitSource unit_source;
  unit_source.logical_name = "kernel.cpp";
  unit_source.format = InputFormat::Source;
  unit_source.language_mode = "c++20";
  unit_source.content.digest = source.digest;
  unit_source.content.size = source.bytes.size();
  unit.sources.push_back(unit_source);
  bundle.request.units.push_back(unit);
  bundle.blobs.push_back(source);
  for (const Blob& blob : blobs) bundle.blobs.push_back(blob);
  bundle.request.dependencies.entries = dependencies;
  return bundle;
}

}  // namespace

int main() {
  const std::string source = "int kernel() { return 42; }\n";
  const Blob header_a = make_blob("#pragma once\nint a();\n");
  const Blob header_b = make_blob("#pragma once\nint b();\n");
  const Blob header_b_changed = make_blob("#pragma once\nint b();\n// changed\n");

  DependencyEntry entry_a;
  entry_a.name = "a.h";
  entry_a.kind = DependencyKind::Header;
  entry_a.content.digest = header_a.digest;
  entry_a.content.size = header_a.bytes.size();
  DependencyEntry entry_b = entry_a;
  entry_b.name = "b.h";
  entry_b.content.digest = header_b.digest;
  entry_b.content.size = header_b.bytes.size();

  SubmissionBundle forward = build({entry_a, entry_b}, {header_a, header_b}, source);
  SubmissionBundle reverse = build({entry_b, entry_a}, {header_b, header_a}, source);
  if (!canonicalize(forward.request).ok() || !canonicalize(reverse.request).ok()) {
    line("example: canonicalization failed");
    return 1;
  }
  line("request identity (declared order):  " + forward.request.request_identity.hex());
  line("request identity (reversed order):  " + reverse.request.request_identity.hex());
  line(std::string("order-independent inputs agree: ") +
       (forward.request.request_identity == reverse.request.request_identity ? "yes" : "no"));

  DependencyEntry changed_entry = entry_b;
  changed_entry.content.digest = header_b_changed.digest;
  changed_entry.content.size = header_b_changed.bytes.size();
  SubmissionBundle mutated = build({entry_a, changed_entry}, {header_a, header_b_changed}, source);
  canonicalize(mutated.request);
  line("request identity (b.h changed):     " + mutated.request.request_identity.hex());
  line(std::string("dependency content change alters identity: ") +
       (mutated.request.request_identity != forward.request.request_identity ? "yes" : "no"));

  SubmissionBundle other_flags = forward;
  other_flags.request.flags = {"/DFAST"};
  canonicalize(other_flags.request);
  line(std::string("flag change alters identity: ") +
       (other_flags.request.request_identity != forward.request.request_identity ? "yes" : "no"));

  line("unit identity:                      " + forward.request.units.front().identity_digest.hex());
  line("dependency set identity:            " + forward.request.dependencies.identity_digest.hex());
  line("specialization identity:            " + forward.request.specialization.identity_digest.hex());
  line("toolchain identity:                 " + forward.request.toolchain.identity_digest.hex());
  line("target identity:                    " + forward.request.target.identity_digest.hex());
  return 0;
}
