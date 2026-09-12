// Distributed Compilation - canonical codec implementation.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include "dc/codec.hpp"

#include <algorithm>

namespace dc {
namespace {

template <class EnumT>
void write_enum(CanonicalWriter& w, EnumT value) {
  w.u8(static_cast<std::uint8_t>(value));
}

template <class EnumT, class LimitT>
bool read_enum(CanonicalReader& r, EnumT& out, LimitT max_value) {
  std::uint8_t raw = 0;
  if (!r.read_u8(raw)) return false;
  if (raw > static_cast<std::uint8_t>(max_value)) {
    r.fail(ErrorCode::Malformed, "enum value out of domain");
    return false;
  }
  out = static_cast<EnumT>(raw);
  return true;
}

void write_sdk(CanonicalWriter& w, const SdkComponent& value) {
  w.str(value.name);
  w.str(value.version);
}

bool read_sdk(CanonicalReader& r, SdkComponent& out) {
  SdkComponent value;
  if (!r.read_str(value.name)) return false;
  if (!r.read_str(value.version)) return false;
  out = std::move(value);
  return true;
}

void write_plugin(CanonicalWriter& w, const PluginIdentity& value) {
  w.str(value.id);
  w.str(value.version);
  w.digest(value.digest);
}

bool read_plugin(CanonicalReader& r, PluginIdentity& out) {
  PluginIdentity value;
  if (!r.read_str(value.id)) return false;
  if (!r.read_str(value.version)) return false;
  if (!r.read_digest(value.digest)) return false;
  out = std::move(value);
  return true;
}

}  // namespace

void encode_content_ref(CanonicalWriter& w, const ContentRef& value) {
  w.digest(value.digest);
  w.u64(value.size);
}

bool decode_content_ref(CanonicalReader& r, ContentRef& out) {
  ContentRef value;
  if (!r.read_digest(value.digest)) return false;
  if (!r.read_u64(value.size)) return false;
  out = value;
  return true;
}

void encode_binary_identity(CanonicalWriter& w, const BinaryIdentity& value) {
  write_enum(w, value.state);
  w.digest(value.digest);
  w.u64(value.size);
  w.str(value.path);
  w.str(value.version_string);
}

bool decode_binary_identity(CanonicalReader& r, BinaryIdentity& out) {
  BinaryIdentity value;
  if (!read_enum(r, value.state, BinaryIdState::Unavailable)) return false;
  if (!r.read_digest(value.digest)) return false;
  if (!r.read_u64(value.size)) return false;
  if (!r.read_str(value.path)) return false;
  if (!r.read_str(value.version_string)) return false;
  if (value.state == BinaryIdState::Known && value.digest.is_zero()) {
    r.fail(ErrorCode::Malformed, "binary identity claims KNOWN with a zero digest");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_toolchain(CanonicalWriter& w, const ToolchainIdentity& value) {
  w.id(value.id);
  w.gen(value.generation);
  write_enum(w, value.family);
  w.str(value.version_string);
  w.u32(value.version_major);
  w.u32(value.version_minor);
  w.u32(value.version_patch);
  encode_binary_identity(w, value.compiler);
  encode_binary_identity(w, value.linker);
  encode_binary_identity(w, value.assembler);
  encode_binary_identity(w, value.runtime_library);
  w.list(static_cast<std::uint32_t>(value.sdk.size()));
  for (const auto& component : value.sdk) write_sdk(w, component);
  w.list(static_cast<std::uint32_t>(value.plugins.size()));
  for (const auto& plugin : value.plugins) write_plugin(w, plugin);
  write_string_list(w, value.target_libraries);
  w.list(static_cast<std::uint32_t>(value.configuration.size()));
  for (const auto& kv : value.configuration) {
    w.str(kv.first);
    w.str(kv.second);
  }
  write_enum(w, value.evidence);
  w.id(value.evidence_id);
  w.gen(value.evidence_generation);
  w.digest(value.identity_digest);
}

bool decode_toolchain(CanonicalReader& r, ToolchainIdentity& out) {
  ToolchainIdentity value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!read_enum(r, value.family, CompilerFamily::MsvcLinker)) return false;
  if (!r.read_str(value.version_string)) return false;
  if (!r.read_u32(value.version_major)) return false;
  if (!r.read_u32(value.version_minor)) return false;
  if (!r.read_u32(value.version_patch)) return false;
  if (!decode_binary_identity(r, value.compiler)) return false;
  if (!decode_binary_identity(r, value.linker)) return false;
  if (!decode_binary_identity(r, value.assembler)) return false;
  if (!decode_binary_identity(r, value.runtime_library)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.sdk.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!read_sdk(r, value.sdk[i])) return false;
  }
  if (!r.read_list(count)) return false;
  value.plugins.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!read_plugin(r, value.plugins[i])) return false;
  }
  if (!read_string_list(r, value.target_libraries)) return false;
  if (!r.read_list(count)) return false;
  value.configuration.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(value.configuration[i].first)) return false;
    if (!r.read_str(value.configuration[i].second)) return false;
  }
  if (!read_enum(r, value.evidence, EvidenceClass::Unsupported)) return false;
  if (!r.read_id(value.evidence_id)) return false;
  if (!r.read_gen(value.evidence_generation)) return false;
  if (!r.read_digest(value.identity_digest)) return false;

  // Recompute: identity digests are never trusted from the wire or from disk.
  const Digest256 claimed = value.identity_digest;
  canonicalize(value);
  if (claimed != value.identity_digest) {
    r.fail(ErrorCode::IntegrityFailure, "toolchain identity digest does not match its contents");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_target(CanonicalWriter& w, const TargetIdentity& value) {
  w.id(value.id);
  w.gen(value.generation);
  write_enum(w, value.os);
  write_enum(w, value.arch);
  write_enum(w, value.abi);
  w.str(value.triple);
  write_enum(w, value.object_format);
  write_enum(w, value.stdlib);
  w.str(value.runtime_abi);
  write_enum(w, value.accelerator.vendor);
  w.str(value.accelerator.architecture);
  w.u32(value.accelerator.compute_major);
  w.u32(value.accelerator.compute_minor);
  w.str(value.accelerator.isa);
  w.str(value.accelerator.device_runtime);
  write_enum(w, value.evidence);
  w.digest(value.identity_digest);
}

bool decode_target(CanonicalReader& r, TargetIdentity& out) {
  TargetIdentity value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!read_enum(r, value.os, OsKind::BareMetal)) return false;
  if (!read_enum(r, value.arch, ArchKind::RiscV64)) return false;
  if (!read_enum(r, value.abi, AbiKind::Gnu)) return false;
  if (!r.read_str(value.triple)) return false;
  if (!read_enum(r, value.object_format, ObjectFormat::Fatbin)) return false;
  if (!read_enum(r, value.stdlib, StdlibKind::None)) return false;
  if (!r.read_str(value.runtime_abi)) return false;
  if (!read_enum(r, value.accelerator.vendor, AcceleratorVendor::Unknown)) return false;
  if (!r.read_str(value.accelerator.architecture)) return false;
  if (!r.read_u32(value.accelerator.compute_major)) return false;
  if (!r.read_u32(value.accelerator.compute_minor)) return false;
  if (!r.read_str(value.accelerator.isa)) return false;
  if (!r.read_str(value.accelerator.device_runtime)) return false;
  if (!read_enum(r, value.evidence, EvidenceClass::Unsupported)) return false;
  if (!r.read_digest(value.identity_digest)) return false;
  const Digest256 claimed = value.identity_digest;
  const TargetId claimed_id = value.id;
  value.id = derive_target_id(value);
  value.identity_digest = compute_target_identity(value);
  if (claimed != value.identity_digest || claimed_id != value.id) {
    r.fail(ErrorCode::IntegrityFailure, "target identity does not match its contents");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_specialization(CanonicalWriter& w, const SpecializationSpec& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.list(static_cast<std::uint32_t>(value.fields.size()));
  for (const auto& field : value.fields) {
    w.str(field.name);
    write_enum(w, field.kind);
    w.i64(field.signed_value);
    w.u64(field.unsigned_value);
    w.f64(field.floating_value);
    w.str(field.text_value);
    w.boolean(field.boolean_value);
  }
  w.digest(value.identity_digest);
}

bool decode_specialization(CanonicalReader& r, SpecializationSpec& out) {
  SpecializationSpec value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.fields.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    SpecField& field = value.fields[i];
    if (!r.read_str(field.name)) return false;
    if (!read_enum(r, field.kind, SpecValueKind::Boolean)) return false;
    if (!r.read_i64(field.signed_value)) return false;
    if (!r.read_u64(field.unsigned_value)) return false;
    if (!r.read_f64(field.floating_value)) return false;
    if (!r.read_str(field.text_value)) return false;
    if (!r.read_bool(field.boolean_value)) return false;
  }
  if (!r.read_digest(value.identity_digest)) return false;
  const Digest256 claimed = value.identity_digest;
  const Status spec_status = canonicalize(value);
  if (!spec_status.ok()) {
    r.fail(ErrorCode::Malformed, "specialization rejected: " + spec_status.describe());
    return false;
  }
  if (claimed != value.identity_digest) {
    r.fail(ErrorCode::IntegrityFailure, "specialization identity digest does not match its contents");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_dependency_entry(CanonicalWriter& w, const DependencyEntry& value) {
  w.str(value.name);
  write_enum(w, value.kind);
  encode_content_ref(w, value.content);
  w.digest(value.identity_digest);
}

bool decode_dependency_entry(CanonicalReader& r, DependencyEntry& out) {
  DependencyEntry value;
  if (!r.read_str(value.name)) return false;
  if (!read_enum(r, value.kind, DependencyKind::Other)) return false;
  if (!decode_content_ref(r, value.content)) return false;
  if (!r.read_digest(value.identity_digest)) return false;
  if (compute_dependency_entry_identity(value) != value.identity_digest) {
    r.fail(ErrorCode::IntegrityFailure, "dependency entry identity digest mismatch");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_dependency_set(CanonicalWriter& w, const DependencySet& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.list(static_cast<std::uint32_t>(value.entries.size()));
  for (const auto& entry : value.entries) encode_dependency_entry(w, entry);
  w.digest(value.identity_digest);
}

bool decode_dependency_set(CanonicalReader& r, DependencySet& out) {
  DependencySet value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.entries.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_dependency_entry(r, value.entries[i])) return false;
  }
  if (!r.read_digest(value.identity_digest)) return false;
  const Digest256 claimed = value.identity_digest;
  canonicalize(value);
  if (claimed != value.identity_digest) {
    r.fail(ErrorCode::IntegrityFailure, "dependency set identity digest mismatch");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_environment(CanonicalWriter& w, const EnvironmentContract& value) {
  w.list(static_cast<std::uint32_t>(value.variables.size()));
  for (const auto& kv : value.variables) {
    w.str(kv.first);
    w.str(kv.second);
  }
  w.boolean(value.deterministic);
  w.boolean(value.inherit_process_environment);
}

bool decode_environment(CanonicalReader& r, EnvironmentContract& out) {
  EnvironmentContract value;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.variables.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(value.variables[i].first)) return false;
    if (!r.read_str(value.variables[i].second)) return false;
  }
  if (!r.read_bool(value.deterministic)) return false;
  if (!r.read_bool(value.inherit_process_environment)) return false;
  canonicalize(value);
  out = std::move(value);
  return true;
}

void encode_validation_requirements(CanonicalWriter& w, const ValidationRequirements& value) {
  w.boolean(value.require_format_check);
  w.boolean(value.require_digest_check);
  w.boolean(value.require_target_metadata);
  w.boolean(value.require_dependency_metadata);
  w.boolean(value.require_smoke_test);
  w.str(value.smoke_expected_stdout);
  w.u32(value.smoke_timeout_ms);
}

bool decode_validation_requirements(CanonicalReader& r, ValidationRequirements& out) {
  ValidationRequirements value;
  if (!r.read_bool(value.require_format_check)) return false;
  if (!r.read_bool(value.require_digest_check)) return false;
  if (!r.read_bool(value.require_target_metadata)) return false;
  if (!r.read_bool(value.require_dependency_metadata)) return false;
  if (!r.read_bool(value.require_smoke_test)) return false;
  if (!r.read_str(value.smoke_expected_stdout)) return false;
  if (!r.read_u32(value.smoke_timeout_ms)) return false;
  if (value.smoke_timeout_ms == 0 || value.smoke_timeout_ms > 3600000u) {
    r.fail(ErrorCode::LimitExceeded, "smoke test timeout out of bounds");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_policy(CanonicalWriter& w, const CompilePolicy& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.str(value.profile);
  write_enum(w, value.reproducibility);
  write_enum(w, value.cache);
  w.boolean(value.flag_order_significant);
  w.boolean(value.require_exact_generation);
  w.boolean(value.negative_cache_enabled);
  w.u32(value.negative_cache_max_entries);
  w.boolean(value.allow_speculative_duplication);
  w.u32(value.max_attempts_per_unit);
  w.boolean(value.require_trusted_workers);
  w.boolean(value.require_provable_toolchain);
  w.digest(value.identity_digest);
}

bool decode_policy(CanonicalReader& r, CompilePolicy& out) {
  CompilePolicy value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_str(value.profile)) return false;
  if (!read_enum(r, value.reproducibility, ReproducibilityRequirement::NotRequired)) return false;
  if (!read_enum(r, value.cache, CachePolicy::Bypass)) return false;
  if (!r.read_bool(value.flag_order_significant)) return false;
  if (!r.read_bool(value.require_exact_generation)) return false;
  if (!r.read_bool(value.negative_cache_enabled)) return false;
  if (!r.read_u32(value.negative_cache_max_entries)) return false;
  if (!r.read_bool(value.allow_speculative_duplication)) return false;
  if (!r.read_u32(value.max_attempts_per_unit)) return false;
  if (!r.read_bool(value.require_trusted_workers)) return false;
  if (!r.read_bool(value.require_provable_toolchain)) return false;
  if (!r.read_digest(value.identity_digest)) return false;
  if (value.max_attempts_per_unit == 0 || value.max_attempts_per_unit > 64) {
    r.fail(ErrorCode::LimitExceeded, "max_attempts_per_unit out of bounds");
    return false;
  }
  if (value.negative_cache_max_entries > 4096) {
    r.fail(ErrorCode::LimitExceeded, "negative cache bound out of range");
    return false;
  }
  const Digest256 claimed = value.identity_digest;
  value.id = derive_policy_id(value);
  value.identity_digest = compute_policy_identity(value);
  if (claimed != value.identity_digest) {
    r.fail(ErrorCode::IntegrityFailure, "policy identity digest mismatch");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_unit_spec(CanonicalWriter& w, const CompilationUnitSpec& value) {
  w.u32(value.index);
  w.str(value.logical_name);
  write_enum(w, value.kind);
  w.list(static_cast<std::uint32_t>(value.sources.size()));
  for (const auto& source : value.sources) {
    w.str(source.logical_name);
    write_enum(w, source.format);
    w.str(source.language_mode);
    encode_content_ref(w, source.content);
  }
  w.list(static_cast<std::uint32_t>(value.dependencies.size()));
  for (const auto& dep : value.dependencies) encode_dependency_entry(w, dep);
  write_string_list(w, value.flags);
  write_enum(w, value.output_kind);
  w.list(static_cast<std::uint32_t>(value.child_units.size()));
  for (std::uint32_t child : value.child_units) w.u32(child);
  w.boolean(value.mandatory);
  w.digest(value.identity_digest);
}

bool decode_unit_spec(CanonicalReader& r, CompilationUnitSpec& out) {
  CompilationUnitSpec value;
  if (!r.read_u32(value.index)) return false;
  if (!r.read_str(value.logical_name)) return false;
  if (!read_enum(r, value.kind, UnitKind::Link)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.sources.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    UnitSource& source = value.sources[i];
    if (!r.read_str(source.logical_name)) return false;
    if (!read_enum(r, source.format, InputFormat::Other)) return false;
    if (!r.read_str(source.language_mode)) return false;
    if (!decode_content_ref(r, source.content)) return false;
  }
  if (!r.read_list(count)) return false;
  value.dependencies.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_dependency_entry(r, value.dependencies[i])) return false;
  }
  if (!read_string_list(r, value.flags)) return false;
  if (!read_enum(r, value.output_kind, OutputKind::PreprocessedSource)) return false;
  if (!r.read_list(count)) return false;
  value.child_units.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_u32(value.child_units[i])) return false;
  }
  if (!r.read_bool(value.mandatory)) return false;
  if (!r.read_digest(value.identity_digest)) return false;
  out = std::move(value);
  return true;
}

void encode_request(CanonicalWriter& w, const CompilationRequest& value) {
  w.id(value.request_id);
  w.gen(value.request_generation);
  encode_toolchain(w, value.toolchain);
  encode_target(w, value.target);
  encode_specialization(w, value.specialization);
  encode_policy(w, value.policy);
  encode_dependency_set(w, value.dependencies);
  encode_environment(w, value.environment);
  write_string_list(w, value.flags);
  encode_validation_requirements(w, value.validation);
  w.list(static_cast<std::uint32_t>(value.units.size()));
  for (const auto& unit : value.units) encode_unit_spec(w, unit);
  w.digest(value.authority_generation);
  w.digest(value.request_identity);
}

bool decode_request(CanonicalReader& r, CompilationRequest& out) {
  CompilationRequest value;
  if (!r.read_id(value.request_id)) return false;
  if (!r.read_gen(value.request_generation)) return false;
  if (!decode_toolchain(r, value.toolchain)) return false;
  if (!decode_target(r, value.target)) return false;
  if (!decode_specialization(r, value.specialization)) return false;
  if (!decode_policy(r, value.policy)) return false;
  if (!decode_dependency_set(r, value.dependencies)) return false;
  if (!decode_environment(r, value.environment)) return false;
  if (!read_string_list(r, value.flags)) return false;
  if (!decode_validation_requirements(r, value.validation)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.units.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_unit_spec(r, value.units[i])) return false;
  }
  if (!r.read_digest(value.authority_generation)) return false;
  if (!r.read_digest(value.request_identity)) return false;

  const Digest256 claimed_request = value.request_identity;
  std::vector<Digest256> claimed_units;
  claimed_units.reserve(value.units.size());
  for (const auto& unit : value.units) claimed_units.push_back(unit.identity_digest);

  const Status canonical_status = canonicalize(value);
  if (!canonical_status.ok()) {
    r.fail(ErrorCode::Malformed, "request rejected during canonicalization: " + canonical_status.describe());
    return false;
  }
  if (claimed_request != value.request_identity) {
    r.fail(ErrorCode::IntegrityFailure, "request identity digest does not match its contents");
    return false;
  }
  for (std::size_t i = 0; i < value.units.size(); ++i) {
    if (claimed_units[i] != value.units[i].identity_digest) {
      r.fail(ErrorCode::IntegrityFailure, "unit identity digest does not match its contents");
      return false;
    }
  }
  out = std::move(value);
  return true;
}

void encode_capabilities(CanonicalWriter& w, const WorkerCapabilities& value) {
  w.list(static_cast<std::uint32_t>(value.toolchains.size()));
  for (const auto& toolchain : value.toolchains) encode_toolchain(w, toolchain);
  w.list(static_cast<std::uint32_t>(value.targets.size()));
  for (const auto& target : value.targets) encode_target(w, target);
  w.list(static_cast<std::uint32_t>(value.input_formats.size()));
  for (InputFormat format : value.input_formats) write_enum(w, format);
  w.list(static_cast<std::uint32_t>(value.plugins.size()));
  for (const auto& plugin : value.plugins) write_plugin(w, plugin);
  w.list(static_cast<std::uint32_t>(value.sdks.size()));
  for (const auto& sdk : value.sdks) write_sdk(w, sdk);
  w.u32(value.logical_cores);
  w.u64(value.memory_bytes);
  w.u64(value.scratch_bytes);
  w.u64(value.max_artifact_bytes);
  w.boolean(value.filesystem_isolation);
  w.boolean(value.sandbox);
  w.boolean(value.deterministic_build);
  w.boolean(value.remote_cache_access);
  w.boolean(value.artifact_store_access);
  w.boolean(value.trusted);
  write_enum(w, value.evidence);
  w.str(value.host);
  w.digest(value.digest);
}

bool decode_capabilities(CanonicalReader& r, WorkerCapabilities& out) {
  WorkerCapabilities value;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.toolchains.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_toolchain(r, value.toolchains[i])) return false;
  }
  if (!r.read_list(count)) return false;
  value.targets.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_target(r, value.targets[i])) return false;
  }
  if (!r.read_list(count)) return false;
  value.input_formats.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!read_enum(r, value.input_formats[i], InputFormat::Other)) return false;
  }
  if (!r.read_list(count)) return false;
  value.plugins.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!read_plugin(r, value.plugins[i])) return false;
  }
  if (!r.read_list(count)) return false;
  value.sdks.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!read_sdk(r, value.sdks[i])) return false;
  }
  if (!r.read_u32(value.logical_cores)) return false;
  if (!r.read_u64(value.memory_bytes)) return false;
  if (!r.read_u64(value.scratch_bytes)) return false;
  if (!r.read_u64(value.max_artifact_bytes)) return false;
  if (!r.read_bool(value.filesystem_isolation)) return false;
  if (!r.read_bool(value.sandbox)) return false;
  if (!r.read_bool(value.deterministic_build)) return false;
  if (!r.read_bool(value.remote_cache_access)) return false;
  if (!r.read_bool(value.artifact_store_access)) return false;
  if (!r.read_bool(value.trusted)) return false;
  if (!read_enum(r, value.evidence, EvidenceClass::Unsupported)) return false;
  if (!r.read_str(value.host)) return false;
  if (!r.read_digest(value.digest)) return false;
  const Digest256 claimed = value.digest;
  canonicalize(value);
  if (claimed != value.digest) {
    r.fail(ErrorCode::IntegrityFailure, "capability digest does not match its contents");
    return false;
  }
  out = std::move(value);
  return true;
}

void encode_worker(CanonicalWriter& w, const WorkerRecord& value) {
  w.id(value.id);
  w.id(value.boot);
  w.gen(value.generation);
  w.id(value.session);
  w.str(value.endpoint);
  w.str(value.host);
  encode_capabilities(w, value.capabilities);
  write_enum(w, value.health);
  w.boolean(value.ready);
  w.boolean(value.fenced);
  w.boolean(value.trusted_evidence_fresh);
  w.u32(value.queue_depth);
  w.u32(value.in_flight);
  w.u64(value.completed_units);
  w.u64(value.failed_units);
  w.u64(value.total_compile_millis);
  w.u64(value.cache_affinity_hits);
  w.i64(value.registered_at);
  w.i64(value.last_seen);
  w.list(static_cast<std::uint32_t>(value.active_leases.size()));
  for (LeaseId lease : value.active_leases) w.id(lease);
}

bool decode_worker(CanonicalReader& r, WorkerRecord& out) {
  WorkerRecord value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_id(value.boot)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.session)) return false;
  if (!r.read_str(value.endpoint)) return false;
  if (!r.read_str(value.host)) return false;
  if (!decode_capabilities(r, value.capabilities)) return false;
  if (!read_enum(r, value.health, WorkerHealth::Draining)) return false;
  if (!r.read_bool(value.ready)) return false;
  if (!r.read_bool(value.fenced)) return false;
  if (!r.read_bool(value.trusted_evidence_fresh)) return false;
  if (!r.read_u32(value.queue_depth)) return false;
  if (!r.read_u32(value.in_flight)) return false;
  if (!r.read_u64(value.completed_units)) return false;
  if (!r.read_u64(value.failed_units)) return false;
  if (!r.read_u64(value.total_compile_millis)) return false;
  if (!r.read_u64(value.cache_affinity_hits)) return false;
  if (!r.read_i64(value.registered_at)) return false;
  if (!r.read_i64(value.last_seen)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.active_leases.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_id(value.active_leases[i])) return false;
  }
  out = std::move(value);
  return true;
}

void encode_lease(CanonicalWriter& w, const CompileLease& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  w.id(value.unit);
  w.id(value.attempt);
  w.id(value.worker);
  w.id(value.worker_boot);
  w.gen(value.worker_generation);
  w.gen(value.epoch);
  w.i64(value.issued_at);
  w.boolean(value.revoked);
  w.str(value.revocation_reason);
}

bool decode_lease(CanonicalReader& r, CompileLease& out) {
  CompileLease value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!r.read_id(value.unit)) return false;
  if (!r.read_id(value.attempt)) return false;
  if (!r.read_id(value.worker)) return false;
  if (!r.read_id(value.worker_boot)) return false;
  if (!r.read_gen(value.worker_generation)) return false;
  if (!r.read_gen(value.epoch)) return false;
  if (!r.read_i64(value.issued_at)) return false;
  if (!r.read_bool(value.revoked)) return false;
  if (!r.read_str(value.revocation_reason)) return false;
  out = std::move(value);
  return true;
}

void encode_validation_report(CanonicalWriter& w, const ValidationReport& value) {
  w.id(value.id);
  w.list(static_cast<std::uint32_t>(value.checks.size()));
  for (const auto& check : value.checks) {
    w.str(check.check);
    write_enum(w, check.outcome);
    w.str(check.detail);
  }
  write_enum(w, value.aggregate);
  w.str(value.summary);
}

bool decode_validation_report(CanonicalReader& r, ValidationReport& out) {
  ValidationReport value;
  if (!r.read_id(value.id)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  if (count > 4096) {
    r.fail(ErrorCode::LimitExceeded, "validation check count out of range");
    return false;
  }
  value.checks.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_str(value.checks[i].check)) return false;
    if (!read_enum(r, value.checks[i].outcome, ValidationOutcome::Unknown)) return false;
    if (!r.read_str(value.checks[i].detail)) return false;
  }
  if (!read_enum(r, value.aggregate, ValidationOutcome::Unknown)) return false;
  if (!r.read_str(value.summary)) return false;
  out = std::move(value);
  return true;
}

void encode_attempt(CanonicalWriter& w, const CompilationAttempt& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  w.id(value.unit);
  w.id(value.worker);
  w.id(value.worker_boot);
  w.gen(value.worker_generation);
  w.id(value.lease);
  w.gen(value.lease_generation);
  w.gen(value.epoch);
  write_enum(w, value.state);
  w.u32(value.ordinal);
  w.boolean(value.speculative);
  w.i64(value.created_at);
  w.i64(value.started_at);
  w.i64(value.finished_at);
  w.u16(static_cast<std::uint16_t>(value.failure));
  w.str(value.failure_detail);
  encode_validation_report(w, value.validation);
  encode_content_ref(w, value.candidate);
  w.digest(value.candidate_digest);
  w.id(value.artifact);
  w.u64(value.compiler_wall_millis);
  w.str(value.compiler_invocation);
  w.str(value.compiler_version_string);
}

bool decode_attempt(CanonicalReader& r, CompilationAttempt& out) {
  CompilationAttempt value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!r.read_id(value.unit)) return false;
  if (!r.read_id(value.worker)) return false;
  if (!r.read_id(value.worker_boot)) return false;
  if (!r.read_gen(value.worker_generation)) return false;
  if (!r.read_id(value.lease)) return false;
  if (!r.read_gen(value.lease_generation)) return false;
  if (!r.read_gen(value.epoch)) return false;
  if (!read_enum(r, value.state, AttemptState::Retired)) return false;
  if (!r.read_u32(value.ordinal)) return false;
  if (!r.read_bool(value.speculative)) return false;
  if (!r.read_i64(value.created_at)) return false;
  if (!r.read_i64(value.started_at)) return false;
  if (!r.read_i64(value.finished_at)) return false;
  std::uint16_t failure = 0;
  if (!r.read_u16(failure)) return false;
  if (failure > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "attempt failure code out of domain");
    return false;
  }
  value.failure = static_cast<ErrorCode>(failure);
  if (!r.read_str(value.failure_detail)) return false;
  if (!decode_validation_report(r, value.validation)) return false;
  if (!decode_content_ref(r, value.candidate)) return false;
  if (!r.read_digest(value.candidate_digest)) return false;
  if (!r.read_id(value.artifact)) return false;
  if (!r.read_u64(value.compiler_wall_millis)) return false;
  if (!r.read_str(value.compiler_invocation)) return false;
  if (!r.read_str(value.compiler_version_string)) return false;
  out = std::move(value);
  return true;
}

void encode_provenance(CanonicalWriter& w, const Provenance& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  w.id(value.unit);
  w.id(value.attempt);
  w.gen(value.attempt_generation);
  w.gen(value.epoch);
  w.id(value.worker);
  w.id(value.worker_boot);
  w.gen(value.worker_generation);
  w.id(value.lease);
  w.gen(value.lease_generation);
  w.id(value.request_id);
  w.digest(value.request_identity);
  w.digest(value.unit_identity);
  encode_content_ref(w, value.artifact);
  w.digest(value.source_identity);
  w.digest(value.ir_identity);
  w.digest(value.dependency_identity);
  w.digest(value.toolchain_identity);
  w.digest(value.target_identity);
  w.digest(value.specialization_identity);
  w.digest(value.policy_identity);
  w.id(value.validation);
  write_enum(w, value.evidence);
  w.str(value.compiler_invocation);
  w.str(value.compiler_version_string);
  w.u64(value.compiler_wall_millis);
  w.i64(value.produced_at);
}

bool decode_provenance(CanonicalReader& r, Provenance& out) {
  Provenance value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!r.read_id(value.unit)) return false;
  if (!r.read_id(value.attempt)) return false;
  if (!r.read_gen(value.attempt_generation)) return false;
  if (!r.read_gen(value.epoch)) return false;
  if (!r.read_id(value.worker)) return false;
  if (!r.read_id(value.worker_boot)) return false;
  if (!r.read_gen(value.worker_generation)) return false;
  if (!r.read_id(value.lease)) return false;
  if (!r.read_gen(value.lease_generation)) return false;
  if (!r.read_id(value.request_id)) return false;
  if (!r.read_digest(value.request_identity)) return false;
  if (!r.read_digest(value.unit_identity)) return false;
  if (!decode_content_ref(r, value.artifact)) return false;
  if (!r.read_digest(value.source_identity)) return false;
  if (!r.read_digest(value.ir_identity)) return false;
  if (!r.read_digest(value.dependency_identity)) return false;
  if (!r.read_digest(value.toolchain_identity)) return false;
  if (!r.read_digest(value.target_identity)) return false;
  if (!r.read_digest(value.specialization_identity)) return false;
  if (!r.read_digest(value.policy_identity)) return false;
  if (!r.read_id(value.validation)) return false;
  if (!read_enum(r, value.evidence, EvidenceClass::Unsupported)) return false;
  if (!r.read_str(value.compiler_invocation)) return false;
  if (!r.read_str(value.compiler_version_string)) return false;
  if (!r.read_u64(value.compiler_wall_millis)) return false;
  if (!r.read_i64(value.produced_at)) return false;
  out = std::move(value);
  return true;
}

void encode_commit(CanonicalWriter& w, const ArtifactCommit& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  w.id(value.unit);
  w.id(value.artifact);
  w.gen(value.artifact_generation);
  w.digest(value.artifact_digest);
  w.id(value.provenance);
  w.id(value.validation);
  w.gen(value.epoch);
  w.id(value.worker);
  w.id(value.worker_boot);
  w.id(value.attempt);
  w.i64(value.committed_at);
  w.boolean(value.deduplicated);
  w.boolean(value.superseded);
}

bool decode_commit(CanonicalReader& r, ArtifactCommit& out) {
  ArtifactCommit value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!r.read_id(value.unit)) return false;
  if (!r.read_id(value.artifact)) return false;
  if (!r.read_gen(value.artifact_generation)) return false;
  if (!r.read_digest(value.artifact_digest)) return false;
  if (!r.read_id(value.provenance)) return false;
  if (!r.read_id(value.validation)) return false;
  if (!r.read_gen(value.epoch)) return false;
  if (!r.read_id(value.worker)) return false;
  if (!r.read_id(value.worker_boot)) return false;
  if (!r.read_id(value.attempt)) return false;
  if (!r.read_i64(value.committed_at)) return false;
  if (!r.read_bool(value.deduplicated)) return false;
  if (!r.read_bool(value.superseded)) return false;
  out = std::move(value);
  return true;
}

void encode_artifact(CanonicalWriter& w, const ArtifactDescriptor& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  w.id(value.unit);
  write_enum(w, value.kind);
  encode_content_ref(w, value.content);
  w.str(value.logical_name);
  w.digest(value.target_identity);
  w.digest(value.toolchain_identity);
  w.digest(value.dependency_identity);
  w.digest(value.specialization_identity);
}

bool decode_artifact(CanonicalReader& r, ArtifactDescriptor& out) {
  ArtifactDescriptor value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!r.read_id(value.unit)) return false;
  if (!read_enum(r, value.kind, OutputKind::PreprocessedSource)) return false;
  if (!decode_content_ref(r, value.content)) return false;
  if (!r.read_str(value.logical_name)) return false;
  if (!r.read_digest(value.target_identity)) return false;
  if (!r.read_digest(value.toolchain_identity)) return false;
  if (!r.read_digest(value.dependency_identity)) return false;
  if (!r.read_digest(value.specialization_identity)) return false;
  out = std::move(value);
  return true;
}

void encode_cache_entry(CanonicalWriter& w, const CacheEntry& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.digest(value.unit_identity);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  encode_content_ref(w, value.artifact);
  w.id(value.artifact_id);
  w.id(value.provenance);
  w.id(value.validation);
  w.digest(value.source_identity);
  w.digest(value.dependency_identity);
  w.digest(value.toolchain_identity);
  w.gen(value.toolchain_generation);
  w.digest(value.target_identity);
  w.gen(value.target_generation);
  w.digest(value.specialization_identity);
  w.digest(value.policy_identity);
  w.digest(value.environment_identity);
  w.id(value.commit);
  w.i64(value.created_at);
  w.boolean(value.invalidated);
  w.str(value.invalidation_reason);
  w.u32(value.hit_count);
}

bool decode_cache_entry(CanonicalReader& r, CacheEntry& out) {
  CacheEntry value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_digest(value.unit_identity)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!decode_content_ref(r, value.artifact)) return false;
  if (!r.read_id(value.artifact_id)) return false;
  if (!r.read_id(value.provenance)) return false;
  if (!r.read_id(value.validation)) return false;
  if (!r.read_digest(value.source_identity)) return false;
  if (!r.read_digest(value.dependency_identity)) return false;
  if (!r.read_digest(value.toolchain_identity)) return false;
  if (!r.read_gen(value.toolchain_generation)) return false;
  if (!r.read_digest(value.target_identity)) return false;
  if (!r.read_gen(value.target_generation)) return false;
  if (!r.read_digest(value.specialization_identity)) return false;
  if (!r.read_digest(value.policy_identity)) return false;
  if (!r.read_digest(value.environment_identity)) return false;
  if (!r.read_id(value.commit)) return false;
  if (!r.read_i64(value.created_at)) return false;
  if (!r.read_bool(value.invalidated)) return false;
  if (!r.read_str(value.invalidation_reason)) return false;
  if (!r.read_u32(value.hit_count)) return false;
  out = std::move(value);
  return true;
}

void encode_negative_cache(CanonicalWriter& w, const NegativeCacheEntry& value) {
  w.id(value.id);
  w.digest(value.unit_identity);
  write_enum(w, value.reason);
  w.u16(static_cast<std::uint16_t>(value.failure));
  w.str(value.diagnostic);
  w.digest(value.toolchain_identity);
  w.gen(value.toolchain_generation);
  w.digest(value.target_identity);
  w.gen(value.target_generation);
  w.digest(value.specialization_identity);
  w.digest(value.policy_identity);
  w.i64(value.created_at);
}

bool decode_negative_cache(CanonicalReader& r, NegativeCacheEntry& out) {
  NegativeCacheEntry value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_digest(value.unit_identity)) return false;
  if (!read_enum(r, value.reason, NegativeCacheReason::PolicyRefusal)) return false;
  std::uint16_t failure = 0;
  if (!r.read_u16(failure)) return false;
  if (failure > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "negative cache failure code out of domain");
    return false;
  }
  value.failure = static_cast<ErrorCode>(failure);
  if (!r.read_str(value.diagnostic)) return false;
  if (!r.read_digest(value.toolchain_identity)) return false;
  if (!r.read_gen(value.toolchain_generation)) return false;
  if (!r.read_digest(value.target_identity)) return false;
  if (!r.read_gen(value.target_generation)) return false;
  if (!r.read_digest(value.specialization_identity)) return false;
  if (!r.read_digest(value.policy_identity)) return false;
  if (!r.read_i64(value.created_at)) return false;
  out = std::move(value);
  return true;
}

void encode_intermediate(CanonicalWriter& w, const IntermediateArtifact& value) {
  w.id(value.id);
  w.gen(value.generation);
  write_enum(w, value.kind);
  encode_content_ref(w, value.content);
  w.digest(value.provenance_identity);
  w.digest(value.toolchain_identity);
  w.digest(value.target_identity);
  w.digest(value.dependency_identity);
  w.id(value.compilation);
  w.gen(value.compilation_generation);
  w.boolean(value.authoritative);
}

bool decode_intermediate(CanonicalReader& r, IntermediateArtifact& out) {
  IntermediateArtifact value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!read_enum(r, value.kind, IntermediateKind::Metadata)) return false;
  if (!decode_content_ref(r, value.content)) return false;
  if (!r.read_digest(value.provenance_identity)) return false;
  if (!r.read_digest(value.toolchain_identity)) return false;
  if (!r.read_digest(value.target_identity)) return false;
  if (!r.read_digest(value.dependency_identity)) return false;
  if (!r.read_id(value.compilation)) return false;
  if (!r.read_gen(value.compilation_generation)) return false;
  if (!r.read_bool(value.authoritative)) return false;
  out = std::move(value);
  return true;
}

void encode_compilation(CanonicalWriter& w, const CompilationRecord& value) {
  w.id(value.id);
  w.gen(value.generation);
  w.id(value.unit);
  w.gen(value.unit_generation);
  w.digest(value.unit_identity);
  w.id(value.request_id);
  w.gen(value.request_generation);
  w.digest(value.request_identity);
  w.digest(value.source_identity);
  w.digest(value.dependency_identity);
  w.digest(value.toolchain_identity);
  w.digest(value.target_identity);
  w.digest(value.specialization_identity);
  w.digest(value.policy_identity);
  w.digest(value.environment_identity);
  w.gen(value.source_generation);
  w.gen(value.ir_generation);
  w.gen(value.dependency_generation);
  w.gen(value.toolchain_generation);
  w.gen(value.target_generation);
  w.gen(value.specialization_generation);
  w.gen(value.policy_generation);
  write_enum(w, value.output_kind);
  write_enum(w, value.reproducibility);
  write_enum(w, value.state);
  w.list(static_cast<std::uint32_t>(value.attempts.size()));
  for (CompilationAttemptId attempt : value.attempts) w.id(attempt);
  w.id(value.current_attempt);
  w.u32(value.attempt_ordinal_counter);
  w.boolean(value.commit.has_value());
  if (value.commit.has_value()) encode_commit(w, *value.commit);
  w.list(static_cast<std::uint32_t>(value.divergent_candidates.size()));
  for (const auto& candidate : value.divergent_candidates) encode_content_ref(w, candidate);
  w.boolean(value.reproducibility_violation);
  w.str(value.failure_detail);
  w.u16(static_cast<std::uint16_t>(value.failure));
  w.boolean(value.cache_hit);
  w.i64(value.created_at);
  w.i64(value.updated_at);
  w.u32(value.unit_index);
  w.u32(value.parent_unit_index);
  w.boolean(value.is_root);
}

bool decode_compilation(CanonicalReader& r, CompilationRecord& out) {
  CompilationRecord value;
  if (!r.read_id(value.id)) return false;
  if (!r.read_gen(value.generation)) return false;
  if (!r.read_id(value.unit)) return false;
  if (!r.read_gen(value.unit_generation)) return false;
  if (!r.read_digest(value.unit_identity)) return false;
  if (!r.read_id(value.request_id)) return false;
  if (!r.read_gen(value.request_generation)) return false;
  if (!r.read_digest(value.request_identity)) return false;
  if (!r.read_digest(value.source_identity)) return false;
  if (!r.read_digest(value.dependency_identity)) return false;
  if (!r.read_digest(value.toolchain_identity)) return false;
  if (!r.read_digest(value.target_identity)) return false;
  if (!r.read_digest(value.specialization_identity)) return false;
  if (!r.read_digest(value.policy_identity)) return false;
  if (!r.read_digest(value.environment_identity)) return false;
  if (!r.read_gen(value.source_generation)) return false;
  if (!r.read_gen(value.ir_generation)) return false;
  if (!r.read_gen(value.dependency_generation)) return false;
  if (!r.read_gen(value.toolchain_generation)) return false;
  if (!r.read_gen(value.target_generation)) return false;
  if (!r.read_gen(value.specialization_generation)) return false;
  if (!r.read_gen(value.policy_generation)) return false;
  if (!read_enum(r, value.output_kind, OutputKind::PreprocessedSource)) return false;
  if (!read_enum(r, value.reproducibility, ReproducibilityRequirement::NotRequired)) return false;
  if (!read_enum(r, value.state, CompilationState::Retired)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.attempts.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_id(value.attempts[i])) return false;
  }
  if (!r.read_id(value.current_attempt)) return false;
  if (!r.read_u32(value.attempt_ordinal_counter)) return false;
  bool has_commit = false;
  if (!r.read_bool(has_commit)) return false;
  if (has_commit) {
    ArtifactCommit commit;
    if (!decode_commit(r, commit)) return false;
    value.commit = commit;
  }
  if (!r.read_list(count)) return false;
  value.divergent_candidates.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!decode_content_ref(r, value.divergent_candidates[i])) return false;
  }
  if (!r.read_bool(value.reproducibility_violation)) return false;
  if (!r.read_str(value.failure_detail)) return false;
  std::uint16_t failure = 0;
  if (!r.read_u16(failure)) return false;
  if (failure > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "compilation failure code out of domain");
    return false;
  }
  value.failure = static_cast<ErrorCode>(failure);
  if (!r.read_bool(value.cache_hit)) return false;
  if (!r.read_i64(value.created_at)) return false;
  if (!r.read_i64(value.updated_at)) return false;
  if (!r.read_u32(value.unit_index)) return false;
  if (!r.read_u32(value.parent_unit_index)) return false;
  if (!r.read_bool(value.is_root)) return false;
  out = std::move(value);
  return true;
}

void encode_job(CanonicalWriter& w, const JobRecord& value) {
  w.id(value.request_id);
  w.gen(value.request_generation);
  w.digest(value.request_identity);
  w.list(static_cast<std::uint32_t>(value.units.size()));
  for (CompilationId unit : value.units) w.id(unit);
  w.u32(value.root_index);
  w.list(static_cast<std::uint32_t>(value.mandatory_units.size()));
  for (std::uint32_t index : value.mandatory_units) w.u32(index);
  w.boolean(value.committed);
  w.id(value.committed_unit);
  w.u16(static_cast<std::uint16_t>(value.failure));
  w.str(value.failure_detail);
  w.i64(value.created_at);
}

bool decode_job(CanonicalReader& r, JobRecord& out) {
  JobRecord value;
  if (!r.read_id(value.request_id)) return false;
  if (!r.read_gen(value.request_generation)) return false;
  if (!r.read_digest(value.request_identity)) return false;
  std::uint32_t count = 0;
  if (!r.read_list(count)) return false;
  value.units.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_id(value.units[i])) return false;
  }
  if (!r.read_u32(value.root_index)) return false;
  if (!r.read_list(count)) return false;
  value.mandatory_units.resize(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    if (!r.read_u32(value.mandatory_units[i])) return false;
  }
  if (!r.read_bool(value.committed)) return false;
  if (!r.read_id(value.committed_unit)) return false;
  std::uint16_t failure = 0;
  if (!r.read_u16(failure)) return false;
  if (failure > static_cast<std::uint16_t>(ErrorCode::Shutdown)) {
    r.fail(ErrorCode::Malformed, "job failure code out of domain");
    return false;
  }
  value.failure = static_cast<ErrorCode>(failure);
  if (!r.read_str(value.failure_detail)) return false;
  if (!r.read_i64(value.created_at)) return false;
  out = std::move(value);
  return true;
}

Digest256 digest_of(const std::vector<std::byte>& encoded) {
  return sha256(std::span<const std::byte>(encoded.data(), encoded.size()));
}

}  // namespace dc
