// Distributed Compilation - canonical codec shared by persistence and the wire protocol.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
//
// There is exactly one encoding for every record in this runtime. Persistence
// and the network protocol both use it, so a record that round-trips through
// disk and a record that round-trips through a socket are byte-identical, and
// a single set of defensive bounds applies to both.
#ifndef DC_CODEC_HPP
#define DC_CODEC_HPP

#include <span>
#include <vector>

#include "dc/canonical.hpp"
#include "dc/model.hpp"
#include "dc/runtime.hpp"

namespace dc {

// Every record begins with a domain tag; a decoder that sees the wrong tag
// fails with Malformed instead of misinterpreting the payload.
void encode_content_ref(CanonicalWriter& w, const ContentRef& value);
bool decode_content_ref(CanonicalReader& r, ContentRef& out);

void encode_binary_identity(CanonicalWriter& w, const BinaryIdentity& value);
bool decode_binary_identity(CanonicalReader& r, BinaryIdentity& out);

void encode_toolchain(CanonicalWriter& w, const ToolchainIdentity& value);
bool decode_toolchain(CanonicalReader& r, ToolchainIdentity& out);

void encode_target(CanonicalWriter& w, const TargetIdentity& value);
bool decode_target(CanonicalReader& r, TargetIdentity& out);

void encode_specialization(CanonicalWriter& w, const SpecializationSpec& value);
bool decode_specialization(CanonicalReader& r, SpecializationSpec& out);

void encode_dependency_entry(CanonicalWriter& w, const DependencyEntry& value);
bool decode_dependency_entry(CanonicalReader& r, DependencyEntry& out);
void encode_dependency_set(CanonicalWriter& w, const DependencySet& value);
bool decode_dependency_set(CanonicalReader& r, DependencySet& out);

void encode_environment(CanonicalWriter& w, const EnvironmentContract& value);
bool decode_environment(CanonicalReader& r, EnvironmentContract& out);

void encode_validation_requirements(CanonicalWriter& w, const ValidationRequirements& value);
bool decode_validation_requirements(CanonicalReader& r, ValidationRequirements& out);

void encode_policy(CanonicalWriter& w, const CompilePolicy& value);
bool decode_policy(CanonicalReader& r, CompilePolicy& out);

void encode_unit_spec(CanonicalWriter& w, const CompilationUnitSpec& value);
bool decode_unit_spec(CanonicalReader& r, CompilationUnitSpec& out);

void encode_request(CanonicalWriter& w, const CompilationRequest& value);
bool decode_request(CanonicalReader& r, CompilationRequest& out);

void encode_capabilities(CanonicalWriter& w, const WorkerCapabilities& value);
bool decode_capabilities(CanonicalReader& r, WorkerCapabilities& out);

void encode_worker(CanonicalWriter& w, const WorkerRecord& value);
bool decode_worker(CanonicalReader& r, WorkerRecord& out);

void encode_lease(CanonicalWriter& w, const CompileLease& value);
bool decode_lease(CanonicalReader& r, CompileLease& out);

void encode_validation_report(CanonicalWriter& w, const ValidationReport& value);
bool decode_validation_report(CanonicalReader& r, ValidationReport& out);

void encode_attempt(CanonicalWriter& w, const CompilationAttempt& value);
bool decode_attempt(CanonicalReader& r, CompilationAttempt& out);

void encode_provenance(CanonicalWriter& w, const Provenance& value);
bool decode_provenance(CanonicalReader& r, Provenance& out);

void encode_commit(CanonicalWriter& w, const ArtifactCommit& value);
bool decode_commit(CanonicalReader& r, ArtifactCommit& out);

void encode_artifact(CanonicalWriter& w, const ArtifactDescriptor& value);
bool decode_artifact(CanonicalReader& r, ArtifactDescriptor& out);

void encode_cache_entry(CanonicalWriter& w, const CacheEntry& value);
bool decode_cache_entry(CanonicalReader& r, CacheEntry& out);

void encode_negative_cache(CanonicalWriter& w, const NegativeCacheEntry& value);
bool decode_negative_cache(CanonicalReader& r, NegativeCacheEntry& out);

void encode_intermediate(CanonicalWriter& w, const IntermediateArtifact& value);
bool decode_intermediate(CanonicalReader& r, IntermediateArtifact& out);

void encode_compilation(CanonicalWriter& w, const CompilationRecord& value);
bool decode_compilation(CanonicalReader& r, CompilationRecord& out);

void encode_job(CanonicalWriter& w, const JobRecord& value);
bool decode_job(CanonicalReader& r, JobRecord& out);

// Digest of an encoded record, used for integrity checks and dedup.
Digest256 digest_of(const std::vector<std::byte>& encoded);

}  // namespace dc

#endif  // DC_CODEC_HPP
