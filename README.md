# Distributed Compilation

Open-source, vendor-neutral C++20 runtime for governing distributed compilation across source, IR,
specialization, toolchains, workers, caches, artifacts, retries, recovery, provenance, and
generation-bound compile authority.

**Version 1.0.0** - Apache License 2.0 - Copyright 2026 Summon Software Labs.

---

## Systems boundary

Given a compilation request, source or IR identity, specialization parameters, target requirements,
toolchain identity, worker capabilities, cache state, dependencies, policy, and authority,
Distributed Compilation determines:

- which compilation work must actually occur;
- which worker is permitted to perform it;
- which prior result may be reused;
- which intermediate state may be resumed;
- which produced artifact may become authoritative.

**Core question.** Which compilation result may become authoritative for this exact source, IR,
specialization, toolchain, target, dependency, and policy generation - and how do we distribute,
retry, cache, recover, and deduplicate that work without stale workers, incompatible artifacts,
duplicate commits, or nondeterministic builds becoming current?

**Central principle.** Compilation completion is not artifact authority.

- A worker producing bytes does not make those bytes authoritative.
- A cache hit is not reusable merely because a key matched.
- A compiler version string is not a complete toolchain identity.
- An artifact built for one target or generation must not silently satisfy another.
- A retried compile must not create two authoritative artifacts.
- A worker restart must not inherit an old compilation lease.
- A coordinator restart must not revive stale in-flight authority.
- **UNKNOWN is first-class.** If compatibility or provenance cannot be proven, reuse and promotion
  fail closed.

## Relationship to Compilation Fabric and Compiler Runtime Fabric

This runtime owns the **distributed execution and authority layer** for compilation work:
distributed compile request identity, worker admission, toolchain identity, input identity,
dependency generations, compile leases, work partitioning, remote dispatch, compile attempts,
retry semantics, cache consultation, intermediate-state reuse, distributed artifact production,
result validation, authoritative artifact commit, worker death, coordinator restart,
stale-authority fencing, and deterministic recovery.

It deliberately does **not** own:

- **Compilation Fabric** semantics - AI compilation specialization, code generation, validation,
  reuse, invalidation, reproducibility policy, and accelerator-targeted deployment. Where broader
  compilation policy or specialization logic exists externally it is consumed through typed inputs
  and generation references: the request carries a specialization, a policy, an environment
  contract and an opaque external authority token.
- **Compiler Runtime Fabric** - local compiler-runtime invocation semantics. The core sees a
  compiler only through a narrow adapter interface and a toolchain identity.
- **Artifact Fabric** (generalized artifact lifecycle), **Kernel Cache**, **Graph Cache**,
  **Compatibility Registry**, **Artifact Promotion**, **Resource Broker**, and unrelated
  agent/execution runtimes. Each is represented here only as a typed input or an outbound
  reference.

It is not a compiler frontend, an LLVM/CUDA/linker replacement, a build system, a package manager,
a generic CI system, a general job scheduler, a source-control system, an artifact registry, a
generic distributed cache, a generic workflow engine, a cluster manager, a resource broker, or a
container runtime.

## Canonical request model

Identity is split into two domains that are never mixed:

- **Content identity** answers *is this the same compilation work?* It is derived only from
  content-derived fields: content digests, declared formats, language modes, canonicalized flags,
  the toolchain identity digest, the target identity digest, the specialization identity digest,
  the dependency set digest, the environment contract digest, the policy identity digest, and the
  output kind. No handle, path, timestamp, counter or process id participates.
- **Authority identity** answers *is this work still allowed to become authoritative right now?*
  It is derived from coordinator-assigned generations and is bound into authority claims and commit
  records.

Canonical encoding (include/dc/canonical.hpp) is self-delimiting, domain-tagged and length-prefixed,
so concatenation can never collide and a source record can never hash equal to a target record with
the same payload bytes. Every identity-bearing collection is sorted before hashing, so container
iteration order and submission order can never leak into an identity. Compiler flags are
order-sensitive by default because their order is semantically meaningful; a policy may declare
them order-insensitive, in which case they are sorted. Both behaviours are tested.

**Path alone is not identity. Modification time alone is not identity.** A source at the same path
with different content is a different input generation, and a compilation against it is a
different compilation.

## Source / IR identity

Implemented input forms: SOURCE, PREPROCESSED_SOURCE, LLVM_IR, PTX, SPIRV, VENDOR_IR, OBJECT,
CUBIN, ASSEMBLY, OTHER. The runtime claims support only for the formats it actually accepts, and an
UNKNOWN format is refused at canonicalization.

Input identity binds content digest, declared format, language mode, generation and the
compiler-facing options that affect semantics. Source content is transferred as digest-referenced
blobs, deduplicated across units, and verified against its digest on ingest, on store, and on load.

## Dependency model

Dependencies are explicit and generation-bound. Supported kinds: HEADER, MODULE, GENERATED_CODE,
LIBRARY, DEVICE_LIBRARY, RUNTIME_LIBRARY, COMPILER_PLUGIN, CONFIGURATION, MODEL_METADATA,
TOOLCHAIN_FILE, OTHER.

A dependency set's **logical id** is derived from the sorted multiset of (name, kind) pairs, and its
**content identity** from the sorted multiset of member content digests. Reordering members never
changes identity; changing any member's content always does. A cache hit produced against old
dependency generations fails closed, both because the compilation identity changes and because
cache validation compares the recorded dependency content identity against the current one.

Dependency discovery beyond explicitly supplied dependencies is a bounded, deterministic
quoted-include scanner in the CLI (--include-dir), limited in file count and include depth. No other
discovery adapter exists, and none is claimed.

## Toolchain identity

A toolchain identity is strictly stronger than a compiler executable path or a version string:

- compiler family, version string, parsed version triple;
- compiler, linker, assembler and runtime-library **binary identities**: either a real SHA-256
  digest with size, or an explicitly recorded UNKNOWN/UNAVAILABLE state;
- SDK/toolkit components with versions;
- plugin set with digests;
- target libraries;
- environment-sensitive configuration;
- evidence provenance (how the identity was established).

Two toolchains reporting the same marketing version are not automatically identical: their binary
digests differ, so their identity digests differ. The compiler path participates in identity **only
when the binary digest could not be established** - an identical binary reached through two paths is
one toolchain, but two unknown binaries at one path are not provably the same thing. A toolchain
whose compiler digest is UNKNOWN, or whose evidence is not REAL, is not *provable*, and a policy
that requires a provable toolchain will refuse to use it for reproducible-cache work.

## Target model

Targets are explicit and multi-dimensional: OS, architecture, ABI, target triple, object format,
standard library, runtime ABI, accelerator vendor, accelerator architecture, compute capability,
ISA and device-runtime compatibility. sm_120 is represented truthfully as compute capability 12.0.
An artifact built for one target cannot satisfy another, because the target identity digest is part
of compilation identity, is rechecked at commit, and is additionally verified against the machine
field embedded in the produced bytes.

## Specialization

Specialization parameters are typed (SIGNED, UNSIGNED, FLOATING, TEXT, BOOLEAN), named, sorted by
name, and unique by name. Unordered containers are never used to derive identity. The
specialization **id** is derived from the field schema (names and kinds) and the specialization
**content identity** from the values, so adding a value to an existing field is observable as a
generation change on the same id, while a schema change is a new id.

## Worker model and capabilities

A worker is an explicit, governed participant with a stable WorkerId, a fresh WorkerBootId per
process start, a monotonic WorkerGeneration, an advertised capability set, health, readiness,
in-flight accounting, lease accounting and evidence freshness. A restarted worker receives a fresh
boot identity; a worker never inherits compile authority merely because it runs on the same machine.

Capabilities are evidence-backed: toolchains, targets, input formats, plugins, SDKs, resource
limits, filesystem isolation, sandboxing, deterministic-build support, remote-cache access,
artifact-store access and trust. **Missing capability evidence remains UNKNOWN, and UNKNOWN fails
closed for hard requirements.** Dropping a capability set to UNKNOWN recomputes its integrity digest
in the same step, so a persisted capability record can never fail its own integrity check.

## Eligibility, ranking, assignment, authority

These four are strictly separated:

1. **Eligibility** - a worker is eligible only if every hard requirement is satisfied (exact
   toolchain identity, target support, input format support, plugin and SDK presence, resource
   minimums, sandbox/isolation/determinism/trust requirements, locality, artifact-size limits). The
   first violated requirement is reported with a typed reason.
2. **Ranking** - applied only to already-eligible workers, using deterministic integer arithmetic
   over locality, cache affinity, evidence freshness, trust, historical and expected cost, queue
   depth, in-flight count, cores and memory, with a stable tie-break on worker id then boot id.
   Identical inputs and identical eligible sets always produce the same order.
3. **Assignment** - creates an attempt and a lease bound to the current coordinator epoch,
   compilation generation, worker boot and worker generation.
4. **Artifact authority** - conferred only by the coordinator, only after validation, only once per
   logical compilation.

**Ranking does not confer authority. Assignment does not confer artifact authority.**

## Compile authority

Every attempt binds an authority claim containing the coordinator epoch, compilation and unit
identities and generations, attempt identity and generation, worker identity, boot and generation,
lease identity and generation, and the source, IR, dependency, toolchain, target, specialization,
policy and cache generations. Every field is compared against the coordinator's current
expectation; the first mismatch is reported as a typed stale failure: StaleEpoch, StaleWorkerBoot,
StaleWorkerGeneration, StaleLease, StaleCompilation, StaleAttempt, StaleSource, StaleIR,
StaleDependencies, StaleToolchain, StaleTarget, StaleSpecialization, StalePolicy, StaleCache,
StaleRequest, alongside NotEligible, ArtifactMismatch, ArtifactAlreadyCommitted, IntegrityFailure,
ProtocolViolation, Unsupported and Unknown.

The commit path performs **reservation then revalidation**: the attempt is moved to Produced under
the lock, artifact digesting, format validation, optional smoke-test execution and content storage
happen outside the lock, and the complete authority claim is rechecked before commit. If any
generation moved during that unlocked window the commit is refused and the attempt is fenced.

## Attempt lifecycle

```
Created -> Eligible -> Assigned -> Preparing -> Running -> Produced -> Validating -> CommitReady -> Committed
                                        \-> Produced
   (Assigned|Preparing|Running|Produced|Validating|CommitReady) -> Failed | Cancelled | Fenced | Ambiguous
   (any terminal) -> Retired
```

The transition relation is closed: anything not listed is refused with IllegalTransition. A stale
attempt cannot become Committed. Committed is terminal with respect to authoritative artifact
identity. Ambiguous (a worker may have produced a result the coordinator never saw) can only be
retired - it can never be resurrected into Produced or CommitReady. A failed attempt may lead to a
new attempt generation if the failure class and policy permit.

## Distributed compilation transaction

```
canonicalize request
  -> derive compilation identity
  -> inspect cache
  -> validate cache candidate
  -> if miss: determine eligible workers
  -> rank eligible workers
  -> assign compile lease
  -> worker prepares environment
  -> compile (real compiler child process)
  -> produce candidate outputs
  -> compute digests
  -> collect provenance
  -> validate artifact
  -> revalidate all generations and authority
  -> persist authoritative commit record
  -> mark exactly one artifact authoritative
  -> expose result
```

If authority changes between production and commit, the candidate does not become current.

## Cache semantics

A cache hit is a candidate, not authority. Cache lookup validates request identity, input content,
dependencies, toolchain, target, specialization, policy, environment contract, artifact integrity,
provenance presence, cache generation and invalidation state, and returns one of REUSABLE, STALE,
INCOMPATIBLE, CORRUPT, UNKNOWN, MISS - never a boolean. UNKNOWN fails closed. A mismatch is reported
with the dimension, the expected value and the actual value. Content equality with generation drift
is recorded rather than hidden.

Negative caching is implemented for deterministic failures only (unsupported target, deterministic
compiler rejection, incompatible source/toolchain pair, policy refusal). Transient causes - worker
death, storage failure, transport failure, resource exhaustion, UNKNOWN - are never admitted as
permanent compile failures. Negative-cache records are bound to the toolchain, target,
specialization and policy generations that justify them and are bounded in number.

## Intermediate artifacts

Intermediates carry identity, generation, content digest, provenance binding, toolchain stage,
target, dependency binding and authority state. An intermediate is never reused because a filename
matches: it is bound to the unit content identity, toolchain identity and target identity.

## Compilation partitioning, fan-out and fan-in

```
one request -> N independent compile units -> M workers -> authoritative unit results
            -> deterministic finalization (link) -> one authoritative final artifact
```

A unit is a whole translation unit or an independent kernel/target variant - not an invented
compiler-stage split. A link unit's identity binds the **identities of its child units**, not just
their positions. Fan-in is an explicit barrier: a parent may only commit when every mandatory child
result is authoritative and generation-consistent, and it may not even be assigned before that gate
opens. A unit retry cannot duplicate logical unit completion, and a stale unit cannot satisfy
fan-in. When a mandatory child can never become authoritative, the parent is failed with
FanInIncomplete rather than left waiting for a gate that will never open.

## Retry semantics

Failure classes: RETRYABLE (transport failure, connection loss, timeout, I/O error, internal, and
any stale-authority refusal - re-issued under fresh authority, never resumed), NON_RETRYABLE
(deterministic compiler error, unsupported target, invalid source, policy refusal, validation
failure, artifact mismatch) and AMBIGUOUS (worker may have produced an artifact the coordinator
lost). A retry creates a **new attempt generation** with a higher lease generation; it never resumes
an old attempt.

## Exactly-once logical artifact commit

Physical compilation is not exactly-once and is not claimed to be: workers may compile the same
request multiple times because of failure or deliberate speculative duplication. For one logical
compilation identity and generation, **exactly one authoritative logical artifact commit may
succeed**. Duplicate equivalent candidate outputs converge on the same artifact identity and are
recorded as deduplicated rather than creating a second authority. Divergent outputs for a
compilation expected to be reproducible trigger an explicit reproducibility failure instead of
arbitrary winner selection.

## Reproducibility

Policy states: REQUIRED, PREFERRED, NOT_REQUIRED. Under REQUIRED, the same canonical request,
authoritative toolchain identity, dependencies, target and specialization must yield a matching
canonical artifact digest. If two workers produce different digests the coordinator does **not**
silently choose one: it returns a typed ReproducibilityViolation, keeps the first authoritative
artifact, records the divergent candidate for diagnostics, and marks the compilation with a
reproducibility violation. A compilation may only be marked with a violation under a policy that
actually requires reproducibility - the auditor checks this.

Determinism aids implemented: /Brepro for MSVC, /Z7 instead of /Zi to avoid PDB path embedding, a
constructed child environment rather than the ambient one, workspace-relative input names,
SOURCE_DATE_EPOCH fixed at the ZIP epoch, and link.exe /Brepro. **Output bytes are never rewritten
after compilation to force matching hashes.** Where exact bit reproducibility cannot be achieved the
weaker contract is stated rather than implied: PREFERRED reports divergence without refusing the
commit.

Known sources of nondeterminism that this runtime does not eliminate: compiler version differences
(caught by toolchain identity), absolute paths embedded by unusual flags, link-time timestamps in
formats that ignore /Brepro, and nondeterministic code generation in third-party backends.

## Artifact validation

Before authoritative commit the coordinator inspects the produced bytes: existence, non-zero size
where appropriate, expected container format (PE, COFF object, ELF relocatable/executable/shared,
ELF CUDA device image, PTX text, archive), digest match, embedded target machine metadata against
the declared target architecture, dependency metadata, and an optional execution smoke test that
runs the produced executable and compares stdout. Text output kinds have no embedded machine field,
which is recorded as *not applicable* rather than silently passing; an unrecognised binary format is
a genuine UNKNOWN and fails closed. **A compiler exit code of 0 is never sufficient proof of
artifact compatibility.**

## Provenance

Every authoritative artifact has provenance: compilation identity and generation, unit, attempt and
generation, coordinator epoch, worker, worker boot and generation, lease and generation, request id
and request identity, unit identity, artifact content reference, source/IR/dependency/toolchain/
target/specialization/policy identities, validation id, evidence class, compiler invocation,
compiler version and compiler wall time. Provenance survives persistence and restart, and the
auditor verifies that a committed compilation's provenance identities match the compilation record.

## Persistence, durability and recovery

State lives in a content-addressed blob store plus an append journal plus atomic snapshots. Journal
records carry a schema version, sequence number, length and CRC-32; snapshots carry a schema version,
sequence number, length and SHA-256. Every journal append is flushed and fsync'd before the caller is
told it succeeded, so a commit acknowledgement always corresponds to state a restarted coordinator
can recover. Snapshots are written to a temporary file, fsync'd, then atomically renamed. Journal
records already captured by a snapshot are skipped by sequence number, so a crash between "snapshot
written" and "journal truncated" is harmless.

Corruption and truncation are distinguished: **a torn tail is recovered by truncation and reported**,
while a structurally corrupt record with valid records after it is refused outright.

### Coordinator restart

On restart the coordinator advances the CoordinatorEpoch; loads and integrity-checks persisted state;
clears every session; revokes every lease; fences every worker and marks its capability evidence
UNKNOWN so it must be re-established; classifies every in-flight attempt as Ambiguous; retains
committed artifacts and re-queues unfinished compilations as Pending; and resumes them only through
fresh authority (a new attempt under the new epoch). An attempt that was Running before a restart is
not Running afterwards.

### Worker restart

A worker restart gets a fresh WorkerBootId and an advanced WorkerGeneration. Attempts remain bound to
the old boot; late completion from the old boot is refused with StaleWorkerBoot, and a recovered
compilation is assigned as a fresh attempt generation.

## Distributed control plane

Real framed TCP with bounded framing (16 MiB maximum frame), a magic number, a protocol version,
correlation ids, and strict field validation. Operations: HELLO, REGISTER_WORKER,
ADVERTISE_TOOLCHAIN, SUBMIT_COMPILATION, QUERY, ASSIGN, BEGIN_COMPILE, REPORT_OUTPUT,
VALIDATE_OUTPUT, VALIDATE_RESPONSE, COMMIT_ARTIFACT, FAIL_ATTEMPT, CANCEL_ATTEMPT, CACHE_QUERY,
CACHE_REPORT, SNAPSHOT, AUDIT, SHUTDOWN, HEARTBEAT, WORKER_READY, RESPONSE, ERROR.

Every payload is a canonical record, so one defensive decoder protects both persistence and the
network, and an out-of-domain enum is a typed refusal rather than undefined behaviour. Defences
implemented and tested: malformed frames, oversized frames (refused before any allocation
proportional to the claim), truncated frames, invalid enums, duplicate ids, replayed completions,
duplicate commits, stale epochs, stale boots, stale leases, stale request generations, stale
toolchain generations, stale dependency generations, stale target generations, reordered
completions, connection loss, half-open sessions, reconnect storms (a reconnect always advances the
worker generation), and backpressure (a peer that cannot drain a bounded outbound backlog is
disconnected rather than allowed to exhaust coordinator memory).

The coordinator is a single-threaded reactor: all authority transitions are serialised in one place,
so "exactly one authoritative commit" is a property of the state machine rather than of timing.
Non-blocking sends are used so a slow peer can never wedge the accept loop.

Binaries: dc_coordinator, dc_worker, dc_cli.

## Multiprocess proof

dc_cli demo multiprocess starts a real coordinator process and two real worker processes, then drives
26 cases over real TCP with real compiler subprocesses:

coordinator start and endpoint publication; two workers registering and advertising real toolchains;
evidence-backed readiness; real MSVC toolchain discovery; canonical identity stability; a real C++
translation unit compiling on a worker process and committing; coordinator-side artifact validation;
validated cache reuse on identical resubmission; a changed source producing a new identity and a new
compile; fan-out to two compile units and fan-in to one authoritative executable; coordinator
execution of the linked artifact with stdout comparison; worker death during an active compile
fencing the old boot; a stale completion claim from a restarted boot being refused; reassignment and
completion through a fresh attempt generation; coordinator restart advancing the epoch; previously
committed artifacts retained across the restart; stale claims refused after the restart; workers
re-registering with fresh boots; new work completing under the new epoch; an invariant audit with
zero violations; clean shutdown of every governed process; and zero leaked compiler child processes.

## Real native compiler proof

The MSVC adapter invokes the real installed toolchain through CreateProcessW with a constructed
environment (INCLUDE, LIB, PATH, TMP/TEMP) derived from the discovered toolchain layout, never
through a shell and never through string concatenation. Arguments are passed as an array using the
documented CRT quoting rules, which are unit tested. Real compilation produces real objects and real
linked executables: the multiprocess proof links two MSVC objects into an executable and the
coordinator executes it and compares stdout. The artifact digest is recorded, an identical rerun is
served from validated cache reuse, and a semantic input change derives a new identity and rebuilds.

## Real CUDA proof

dc_cli cuda-proof compiles a real CUDA kernel with a real nvcc for a real SM architecture, commits
the device image through the normal compilation transaction, then loads and executes it on the
physical GPU through the CUDA driver API: module load, H2D, kernel launch, device synchronise, D2H,
CPU parity and cleanup.

Observed in this environment: NVIDIA GeForce RTX 5090, compute capability 12.0 (sm_120), CUDA 12.9
and CUDA 13.1 both installed and both compiled, 1,048,576 elements, 0 mismatches against the CPU
reference, and **no cross-toolkit cache reuse** - a device image produced by one toolkit generation
never satisfies the other.

Toolchain identity distinguishes the two toolkits by version and by binary digest. The CUDA driver
probe (dc_cuda_probe) is an optional executable built only when a toolkit with cuda.h and the driver
import library is present; the core library has no CUDA dependency whatsoever.

## REAL / SYNTHETIC / UNSUPPORTED

**REAL** (physically exercised in this repository): Windows process creation and job-object child
tree cleanup; loopback TCP with multiple processes; MSVC native C++20 compilation through real child
processes; real link.exe linking; execution of the produced executable; CUDA toolchain discovery,
nvcc compilation for sm_120, and kernel execution on the RTX 5090; durable persistence with
snapshot, journal and blob store; worker kill and restart; coordinator restart; stale-authority
fencing; artifact validation by inspecting produced bytes.

**SYNTHETIC** (constructed profiles used only to exercise generic authority, identity and
compatibility logic; never presented as compilation): ROCm toolchain profile, Level Zero toolchain
profile, alternate-triple profile, and their targets. Synthetic toolchains carry
EvidenceClass::SYNTHETIC, are not provable, and are refused by any policy that requires a provable
toolchain. The synthetic adapter emits a clearly labelled synthetic artifact and performs no
compilation.

**UNSUPPORTED** (not implemented, not claimed): real ROCm compilation; real Level Zero compilation;
physical multi-node compilation across separate machines; a compiler farm spanning hosts; a
replicated or consensus coordinator; remote sandboxing infrastructure; cross-platform toolchain
proof; a Windows worker with a Linux coordinator or vice versa.

## Security

Source, compile options, protocol input, persisted input and artifact metadata are treated as
untrusted. IDs, generations, lengths, counts, paths, environment fields, argument arrays, target and
toolchain identifiers, dependency counts, digests, artifact sizes, enum domains and integer overflow
are validated. Compiler commands are never constructed through unsafe string concatenation where
structured process invocation is available, and the escaping rules used are unit tested. A peer
cannot select an arbitrary executable path: the worker only invokes a toolchain whose binary identity
matches the one it advertised and the coordinator assigned. Attempts run in unique attempt-scoped
workspaces with traversal-checked, normalized, workspace-relative paths. Compiler output is captured
with a bound and the excess is drained and discarded. Handle inheritance into compiler children is
restricted to exactly the two capture pipes, so a compiler can neither observe the worker's
coordinator connection nor hold another compile's pipes open. Every limit is configurable and
enforced before allocation.

**No telemetry is transmitted.** The runtime makes no outbound network connection except to the
coordinator endpoint it is configured with.

## CLI

```
worker list | worker show <id>
toolchain list [--synthetic] [--cuda] | toolchain show <index>
compile submit --source <file> [--source <file> ...] [--link] [--output <kind>]
               [--toolchain <family|path|auto>] [--target <triple|sm_120>]
               [--flag <flag>] [--spec <name>=<value>] [--dep <name>=<file>]
               [--include-dir <dir>] [--repro required|preferred|not-required]
               [--cache read-write|read-only|bypass] [--force-rebuild] [--dry-run]
               [--smoke-stdout <text>] [--no-wait]
compile show <compilation-id> | compile explain <compilation-id>
attempt list | attempt show <id>
cache query <unit-identity-hex> | cache explain <compilation-id>
artifact show <compilation-id> | artifact verify <compilation-id> [--output <file>]
provenance list | provenance show <provenance-id>
reproducibility show <compilation-id>
cancel <compilation-id>
snapshot | audit | state info
verify
probe-process --exe <path> [--arg X] [--cwd DIR] [--env K=V] [--inherit-env]
demo multiprocess [--only <case>] [--keep] [--verbose]
cuda-proof [--arch sm_120] [--elements N]
```

compile explain prints a deterministic explanation: canonical identity, every generation, each
identity dimension, the cache outcome with the reason and every mismatch, each attempt with its
state, worker, boot, lease and candidate digest, the authoritative artifact and why it became
authoritative, the validation evidence per check, the provenance, and the reproducibility state.
audit prints the invariant report and exits non-zero if any finding exists. verify runs the whole
transaction in-process against a durable coordinator and reports 14 named checks.

## Examples

- dc_example_identity - canonical request identity: order-independent inputs agree, dependency
  content changes and flag changes do not.
- dc_example_transaction - the full transaction in-process: submit, commit, validated reuse,
  dependency invalidation, audit, explanation.
- dc_example_inspection - offline inspection of a coordinator state directory, including recovery
  classification and refusing to guess about damaged state.

Every example performs real operations and prints what it measured; none contains hardcoded success
text.

## Benchmarks

dc_bench measures completed work at scales of 10, 100, 1,000, 10,000 and 100,000: canonical request
identity, submit plus cache consult, worker eligibility and ranking, assignment creation, artifact
commit (adapter included, reported separately), cache validation lookup, provenance lookup,
dependency invalidation, invariant audit, snapshot save, and snapshot load plus recovery
classification. Compiler wall time is reported separately from coordinator overhead so compiler
submission is never presented as completed compilation.

## Build, test, install

```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix <prefix>
```

Options: DC_BUILD_APPS, DC_BUILD_TESTS, DC_BUILD_EXAMPLES, DC_BUILD_BENCHMARKS,
DC_WARNINGS_AS_ERRORS, DC_ENABLE_ASAN, DC_WITH_CUDA, DC_CUDA_TOOLKIT_ROOT.

The installed package exports a namespaced target and a config package:

```
find_package(DistributedCompilation CONFIG REQUIRED)
target_link_libraries(consumer PRIVATE dc::core)
```

Four test suites run under CTest: dc_tests_core (unit), dc_tests_property (randomized with recorded
seeds), dc_tests_concurrency (races) and dc_tests_adversarial (hostile input). Every case prints a
flushed [BEGIN], phase markers and a flushed [PASS]/[FAIL], so a stopped suite identifies the exact
case and phase. A single case can be run directly:

```
dc_tests_core canonical.reader_refuses_malformed_input
```

## Limitations

- A single coordinator; there is no consensus, replication or failover.
- Local durable state on the coordinator host; no distributed state store.
- Loopback multiprocess rather than a physical multi-node cluster: this is real OS-process
  distribution and real TCP, but it is not a physical multi-machine proof.
- No remote sandbox implementation; workspace isolation is filesystem-level.
- Native MSVC and CUDA are the only real compiler adapters. Other toolchains are synthetic or
  unsupported.
- No generic build-system replacement, no dependency discovery beyond the implemented
  quoted-include scanner, no automatic artifact deployment.
- No cryptographic worker authentication: workers are trusted by configuration, and the transport is
  plain TCP without TLS.
- POSIX process and socket paths are implemented but were exercised only on Windows in this release;
  the proven platform is Windows x64 with MSVC and CUDA.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
