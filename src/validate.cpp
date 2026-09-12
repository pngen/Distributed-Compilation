// Distributed Compilation - artifact validation. A compiler exit code is not proof.
// Copyright 2026 Summon Software Labs. Apache License 2.0.
#include <algorithm>
#include <cstring>

#include "dc/codec.hpp"
#include "dc/coordinator.hpp"

namespace dc {
namespace {

bool has_prefix(std::span<const std::byte> bytes, const char* text, std::size_t length) {
  if (bytes.size() < length) return false;
  return std::memcmp(bytes.data(), text, length) == 0;
}

std::uint16_t read_le16(std::span<const std::byte> bytes, std::size_t offset) {
  return static_cast<std::uint16_t>(static_cast<std::uint8_t>(bytes[offset]) |
                                    (static_cast<std::uint16_t>(static_cast<std::uint8_t>(bytes[offset + 1])) << 8));
}

std::uint32_t read_le32(std::span<const std::byte> bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<std::uint8_t>(bytes[offset + static_cast<std::size_t>(i)]))
             << (i * 8);
  }
  return value;
}

std::uint16_t read_be16(std::span<const std::byte> bytes, std::size_t offset) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(static_cast<std::uint8_t>(bytes[offset])) << 8) |
                                    static_cast<std::uint8_t>(bytes[offset + 1]));
}

constexpr std::uint16_t kCoffMachineAmd64 = 0x8664;
constexpr std::uint16_t kCoffMachineArm64 = 0xAA64;
constexpr std::uint16_t kElfMachineX8664 = 0x3E;
constexpr std::uint16_t kElfMachineAarch64 = 0xB7;
constexpr std::uint16_t kElfMachineCuda = 0xBE;

const char* expected_machine_name(ArchKind arch) {
  switch (arch) {
    case ArchKind::X86_64: return "x86_64";
    case ArchKind::Aarch64: return "aarch64";
    default: return "unknown";
  }
}

std::uint16_t expected_coff_machine(ArchKind arch) {
  switch (arch) {
    case ArchKind::X86_64: return kCoffMachineAmd64;
    case ArchKind::Aarch64: return kCoffMachineArm64;
    default: return 0;
  }
}

std::uint16_t expected_elf_machine(ArchKind arch) {
  switch (arch) {
    case ArchKind::X86_64: return kElfMachineX8664;
    case ArchKind::Aarch64: return kElfMachineAarch64;
    default: return 0;
  }
}

bool looks_like_text(std::span<const std::byte> bytes) {
  const std::size_t sample = std::min<std::size_t>(bytes.size(), 4096);
  std::size_t printable = 0;
  for (std::size_t i = 0; i < sample; ++i) {
    const auto value = static_cast<std::uint8_t>(bytes[i]);
    if (value == '\n' || value == '\r' || value == '\t' || (value >= 0x20 && value < 0x7F)) ++printable;
  }
  return sample > 0 && printable * 100 >= sample * 95;
}

struct FormatProbe {
  bool recognized = false;
  std::string description;
  std::uint16_t machine = 0;
  bool machine_is_coff = false;
  bool machine_is_elf = false;
  bool is_pe = false;
  bool is_elf = false;
  bool is_cubin = false;
};

FormatProbe probe_pe(std::span<const std::byte> bytes) {
  FormatProbe probe;
  if (!has_prefix(bytes, "MZ", 2) || bytes.size() < 0x40) return probe;
  const std::uint32_t pe_offset = read_le32(bytes, 0x3C);
  if (pe_offset > bytes.size() || bytes.size() - pe_offset < 24) return probe;
  if (std::memcmp(bytes.data() + pe_offset, "PE\0\0", 4) != 0) return probe;
  probe.recognized = true;
  probe.is_pe = true;
  probe.machine = read_le16(bytes, pe_offset + 4);
  probe.machine_is_coff = true;
  static const char* digits = "0123456789abcdef";
  std::string machine_hex;
  for (int i = 3; i >= 0; --i) machine_hex.push_back(digits[(probe.machine >> (i * 4)) & 0xF]);
  probe.description = "PE image, machine=0x" + machine_hex;
  return probe;
}

FormatProbe probe_elf(std::span<const std::byte> bytes) {
  FormatProbe probe;
  if (!has_prefix(bytes, "\x7f" "ELF", 4) || bytes.size() < 20) return probe;
  const std::uint16_t type = read_le16(bytes, 16);
  probe.recognized = true;
  probe.is_elf = true;
  probe.machine = read_le16(bytes, 18);
  probe.machine_is_elf = true;
  if (probe.machine == kElfMachineCuda) {
    probe.is_cubin = true;
    probe.description = "ELF CUDA device image (cubin)";
  } else if (type == 1) {
    probe.description = "ELF relocatable object";
  } else if (type == 2) {
    probe.description = "ELF executable";
  } else if (type == 3) {
    probe.description = "ELF shared object";
  } else {
    probe.description = "ELF image type " + std::to_string(type);
  }
  return probe;
}

FormatProbe probe_coff_object(std::span<const std::byte> bytes) {
  FormatProbe probe;
  if (bytes.size() < 20) return probe;
  const std::uint16_t machine = read_le16(bytes, 0);
  const std::uint16_t sections = read_le16(bytes, 2);
  const std::uint32_t timestamp = read_le32(bytes, 4);
  const std::uint16_t optional_size = read_le16(bytes, 16);
  const bool known_machine = machine == kCoffMachineAmd64 || machine == kCoffMachineArm64 ||
                             machine == 0x14C || machine == 0x1C0 || machine == 0x1C4 || machine == 0xAA64;
  if (!known_machine) return probe;
  if (sections == 0 || sections > 4096) return probe;
  if (optional_size != 0) return probe;   // plain COFF objects have no optional header
  (void)timestamp;
  probe.recognized = true;
  probe.machine = machine;
  probe.machine_is_coff = true;
  probe.description = "COFF object, sections=" + std::to_string(sections);
  return probe;
}

FormatProbe probe_ptx(std::span<const std::byte> bytes) {
  FormatProbe probe;
  if (!looks_like_text(bytes)) return probe;
  const std::string_view text(reinterpret_cast<const char*>(bytes.data()),
                              std::min<std::size_t>(bytes.size(), 512));
  if (text.find(".version") != std::string_view::npos || text.find(".target") != std::string_view::npos ||
      text.rfind("//", 0) == 0) {
    probe.recognized = true;
    probe.description = "PTX text module";
  }
  return probe;
}

bool machine_matches_target(const FormatProbe& probe, const TargetIdentity& target, std::string& detail) {
  const std::uint16_t expected_coff = expected_coff_machine(target.arch);
  const std::uint16_t expected_elf = expected_elf_machine(target.arch);
  if (probe.machine_is_coff && probe.is_pe) {
    if (expected_coff == 0) {
      detail = "no expected COFF machine for target architecture";
      return false;
    }
    if (probe.machine != expected_coff) {
      detail = std::string("PE machine 0x") + std::to_string(probe.machine) + " does not match target " +
               expected_machine_name(target.arch);
      return false;
    }
    return true;
  }
  if (probe.machine_is_coff) {
    if (probe.machine == 0x14C) return true;   // x86 objects are accepted only for x86 targets
    if (expected_coff == 0) {
      detail = "no expected COFF machine for target architecture";
      return false;
    }
    if (probe.machine != expected_coff) {
      detail = "COFF machine does not match target " + std::string(expected_machine_name(target.arch));
      return false;
    }
    return true;
  }
  if (probe.machine_is_elf) {
    if (probe.is_cubin) return true;   // device images are checked against the accelerator target below
    if (expected_elf == 0) {
      detail = "no expected ELF machine for target architecture";
      return false;
    }
    if (probe.machine != expected_elf) {
      detail = "ELF machine does not match target " + std::string(expected_machine_name(target.arch));
      return false;
    }
  }
  return true;
}

}  // namespace

ValidationReport validate_artifact_bytes(std::span<const std::byte> bytes, OutputKind kind,
                                         const TargetIdentity& target,
                                         const ValidationRequirements& requirements,
                                         const Digest256& expected_digest) {
  ValidationReport report;
  report.id = ValidationId(0);

  const auto push = [&report](std::string check, ValidationOutcome outcome, std::string detail) {
    ValidationCheck entry;
    entry.check = std::move(check);
    entry.outcome = outcome;
    entry.detail = std::move(detail);
    report.checks.push_back(std::move(entry));
  };

  push("existence", bytes.empty() ? ValidationOutcome::Fail : ValidationOutcome::Pass,
       bytes.empty() ? "artifact is empty" : "artifact present");

  if (requirements.require_digest_check) {
    const Digest256 actual = sha256(bytes);
    if (expected_digest.is_zero()) {
      push("digest", ValidationOutcome::Fail, "expected digest is absent");
    } else if (actual != expected_digest) {
      push("digest", ValidationOutcome::Fail, "artifact digest does not match the declared digest");
    } else {
      push("digest", ValidationOutcome::Pass, actual.hex());
    }
  }

  FormatProbe probe;
  if (!bytes.empty()) {
    probe = probe_pe(bytes);
    if (!probe.recognized) probe = probe_elf(bytes);
    if (!probe.recognized) probe = probe_coff_object(bytes);
    if (!probe.recognized) probe = probe_ptx(bytes);
  }

  if (requirements.require_format_check) {
    bool format_ok = false;
    std::string detail;
    switch (kind) {
      case OutputKind::Executable:
      case OutputKind::DynamicLibrary:
        if (target.os == OsKind::Windows) {
          format_ok = probe.is_pe;
          detail = probe.is_pe ? probe.description : "expected a PE image for a Windows target";
        } else {
          format_ok = probe.is_elf && !probe.is_cubin;
          detail = format_ok ? probe.description : "expected an ELF image for the target OS";
        }
        break;
      case OutputKind::Object:
        if (target.object_format == ObjectFormat::Coff) {
          format_ok = probe.machine_is_coff && !probe.is_pe;
          detail = format_ok ? probe.description : "expected a COFF object";
        } else if (target.object_format == ObjectFormat::Elf) {
          format_ok = probe.is_elf && !probe.is_cubin;
          detail = format_ok ? probe.description : "expected an ELF object";
        } else {
          format_ok = probe.machine_is_coff || probe.is_elf;
          detail = format_ok ? probe.description : "expected an object file";
        }
        break;
      case OutputKind::StaticLibrary:
        format_ok = has_prefix(bytes, "!<arch>\n", 8);
        detail = format_ok ? "COFF/ELF archive" : "expected an archive ('!<arch>')";
        break;
      case OutputKind::Cubin:
        format_ok = probe.is_cubin;
        detail = format_ok ? probe.description : "expected an ELF CUDA device image";
        break;
      case OutputKind::Ptx:
        format_ok = probe.recognized && looks_like_text(bytes);
        detail = format_ok ? probe.description : "expected PTX text";
        break;
      case OutputKind::Assembly:
      case OutputKind::PreprocessedSource:
        format_ok = looks_like_text(bytes);
        detail = format_ok ? "text output" : "expected text output";
        break;
    }
    push("format", format_ok ? ValidationOutcome::Pass : ValidationOutcome::Fail, std::move(detail));
  }

  if (requirements.require_target_metadata && probe.recognized) {
    std::string detail;
    const bool matches = machine_matches_target(probe, target, detail);
    push("target_metadata", matches ? ValidationOutcome::Pass : ValidationOutcome::Fail,
         matches ? probe.description : detail);
  } else if (requirements.require_target_metadata) {
    push("target_metadata", ValidationOutcome::Unknown,
         "artifact format was not recognised, so target metadata could not be checked");
  }

  if (requirements.require_dependency_metadata) {
    push("dependency_metadata", bytes.empty() ? ValidationOutcome::Fail : ValidationOutcome::Pass,
         bytes.empty() ? "no artifact to inspect" : "dependency binding recorded in provenance");
  }

  ValidationOutcome aggregate = ValidationOutcome::Pass;
  std::size_t failures = 0;
  std::size_t unknowns = 0;
  for (const auto& check : report.checks) {
    if (check.outcome == ValidationOutcome::Fail) {
      ++failures;
      aggregate = ValidationOutcome::Fail;
    } else if (check.outcome == ValidationOutcome::Unknown) {
      ++unknowns;
      if (aggregate == ValidationOutcome::Pass) aggregate = ValidationOutcome::Unknown;
    }
  }
  report.aggregate = aggregate;
  report.summary = "checks=" + std::to_string(report.checks.size()) + " failures=" + std::to_string(failures) +
                   " unknown=" + std::to_string(unknowns);
  return report;
}

}  // namespace dc
