#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"
#include "elf/elf_binary_program_header.h"

#include <elf.h>
#include <iomanip>
#include <stdint.h>
#include <sstream>
#include <vector>

using Header = ElfBinary::Header;
using ProgramHeader = ElfBinary::ProgramHeader;

#define EXTRACT_ELF_FIELD(bits, offset) \
  *(reinterpret_cast<const uint##bits##_t*>(buf+(offset)))

namespace {

// Set of helper methods that extract fields from
// the buffer.

static uint32_t
ExtractElfProgramHeaderType(const uint8_t *const buf,
    const Header *const)
{
  return EXTRACT_ELF_FIELD(32, 0);
}

static uint32_t
ExtractElfProgramHeaderFlags(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 24);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(32, 4);
    default: return ~0U;
  }
}

static uint64_t
ExtractElfProgramHeaderOffset(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 4);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 8);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfProgramHeaderVirtualAddress(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 8);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 16);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfProgramHeaderPhysicalAddress(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 12);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 24);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfProgramHeaderFileSize(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 16);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 32);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfProgramHeaderMemorySize(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 20);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 40);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfProgramHeaderAlign(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 28);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 48);
    default: return ~0ULL;
  }
}

// Set of helper methods that validate individual fields.

static bool
ValidElfProgramHeaderType(const uint32_t kType)
{
  switch (kType) {
    case PT_NULL: return true;
    case PT_LOAD: return true;
    case PT_DYNAMIC: return true;
    case PT_INTERP: return true;
    case PT_NOTE: return true;
    case PT_SHLIB: return true;
    case PT_PHDR: return true;
    case PT_LOPROC: return true;
    case PT_HIPROC: return true;
    case PT_GNU_STACK: return true;
    case PT_GNU_EH_FRAME: return true;
    case PT_GNU_RELRO: return true;
    case PT_TLS: return true;
    default: break;
  }
  fprintf(stderr, "ELF Program Header has invalid type\n");
  return false;
}

static bool
ValidElfProgramHeaderFlags(const uint32_t kFlags)
{
  switch (kFlags) {
    case PF_X: return true;
    case PF_W: return true;
    case PF_R: return true;
    case PF_X | PF_W: return true;
    case PF_X | PF_R: return true;
    case PF_W | PF_R: return true;
    case PF_X | PF_W | PF_R: return true;
    default: break;
  }
  fprintf(stderr, "ELF Program Header has invalid flags\n");
  return false;
}

static uint32_t
ExtractElfSectionHeaderInfo(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 28);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(32, 44);
    default: return ~0u;
  }
}

// Set of helper methods that convert enumerated values into strings.

static const char *ElfProgramHeaderTypeString(const uint32_t kType)
{
  switch (kType) {
    case PT_NULL: return "NULL";
    case PT_LOAD: return "LOAD";
    case PT_DYNAMIC: return "DYNAMIC";
    case PT_INTERP: return "INTERP";
    case PT_NOTE: return "NOTE";
    case PT_SHLIB: return "SHLIB";
    case PT_PHDR: return "PHDR";
    case PT_LOPROC: return "LOPROC";
    case PT_HIPROC: return "HIPROC";
    case PT_GNU_STACK: return "GNU_STACK";
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case PT_GNU_RELRO: return "GNU_RELRO";
    case PT_TLS: return "TLS";
    default: return "UNKNOWN";
  }
}

static const char *ElfProgramHeaderFlagsString(const uint32_t kFlags)
{
  switch (kFlags) {
    case PF_X: return "  X";
    case PF_W: return " W ";
    case PF_R: return "R  ";
    case PF_X | PF_W: return " WX";
    case PF_X | PF_R: return "R X";
    case PF_W | PF_R: return "RW ";
    case PF_X | PF_W | PF_R: return "RWX";
    default: return "   ";
  }
}

} // namespace

#undef EXTRACT_ELF_FIELD

bool ValidElfProgramHeader(const ProgramHeader &program_header)
{
  if (!ValidElfProgramHeaderType(program_header.kType)) {
    return false;
  }

  if (!ValidElfProgramHeaderFlags(program_header.kFlags)) {
    return false;
  }

  return true;
}

std::vector<ProgramHeader> ParseElfProgramHeaders(const uint8_t *const buf,
                                                  const Header *const header)
{
  const uint64_t kOffset = header->kProgramHeaderOffset;
  const uint64_t kSize = header->kProgramHeaderSize;
  uint64_t count = header->kProgramHeaderCount;
  if (!kOffset || !count) {
    return std::vector<ProgramHeader>();
  }
  std::vector<ProgramHeader> program_headers;

  const uint8_t *program_header = buf + kOffset;

  // If count == PN_XNUM, we have to get the count from the section header.
  if (count == PN_XNUM) {
    const uint8_t *const section_header_base
        = buf + header->kSectionHeaderOffset;
    count = ExtractElfSectionHeaderInfo(section_header_base, header);
  }

  for (unsigned i = 0; i < count; i++) {
    program_headers.push_back(std::move(ProgramHeader{
      ExtractElfProgramHeaderType(program_header + i*kSize, header),
      ExtractElfProgramHeaderFlags(program_header + i*kSize, header),
      ExtractElfProgramHeaderOffset(program_header + i*kSize, header),
      ExtractElfProgramHeaderVirtualAddress(program_header + i*kSize, header),
      ExtractElfProgramHeaderPhysicalAddress(program_header + i*kSize, header),
      ExtractElfProgramHeaderFileSize(program_header + i*kSize, header),
      ExtractElfProgramHeaderMemorySize(program_header + i*kSize, header),
      ExtractElfProgramHeaderAlign(program_header + i*kSize, header)
    }));
  }

  return program_headers;
}

std::string ProgramHeader::ToString() const
{
  std::stringstream res;
  res << "\n  Type:            " << ElfProgramHeaderTypeString(kType)
      << "\n  Flags:           " << ElfProgramHeaderFlagsString(kFlags)
      << std::hex
      << "\n  Offset:          " << "0x" << kOffset
      << "\n  VirtualAddress:  " << "0x" << kVirtualAddress
      << "\n  PhysicalAddress: " << "0x" << kPhysicalAddress
      << std::dec
      << "\n  FileSize:        " << kFileSize
      << "\n  MemorySize:      " << kMemorySize
      << std::hex
      << "\n  Align:           " << "0x" << kAlign
      << std::dec;
  return res.str();
}
