#include "elf_executable.h"
#include "elf_executable_header.h"
#include "elf_executable_program_header.h"

#include <elf.h>
#include <iomanip>
#include <stdint.h>
#include <sstream>
#include <vector>

#define EXTRACT_ELF_FIELD(bits, offset) \
  *((uint##bits##_t*)(buf+(offset)))

namespace {

static uint32_t
ExtractElfProgramHeaderType(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  return EXTRACT_ELF_FIELD(32, 0);
}

static uint32_t
ExtractElfProgramHeaderFlags(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 24);
  } else {
    return EXTRACT_ELF_FIELD(32, 4);
  }
}

static uint64_t
ExtractElfProgramHeaderOffset(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 4);
  } else {
    return EXTRACT_ELF_FIELD(64, 8);
  }
}

static uint64_t
ExtractElfProgramHeaderVirtualAddress(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 8);
  } else {
    return EXTRACT_ELF_FIELD(64, 16);
  }
}

static uint64_t
ExtractElfProgramHeaderPhysicalAddress(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 12);
  } else {
    return EXTRACT_ELF_FIELD(64, 24);
  }
}

static uint64_t
ExtractElfProgramHeaderFileSize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 16);
  } else {
    return EXTRACT_ELF_FIELD(64, 32);
  }
}

static uint64_t
ExtractElfProgramHeaderMemorySize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 20);
  } else {
    return EXTRACT_ELF_FIELD(64, 40);
  }
}

static uint64_t
ExtractElfProgramHeaderAlign(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 28);
  } else {
    return EXTRACT_ELF_FIELD(64, 48);
  }
}

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
  }
  fprintf(stderr, "ELF Program Header has invalid flags\n");
  return false;
}

static bool
ValidElfProgramHeaderOffset(const uint64_t kOffset)
{
  return true;
}

static bool
ValidElfProgramHeaderVirtualAddress(const uint64_t kVirtualAddress)
{
  return true;
}

static bool
ValidElfProgramHeaderPhysicalAddress(const uint64_t kPhysicalAddress)
{
  return true;
}

static bool
ValidElfProgramHeaderFileSize(const uint64_t kFileSize)
{
  return true;
}

static bool
ValidElfProgramHeaderMemorySize(const uint64_t kMemorySize)
{
  return true;
}

static bool
ValidElfProgramHeaderAlign(const uint64_t kAlign)
{
  return true;
}

static uint32_t
ExtractElfSectionHeaderInfo(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 28);
  } else {
    return EXTRACT_ELF_FIELD(32, 44);
  }
}

static const char *const ElfProgramHeaderTypeString(const uint32_t kType)
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
  }
  return "UNKNOWN";
}

static const char *const ElfProgramHeaderFlagsString(const uint32_t kFlags)
{
  switch (kFlags) {
    case PF_X: return "  X";
    case PF_W: return " W ";
    case PF_R: return "R  ";
    case PF_X | PF_W: return " WX";
    case PF_X | PF_R: return "R X";
    case PF_W | PF_R: return "RW ";
    case PF_X | PF_W | PF_R: return "RWX";
  }
  return "   ";
}

} // namespace

#undef EXTRACT_ELF_FIELD

bool ValidElfProgramHeader(const ElfExecutable::ProgramHeader &program_header)
{
  if (!ValidElfProgramHeaderType(program_header.kType)) {
    return false;
  }

  if (!ValidElfProgramHeaderFlags(program_header.kFlags)) {
    return false;
  }

  if (!ValidElfProgramHeaderOffset(program_header.kOffset)) {
    return false;
  }

  if (!ValidElfProgramHeaderVirtualAddress(program_header.kVirtualAddress)) {
    return false;
  }

  if (!ValidElfProgramHeaderPhysicalAddress(program_header.kPhysicalAddress)) {
    return false;
  }

  if (!ValidElfProgramHeaderFileSize(program_header.kFileSize)) {
    return false;
  }

  if (!ValidElfProgramHeaderMemorySize(program_header.kMemorySize)) {
    return false;
  }

  if (!ValidElfProgramHeaderAlign(program_header.kAlign)) {
    return false;
  }

  return true;
}

std::vector<ElfExecutable::ProgramHeader>
ParseElfProgramHeaders(const uint8_t *const buf,
                       const ElfExecutable::Header *const header)
{
  const uint64_t kOffset = header->kProgramHeaderOffset;
  const uint64_t kSize = header->kProgramHeaderSize;
  uint64_t count = header->kProgramHeaderCount;
  if (!kOffset || !count) {
    return std::vector<ElfExecutable::ProgramHeader>();
  }
  std::vector<ElfExecutable::ProgramHeader> program_headers;

  const uint8_t *program_header = buf + kOffset;

  if (count == PN_XNUM) {
    count = ExtractElfSectionHeaderInfo(program_header, header);
  }

  for (unsigned i = 0; i < count; i++) {
    program_headers.push_back(std::move(ElfExecutable::ProgramHeader{
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

std::string ElfExecutable::ProgramHeader::ToString() const
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
