#include "elf_executable.h"
#include "elf_executable_header.h"

#include <elf.h>
#include <iomanip>
#include <sstream>

#define EXTRACT_ELF_FIELD(bits, offset) \
  *((uint##bits##_t*)(buf+(offset)))

namespace {

static uint8_t
ExtractElfHeaderClass(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 4);
}

static uint8_t
ExtractElfHeaderData(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 5);
}

static uint8_t
ExtractElfHeaderShortVersion(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 6);
}

static uint8_t
ExtractElfHeaderOsAbi(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 7);
}

static uint8_t
ExtractElfHeaderAbiVersion(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(8, 8);
}

static uint16_t
ExtractElfHeaderType(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(16, EI_NIDENT);
}

static uint16_t
ExtractElfHeaderMachine(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(16, EI_NIDENT+2);
}

static uint32_t
ExtractElfHeaderLongVersion(const uint8_t *const buf)
{
  return EXTRACT_ELF_FIELD(32, EI_NIDENT+4);
}

static uint64_t
ExtractElfHeaderEntryPoint(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+8);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+8);
    }
  }
  return -1;
}

static uint64_t
ExtractElfHeaderProgramHeaderOffset(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+12);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+16);
    }
  }
  return -1;
}

static uint64_t
ExtractElfHeaderSectionHeaderOffset(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+16);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(64, EI_NIDENT+24);
    }
  }
  return -1;
}

static uint32_t
ExtractElfHeaderFlags(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+20);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(32, EI_NIDENT+32);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+24);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+36);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderProgramHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+26);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+38);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderProgramHeaderCount(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+28);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+40);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderSectionHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+30);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+42);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderSectionHeaderCount(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+32);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+44);
    }
  }
  return -1;
}

static uint16_t
ExtractElfHeaderSectionHeaderNamesIndex(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+34);
    }
    case ELFCLASS64: {
      return EXTRACT_ELF_FIELD(16, EI_NIDENT+46);
    }
  }
  return -1;
}

static bool
ValidElfHeaderClass(const uint8_t kClass)
{
  switch (kClass) {
    case ELFCLASS32: return true;
    case ELFCLASS64: return true;
  }
  fprintf(stderr, "ELF Header has invalid class\n");
  return false;
}

static bool
ValidElfHeaderData(const uint8_t kData)
{
  switch (kData) {
    case ELFDATA2LSB: return true;
    case ELFDATA2MSB: return true;
  }
  fprintf(stderr, "ELF Header has invalid data type\n");
  return false;
}

static bool
ValidElfHeaderShortVersion(const uint8_t kShortVersion)
{
  switch (kShortVersion) {
    case EV_CURRENT: return true;
  }
  fprintf(stderr, "ELF Header has invalid short version\n");
  return false;
}

static bool
ValidElfHeaderOsAbi(const uint8_t kOsAbi)
{
  switch (kOsAbi) {
    case ELFOSABI_SYSV: return true;
    case ELFOSABI_HPUX: return true;
    case ELFOSABI_NETBSD: return true;
    case ELFOSABI_LINUX: return true;
    case ELFOSABI_SOLARIS: return true;
    case ELFOSABI_IRIX: return true;
    case ELFOSABI_FREEBSD: return true;
    case ELFOSABI_TRU64: return true;
    case ELFOSABI_ARM: return true;
    case ELFOSABI_STANDALONE: return true;
  }
  fprintf(stderr, "ELF Header has invalid OS ABI\n");
  return false;
}

static bool
ValidElfHeaderAbiVersion(const uint8_t kAbiVersion)
{
  switch (kAbiVersion) {
    case 0: return true;
  }
  fprintf(stderr, "ELF Header has invalid ABI version\n");
  return false;
}

static bool
ValidElfHeaderType(const uint16_t kType)
{
  switch (kType) {
    case ET_REL: return true;
    case ET_EXEC: return true;
    case ET_DYN: return true;
    case ET_CORE: return true;
  }
  fprintf(stderr, "ELF Header has invalid type\n");
  return false;
}

static bool
ValidElfHeaderMachine(const uint16_t kMachine)
{
  switch (kMachine) {
    case EM_M32: return true;
    case EM_SPARC: return true;
    case EM_386: return true;
    case EM_68K: return true;
    case EM_88K: return true;
    case EM_860: return true;
    case EM_MIPS: return true;
    case EM_PARISC: return true;
    case EM_SPARC32PLUS: return true;
    case EM_PPC: return true;
    case EM_PPC64: return true;
    case EM_S390: return true;
    case EM_ARM: return true;
    case EM_SH: return true;
    case EM_SPARCV9: return true;
    case EM_IA_64: return true;
    case EM_X86_64: return true;
    case EM_VAX: return true;
  }
  fprintf(stderr, "ELF Header has invalid machine type\n");
  return false;
}

static bool
ValidElfHeaderLongVersion(const uint32_t kLongVersion)
{
  switch (kLongVersion) {
    case EV_CURRENT: return true;
  }
  fprintf(stderr, "ELF Header has invalid long version\n");
  return false;
}

static bool
ValidElfHeaderEntryPoint(const uint64_t kEntryPoint)
{
  return true;
}

static bool
ValidElfHeaderProgramHeaderOffset(const uint64_t kProgramHeaderOffset)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderOffset(const uint64_t kSectionHeaderOffset)
{
  return true;
}

static bool
ValidElfHeaderFlags(const uint32_t kFlags)
{
  switch (kFlags) {
    case 0: return true;
  }
  fprintf(stderr, "ELF Header has invalid flags\n");
  return false;
}

static bool
ValidElfHeaderHeaderSize(const uint16_t kHeaderSize)
{
  switch (kHeaderSize) {
    case EI_NIDENT + 36: return true;
    case EI_NIDENT + 48: return true;
  }
  fprintf(stderr, "ELF Header has invalid header size\n");
  return false;
}

static bool
ValidElfHeaderProgramHeaderSize(const uint16_t kProgramHeaderSize)
{
  return true;
}

static bool
ValidElfHeaderProgramHeaderCount(const uint16_t kProgramHeaderCount)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderSize(const uint16_t kSectionHeaderSize)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderCount(const uint16_t kSectionHeaderCount)
{
  return true;
}

static bool
ValidElfHeaderSectionHeaderNamesIndex(const uint16_t kSectionHeaderNamesIndex)
{
  return true;
}

static const char *const ElfHeaderClassString(const uint8_t kClass)
{
  switch (kClass) {
    case ELFCLASS32: return "ELF32";
    case ELFCLASS64: return "ELF64";
  }
  return "UNKNOWN";
}

static const char *const ElfHeaderDataString(const uint8_t kData)
{
  switch (kData) {
    case ELFDATA2LSB: return "2's complement, little endian";
    case ELFDATA2MSB: return "2's complement, big endian";
  }
  return "UNKNOWN";
}

static const char *const ElfHeaderOsAbiString(const uint8_t kOsAbi)
{
  switch (kOsAbi) {
    case ELFOSABI_SYSV: return "UNIX System V ABI";
    case ELFOSABI_HPUX: return "HP-UX ABI";
    case ELFOSABI_NETBSD: return "NetBSD ABI";
    case ELFOSABI_LINUX: return "Linux ABI";
    case ELFOSABI_SOLARIS: return "Solaris ABI";
    case ELFOSABI_IRIX: return "IRIX ABI";
    case ELFOSABI_FREEBSD: return "FreeBSD ABI";
    case ELFOSABI_TRU64: return "TRU64 Unix ABI";
    case ELFOSABI_ARM: return "ARM architecture ABI";
    case ELFOSABI_STANDALONE: return "Stand-alone (embedded) ABI";
  }
  return "UNKNOWN";
}

static const char *const ElfHeaderTypeString(const uint16_t kType)
{
  switch (kType) {
    case ET_REL: return "Relocatable";
    case ET_EXEC: return "Executable";
    case ET_DYN: return "Shared Object";
    case ET_CORE: return "Core dump";
  }
  return "UNKNOWN";
}

static const char *const ElfHeaderMachineString(const uint16_t kMachine)
{
  switch (kMachine) {
    case EM_M32: return "AT&T WE 32100";
    case EM_SPARC: return "Sun Microsystems SPARC";
    case EM_386: return "Intel 80386";
    case EM_68K: return "Motorola 68000";
    case EM_88K: return "Motorola 88000";
    case EM_860: return "Intel 80860";
    case EM_MIPS: return "MIPS RS3000 (big-endian only)";
    case EM_PARISC: return "HP/PA";
    case EM_SPARC32PLUS: return "SPARC with enhanced instruction set";
    case EM_PPC: return "PowerPC";
    case EM_PPC64: return "PowerPC 64-bit";
    case EM_S390: return "IBM S/390";
    case EM_ARM: return "Advanced RISC Machines";
    case EM_SH: return "Renesas SuperH";
    case EM_SPARCV9: return "SPARC v9 64-bit";
    case EM_IA_64: return "Intel Itanium";
    case EM_X86_64: return "AMD x86-64";
    case EM_VAX: return "DEC Vax";
  }
  return "UNKNOWN";
}


} // namespace

#undef EXTRACT_ELF_FIELD

bool ValidElfHeader(const ElfExecutable::Header *const head)
{
  if (!head) {
    return false;
  }

  if (!ValidElfHeaderClass(head->kClass)) {
    return false;
  }

  if (!ValidElfHeaderData(head->kData)) {
    return false;
  }

  if (!ValidElfHeaderShortVersion(head->kShortVersion)) {
    return false;
  }

  if (!ValidElfHeaderOsAbi(head->kOsAbi)) {
    return false;
  }

  if (!ValidElfHeaderAbiVersion(head->kAbiVersion)) {
    return false;
  }

  if (!ValidElfHeaderType(head->kType)) {
    return false;
  }

  if (!ValidElfHeaderMachine(head->kMachine)) {
    return false;
  }

  if (!ValidElfHeaderLongVersion(head->kLongVersion)) {
    return false;
  }

  if (!ValidElfHeaderEntryPoint(head->kEntryPoint)) {
    return false;
  }

  if (!ValidElfHeaderProgramHeaderOffset(head->kProgramHeaderOffset)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderOffset(head->kSectionHeaderOffset)) {
    return false;
  }

  if (!ValidElfHeaderFlags(head->kFlags)) {
    return false;
  }

  if (!ValidElfHeaderHeaderSize(head->kHeaderSize)) {
    return false;
  }

  if (!ValidElfHeaderProgramHeaderSize(head->kProgramHeaderSize)) {
    return false;
  }

  if (!ValidElfHeaderProgramHeaderCount(head->kProgramHeaderCount)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderSize(head->kSectionHeaderSize)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderCount(head->kSectionHeaderCount)) {
    return false;
  }

  if (!ValidElfHeaderSectionHeaderNamesIndex(head->kSectionHeaderNamesIndex)) {
    return false;
  }
  return true;
}

ElfExecutable::Header *ParseElfHeader(const uint8_t *const buf)
{
  return new ElfExecutable::Header {
    ExtractElfHeaderClass(buf),
    ExtractElfHeaderData(buf),
    ExtractElfHeaderShortVersion(buf),
    ExtractElfHeaderOsAbi(buf),
    ExtractElfHeaderAbiVersion(buf),
    ExtractElfHeaderType(buf),
    ExtractElfHeaderMachine(buf),
    ExtractElfHeaderLongVersion(buf),
    ExtractElfHeaderEntryPoint(buf),
    ExtractElfHeaderProgramHeaderOffset(buf),
    ExtractElfHeaderSectionHeaderOffset(buf),
    ExtractElfHeaderFlags(buf),
    ExtractElfHeaderHeaderSize(buf),
    ExtractElfHeaderProgramHeaderSize(buf),
    ExtractElfHeaderProgramHeaderCount(buf),
    ExtractElfHeaderSectionHeaderSize(buf),
    ExtractElfHeaderSectionHeaderCount(buf),
    ExtractElfHeaderSectionHeaderNamesIndex(buf),
  };
}

std::string ElfExecutable::Header::ToString() const
{
  std::stringstream res;
  res << "ELF Header:";
  res << "\n  Class:                   " << ElfHeaderClassString(kClass);
  res << "\n  Data:                    " << ElfHeaderDataString(kData);
  res << "\n  ShortVersion:            " << (uint16_t)kShortVersion;
  res << "\n  OsAbi:                   " << ElfHeaderOsAbiString(kOsAbi);
  res << "\n  AbiVersion:              " << (uint16_t)kAbiVersion;
  res << "\n  Type:                    " << ElfHeaderTypeString(kType);
  res << "\n  Machine:                 " << ElfHeaderMachineString(kMachine);
  res << std::hex;
  res << "\n  LongVersion:             " << "0x" << kLongVersion;
  res << "\n  EntryPoint:              " << "0x" << kEntryPoint;
  res << std::dec;
  res << "\n  ProgramHeaderOffset:     " << kProgramHeaderOffset;
  res << "\n  SectionHeaderOffset:     " << kSectionHeaderOffset;
  res << std::hex;
  res << "\n  Flags:                   " << "0x" << kFlags;
  res << std::dec;
  res << "\n  HeaderSize:              " << kHeaderSize;
  res << "\n  ProgramHeaderSize:       " << kProgramHeaderSize;
  res << "\n  ProgramHeaderCount:      " << kProgramHeaderCount;
  res << "\n  SectionHeaderSize:       " << kSectionHeaderSize;
  res << "\n  SectionHeaderCount:      " << kSectionHeaderCount;
  res << "\n  SectionHeaderNamesIndex: " << kSectionHeaderNamesIndex;
  return res.str();
}
