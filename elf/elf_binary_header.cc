#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"

#include <elf.h>
#include <iomanip>
#include <sstream>

using Header = ElfBinary::Header;

#define EXTRACT_ELF_FIELD(bits, offset) \
  *(reinterpret_cast<const uint##bits##_t*>(buf+(offset)))

namespace {

// Set of helper methods that extract fields from
// the buffer.

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
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, EI_NIDENT+8);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, EI_NIDENT+8);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfHeaderProgramHeaderOffset(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, EI_NIDENT+12);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, EI_NIDENT+16);
    default: return ~0ULL;
  }
}

static uint64_t
ExtractElfHeaderSectionHeaderOffset(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, EI_NIDENT+16);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, EI_NIDENT+24);
    default: return ~0ULL;
  }
}

static uint32_t
ExtractElfHeaderFlags(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, EI_NIDENT+20);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(32, EI_NIDENT+32);
    default: return ~0U;
  }
}

static uint16_t
ExtractElfHeaderHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, EI_NIDENT+24);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, EI_NIDENT+36);
    default: return 0xFFFF;
  }
}

static uint16_t
ExtractElfHeaderProgramHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, EI_NIDENT+26);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, EI_NIDENT+38);
    default: return 0xFFFF;
  }
}

static uint16_t
ExtractElfHeaderProgramHeaderCount(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, EI_NIDENT+28);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, EI_NIDENT+40);
    default: return 0xFFFF;
  }
}

static uint16_t
ExtractElfHeaderSectionHeaderSize(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, EI_NIDENT+30);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, EI_NIDENT+42);
    default: return 0xFFFF;
  }
}

static uint16_t
ExtractElfHeaderSectionHeaderCount(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, EI_NIDENT+32);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, EI_NIDENT+44);
    default: return 0xFFFF;
  }
}

static uint16_t
ExtractElfHeaderSectionHeaderNamesIndex(const uint8_t *const buf)
{
  switch (ExtractElfHeaderClass(buf)) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(16, EI_NIDENT+34);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(16, EI_NIDENT+46);
    default: return 0xFFFF;
  }
}

// Set of helper methods that validate individual fields.

static bool
ValidElfHeaderClass(const uint8_t kClass)
{
  switch (kClass) {
    case ELFCLASS32: return true;
    case ELFCLASS64: return true;
    default: break;
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
    default: break;
  }
  fprintf(stderr, "ELF Header has invalid data type\n");
  return false;
}

static bool
ValidElfHeaderShortVersion(const uint8_t kShortVersion)
{
  switch (kShortVersion) {
    case EV_CURRENT: return true;
    default: break;
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
    default: break;
  }
  fprintf(stderr, "ELF Header has invalid OS ABI\n");
  return false;
}

static bool
ValidElfHeaderAbiVersion(const uint8_t kAbiVersion)
{
  switch (kAbiVersion) {
    case 0: return true;
    default: break;
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
    default: break;
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
    default: break;
  }
  fprintf(stderr, "ELF Header has invalid machine type\n");
  return false;
}

static bool
ValidElfHeaderLongVersion(const uint32_t kLongVersion)
{
  switch (kLongVersion) {
    case EV_CURRENT: return true;
    default: break;
  }
  fprintf(stderr, "ELF Header has invalid long version\n");
  return false;
}

static bool
ValidElfHeaderFlags(const uint32_t kFlags)
{
  switch (kFlags) {
    case 0: return true;
    default: break;
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
    default: break;
  }
  fprintf(stderr, "ELF Header has invalid header size\n");
  return false;
}

// Set of helper methods that convert enumerated values into strings.

static const char *ElfHeaderClassString(const uint8_t kClass)
{
  switch (kClass) {
    case ELFCLASS32: return "ELF32";
    case ELFCLASS64: return "ELF64";
    default: return "UNKNOWN";
  }
}

static const char *ElfHeaderDataString(const uint8_t kData)
{
  switch (kData) {
    case ELFDATA2LSB: return "2's complement, little endian";
    case ELFDATA2MSB: return "2's complement, big endian";
    default: return "UNKNOWN";
  }
}

static const char *ElfHeaderOsAbiString(const uint8_t kOsAbi)
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
    default: return "UNKNOWN";
  }
}

static const char *ElfHeaderTypeString(const uint16_t kType)
{
  switch (kType) {
    case ET_REL: return "Relocatable";
    case ET_EXEC: return "Binary";
    case ET_DYN: return "Shared Object";
    case ET_CORE: return "Core dump";
    default: return "UNKNOWN";
  }
}

static const char *ElfHeaderMachineString(const uint16_t kMachine)
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
    default: return "UNKNOWN";
  }
}

} // namespace

#undef EXTRACT_ELF_FIELD

bool ValidElfHeader(const Header *const head)
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

  if (!ValidElfHeaderFlags(head->kFlags)) {
    return false;
  }

  if (!ValidElfHeaderHeaderSize(head->kHeaderSize)) {
    return false;
  }

  return true;
}

Header *ParseElfHeader(const uint8_t *const buf)
{
  return new Header {
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

std::string Header::ToString() const
{
  std::stringstream res;
  res << "ELF Header:"
      << "\n  Class:                   " << ElfHeaderClassString(kClass)
      << "\n  Data:                    " << ElfHeaderDataString(kData)
      << "\n  ShortVersion:            " << static_cast<unsigned>(kShortVersion)
      << "\n  OsAbi:                   " << ElfHeaderOsAbiString(kOsAbi)
      << "\n  AbiVersion:              " << static_cast<unsigned>(kAbiVersion)
      << "\n  Type:                    " << ElfHeaderTypeString(kType)
      << "\n  Machine:                 " << ElfHeaderMachineString(kMachine)
      << std::hex
      << "\n  LongVersion:             " << "0x" << kLongVersion
      << "\n  EntryPoint:              " << "0x" << kEntryPoint
      << std::dec
      << "\n  ProgramHeaderOffset:     " << kProgramHeaderOffset
      << "\n  SectionHeaderOffset:     " << kSectionHeaderOffset
      << std::hex
      << "\n  Flags:                   " << "0x" << kFlags
      << std::dec
      << "\n  HeaderSize:              " << kHeaderSize
      << "\n  ProgramHeaderSize:       " << kProgramHeaderSize
      << "\n  ProgramHeaderCount:      " << kProgramHeaderCount
      << "\n  SectionHeaderSize:       " << kSectionHeaderSize
      << "\n  SectionHeaderCount:      " << kSectionHeaderCount
      << "\n  SectionHeaderNamesIndex: " << kSectionHeaderNamesIndex;
  return res.str();
}
