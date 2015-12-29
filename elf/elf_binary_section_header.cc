#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"
#include "elf/elf_binary_section_header.h"

#include <elf.h>
#include <iomanip>
#include <sstream>
#include <vector>

using Header = ElfBinary::Header;
using SectionHeader = ElfBinary::SectionHeader;

#define EXTRACT_ELF_FIELD(bits, offset) \
  *(reinterpret_cast<const uint##bits##_t*>(buf+(offset)))

namespace {

// Set of helper methods that extract fields from
// the buffer.

inline static uint32_t
ExtractElfSectionHeaderName(const uint8_t *const buf,
    const Header *const)
{
  return EXTRACT_ELF_FIELD(32, 0);
}

inline static uint32_t
ExtractElfSectionHeaderType(const uint8_t *const buf,
    const Header *const)
{
  return EXTRACT_ELF_FIELD(32, 4);
}

inline static uint64_t
ExtractElfSectionHeaderFlags(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 8);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 8);
    default: return ~0ULL;
  }
}

inline static uint64_t
ExtractElfSectionHeaderAddress(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 12);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 16);
    default: return ~0ULL;
  }
}

inline static uint64_t
ExtractElfSectionHeaderOffset(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 16);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 24);
    default: return ~0ULL;
  }
}

inline static uint64_t
ExtractElfSectionHeaderSize(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 20);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 32);
    default: return ~0ULL;
  }
}

inline static uint32_t
ExtractElfSectionHeaderLink(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 24);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(32, 40);
    default: return ~0U;
  }
}

inline static uint32_t
ExtractElfSectionHeaderInfo(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 28);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(32, 44);
    default: return ~0U;
  }
}

inline static uint64_t
ExtractElfSectionHeaderAddressAlignment(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 32);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 48);
    default: return ~0ULL;
  }
}

inline static uint64_t
ExtractElfSectionHeaderEntrySize(const uint8_t *const buf,
    const Header *const header)
{
  switch (header->kClass) {
    case ELFCLASS32: return EXTRACT_ELF_FIELD(32, 36);
    case ELFCLASS64: return EXTRACT_ELF_FIELD(64, 56);
    default: return ~0ULL;
  }
}

// Set of helper methods that validate individual fields.

inline static bool
ValidElfSectionHeaderType(const uint32_t kType)
{
  switch (kType) {
    case SHT_NULL: return true;
    case SHT_PROGBITS: return true;
    case SHT_SYMTAB: return true;
    case SHT_STRTAB: return true;
    case SHT_RELA: return true;
    case SHT_HASH: return true;
    case SHT_DYNAMIC: return true;
    case SHT_NOTE: return true;
    case SHT_NOBITS: return true;
    case SHT_REL: return true;
    case SHT_SHLIB: return true;
    case SHT_DYNSYM: return true;
    case SHT_LOPROC: return true;
    case SHT_HIPROC: return true;
    case SHT_LOUSER: return true;
    case SHT_HIUSER: return true;
    case SHT_GNU_verdef: return true;
    case SHT_GNU_verneed: return true;
    case SHT_GNU_versym: return true;
    case SHT_GNU_HASH: return true;
    case SHT_INIT_ARRAY: return true;
    case SHT_FINI_ARRAY: return true;
    default: break;
  }
  fprintf(stderr, "ELF Section Header has invalid type\n");
  return false;
}

// Set of helper methods that convert enumerated values into strings.

inline static const char
*ElfSectionHeaderTypeString(const uint32_t kType)
{
  switch (kType) {
    case SHT_NULL: return "NULL";
    case SHT_PROGBITS: return "PROGBITS";
    case SHT_SYMTAB: return "SYMTAB";
    case SHT_STRTAB: return "STRTAB";
    case SHT_RELA: return "RELA";
    case SHT_HASH: return "HASH";
    case SHT_DYNAMIC: return "DYNAMIC";
    case SHT_NOTE: return "NOTE";
    case SHT_NOBITS: return "NOBITS";
    case SHT_REL: return "REL";
    case SHT_SHLIB: return "SHLIB";
    case SHT_DYNSYM: return "DYNSYM";
    case SHT_LOPROC: return "LOPROC";
    case SHT_HIPROC: return "HIPROC";
    case SHT_LOUSER: return "LOUSER";
    case SHT_HIUSER: return "HIUSER";
    case SHT_GNU_verdef: return "GNU_verdef";
    case SHT_GNU_verneed: return "GNU_verneed";
    case SHT_GNU_versym: return "GNU_versym";
    case SHT_GNU_HASH: return "GNU_HASH";
    case SHT_INIT_ARRAY: return "INIT_ARRAY";
    case SHT_FINI_ARRAY: return "FINI_ARRAY";
    default: return "UNKNOWN";
  }
}

inline static const char
*ElfSectionHeaderFlagsString(const uint64_t kFlags)
{
  switch (kFlags & (SHF_WRITE|SHF_ALLOC|SHF_EXECINSTR)) {
    case SHF_WRITE: return "W  ";
    case SHF_ALLOC: return " A ";
    case SHF_EXECINSTR: return "  X";
    case SHF_WRITE | SHF_ALLOC: return "WA ";
    case SHF_WRITE | SHF_EXECINSTR: return "W  X;";
    case SHF_ALLOC | SHF_EXECINSTR: return " AX";
    case SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR: return "WAX";
    case 0: return "   ";
    default: return "???";
  }
}

} // namespace

#undef EXTRACT_ELF_FIELD

bool ValidElfSectionHeader(const SectionHeader &header)
{
  if (!ValidElfSectionHeaderType(header.kType)) {
    return false;
  }

  return true;
}

std::vector<SectionHeader>
ParseElfSectionHeaders(const uint8_t *const buf,
                       const Header *const header)
{
  const uint64_t kOffset = header->kSectionHeaderOffset;
  const uint64_t kSize = header->kSectionHeaderSize;
  uint64_t count = header->kSectionHeaderCount;
  if (!kOffset || !count) {
    return std::vector<SectionHeader>();
  }
  std::vector<SectionHeader> section_headers;

  const uint8_t *section_header_base = buf + kOffset;

  // If the count is 0, then extract the count from the initial
  // section header.
  if (count == 0) {
    count = ExtractElfSectionHeaderLink(section_header_base, header);
  }

  const uint8_t *const section_header_names_section
      = section_header_base + kSize * header->kSectionHeaderNamesIndex;

  const uint64_t section_header_names_table_offset
      = ExtractElfSectionHeaderOffset(section_header_names_section, header);

  const uint8_t *const section_header_names_table
      = buf + section_header_names_table_offset;

  for (unsigned i = 0; i < count; i++) {
    const uint8_t *section_header = section_header_base + i*kSize;
    const uint32_t kName
        = ExtractElfSectionHeaderName(section_header, header);

    section_headers.push_back(std::move(SectionHeader{
      kName,
      reinterpret_cast<const char*>(section_header_names_table+kName),
      ExtractElfSectionHeaderType(section_header, header),
      ExtractElfSectionHeaderFlags(section_header, header),
      ExtractElfSectionHeaderAddress(section_header, header),
      ExtractElfSectionHeaderOffset(section_header, header),
      ExtractElfSectionHeaderSize(section_header, header),
      ExtractElfSectionHeaderLink(section_header, header),
      ExtractElfSectionHeaderInfo(section_header, header),
      ExtractElfSectionHeaderAddressAlignment(section_header, header),
      ExtractElfSectionHeaderEntrySize(section_header, header),
    }));
  }

  return section_headers;
}

std::string SectionHeader::ToString() const
{
  std::stringstream res;
  res << "\n  Name:             " << kStringName
      << "\n  Type:             " << ElfSectionHeaderTypeString(kType)
      << "\n  Flags:            " << ElfSectionHeaderFlagsString(kFlags)
      << std::hex
      << "\n  Address:          " << "0x" << kAddress
      << "\n  Offset:           " << "0x" << kOffset
      << "\n  Size:             " << "0x" << kSize
      << "\n  Link:             " << "0x" << kLink
      << "\n  Info:             " << "0x" << kInfo
      << "\n  AddressAlignment: " << "0x" << kAddressAlignment
      << "\n  EntrySize:        " << "0x" << kEntrySize;
  return res.str();
}
