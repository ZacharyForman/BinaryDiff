#include "elf_executable.h"
#include "elf_executable_header.h"
#include "elf_executable_section_header.h"

#include <elf.h>
#include <vector>

#define EXTRACT_ELF_FIELD(bits, offset) \
  *((uint##bits##_t*)(buf+(offset)))

namespace {

static uint32_t
ExtractElfSectionHeaderName(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  return EXTRACT_ELF_FIELD(32, 0);
}

static uint32_t
ExtractElfSectionHeaderType(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  return EXTRACT_ELF_FIELD(32, 4);
}

static uint64_t
ExtractElfSectionHeaderFlags(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 8);
  } else {
    return EXTRACT_ELF_FIELD(64, 8);
  }
}

static uint64_t
ExtractElfSectionHeaderAddress(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 12);
  } else {
    return EXTRACT_ELF_FIELD(64, 16);
  }
}

static uint64_t
ExtractElfSectionHeaderOffset(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 16);
  } else {
    return EXTRACT_ELF_FIELD(64, 24);
  }
}

static uint64_t
ExtractElfSectionHeaderSize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 20);
  } else {
    return EXTRACT_ELF_FIELD(64, 32);
  }
}

static uint32_t
ExtractElfSectionHeaderLink(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 24);
  } else {
    return EXTRACT_ELF_FIELD(32, 40);
  }
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

static uint64_t
ExtractElfSectionHeaderAddressAlignment(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 32);
  } else {
    return EXTRACT_ELF_FIELD(64, 48);
  }
}

static uint64_t
ExtractElfSectionHeaderEntrySize(const uint8_t *const buf,
    const ElfExecutable::Header *const header)
{
  if (header->kClass == ELFCLASS32) {
    return EXTRACT_ELF_FIELD(32, 36);
  } else {
    return EXTRACT_ELF_FIELD(64, 56);
  }
}

static bool
ValidElfSectionHeaderName(const uint32_t kName)
{
  return true;
}

static bool
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
  }
  fprintf(stderr, "ELF Section Header has invalid type\n");
  return false;
}

static bool
ValidElfSectionHeaderFlags(const uint64_t kFlags)
{
  return true;
}

static bool
ValidElfSectionHeaderAddress(const uint64_t kAddress)
{
  return true;
}

static bool
ValidElfSectionHeaderOffset(const uint64_t kOffset)
{
  return true;
}

static bool
ValidElfSectionHeaderSize(const uint64_t kSize)
{
  return true;
}

static bool
ValidElfSectionHeaderLink(const uint32_t kLink)
{
  return true;
}

static bool
ValidElfSectionHeaderInfo(const uint32_t kInfo)
{
  return true;
}

static bool
ValidElfSectionHeaderAddressAlignment(const uint64_t kAddressAlignment)
{
  return true;
}

static bool
ValidElfSectionHeaderEntrySize(const uint64_t kEntrySize)
{
  return true;
}

} // namespace

#undef EXTRACT_ELF_FIELD

bool ValidElfSectionHeader(const ElfExecutable::SectionHeader &header)
{
  if (!ValidElfSectionHeaderName(header.kName)) {
    return false;
  }

  if (!ValidElfSectionHeaderType(header.kType)) {
    return false;
  }

  if (!ValidElfSectionHeaderFlags(header.kFlags)) {
    return false;
  }

  if (!ValidElfSectionHeaderAddress(header.kAddress)) {
    return false;
  }

  if (!ValidElfSectionHeaderOffset(header.kOffset)) {
    return false;
  }

  if (!ValidElfSectionHeaderSize(header.kSize)) {
    return false;
  }

  if (!ValidElfSectionHeaderLink(header.kLink)) {
    return false;
  }

  if (!ValidElfSectionHeaderInfo(header.kInfo)) {
    return false;
  }

  if (!ValidElfSectionHeaderAddressAlignment(header.kAddressAlignment)) {
    return false;
  }

  if (!ValidElfSectionHeaderEntrySize(header.kEntrySize)) {
    return false;
  }

  return true;
}

std::vector<ElfExecutable::SectionHeader>
ParseElfSectionHeaders(const uint8_t *const buf,
                       const ElfExecutable::Header *const header)
{
  const uint64_t kOffset = header->kSectionHeaderOffset;
  const uint64_t kSize = header->kSectionHeaderSize;
  uint64_t count = header->kSectionHeaderCount;
  if (!kOffset || !count) {
    return std::vector<ElfExecutable::SectionHeader>();
  }
  std::vector<ElfExecutable::SectionHeader> section_headers;

  const uint8_t *section_header = buf + kOffset;

  if (count == SHN_LORESERVE) {
    count = ExtractElfSectionHeaderSize(section_header, header);
  }

  for (unsigned i = 0; i < count; i++) {
    section_headers.push_back(std::move(ElfExecutable::SectionHeader{
      ExtractElfSectionHeaderName(section_header + i*kSize, header),
      ExtractElfSectionHeaderType(section_header + i*kSize, header),
      ExtractElfSectionHeaderFlags(section_header + i*kSize, header),
      ExtractElfSectionHeaderAddress(section_header + i*kSize, header),
      ExtractElfSectionHeaderOffset(section_header + i*kSize, header),
      ExtractElfSectionHeaderSize(section_header + i*kSize, header),
      ExtractElfSectionHeaderLink(section_header + i*kSize, header),
      ExtractElfSectionHeaderInfo(section_header + i*kSize, header),
      ExtractElfSectionHeaderAddressAlignment(section_header + i*kSize, header),
      ExtractElfSectionHeaderEntrySize(section_header + i*kSize, header),
    }));
  }

  return section_headers;
}
