#ifndef BINARY_MATCHER_ELF_BINARY_SECTION_HEADER_H
#define BINARY_MATCHER_ELF_BINARY_SECTION_HEADER_H

#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"

#include <stdint.h>
#include <string>

struct ElfBinary::SectionHeader {
  const uint32_t kName;
  const char *const kStringName;
  const uint32_t kType;
  const uint64_t kFlags;
  const uint64_t kAddress;
  const uint64_t kOffset;
  const uint64_t kSize;
  const uint32_t kLink;
  const uint32_t kInfo;
  const uint64_t kAddressAlignment;
  const uint64_t kEntrySize;

  std::string ToString() const;
};

bool ValidElfSectionHeader(const ElfBinary::SectionHeader &header);

std::vector<ElfBinary::SectionHeader>
ParseElfSectionHeaders(const uint8_t *const buf,
                       const ElfBinary::Header *const header);

#endif // BINARY_MATCHER_ELF_BINARY_SECTION_HEADER_H
