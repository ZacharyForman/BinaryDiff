#ifndef BINARY_MATCHER_ELF_EXECUTABLE_SECTION_HEADER_H
#define BINARY_MATCHER_ELF_EXECUTABLE_SECTION_HEADER_H

#include "elf_executable.h"
#include "elf_executable_header.h"
#include <stdint.h>

struct ElfExecutable::SectionHeader {
  const uint32_t kName;
  const uint32_t kType;
  const uint64_t kFlags;
  const uint64_t kAddress;
  const uint64_t kOffset;
  const uint64_t kSize;
  const uint32_t kLink;
  const uint32_t kInfo;
  const uint64_t kAddressAlignment;
  const uint64_t kEntrySize;
};

bool ValidElfSectionHeader(const ElfExecutable::SectionHeader &header);

std::vector<ElfExecutable::SectionHeader>
ParseElfSectionHeaders(const uint8_t *const buf,
                       const ElfExecutable::Header *const header);

#endif // BINARY_MATCHER_ELF_EXECUTABLE_SECTION_HEADER_H
