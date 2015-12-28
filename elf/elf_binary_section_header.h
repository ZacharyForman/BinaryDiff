#ifndef BINARY_MATCHER_ELF_BINARY_SECTION_HEADER_H
#define BINARY_MATCHER_ELF_BINARY_SECTION_HEADER_H

#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"

#include <stdint.h>
#include <string>

// Type that represents an ELF section header.
// An elf section header contains information about
// the sections within the binary.
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

  // Constructs a string representation of the section header
  // that contains all of the information in the above fields.
  std::string ToString() const;
};

// Validates that the given section header is a valid ELF section header.
bool ValidElfSectionHeader(const ElfBinary::SectionHeader &header);

// Parses the ELF section headers from the given buffer.
// Returns an empty vector on failure.
std::vector<ElfBinary::SectionHeader>
ParseElfSectionHeaders(const uint8_t *const buf,
                       const ElfBinary::Header *const header);

#endif // BINARY_MATCHER_ELF_BINARY_SECTION_HEADER_H
