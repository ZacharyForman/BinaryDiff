#ifndef BINARY_MATCHER_ELF_EXECUTABLE_PROGRAM_HEADER_H
#define BINARY_MATCHER_ELF_EXECUTABLE_PROGRAM_HEADER_H

#include "elf_executable.h"
#include "elf_executable_header.h"
#include <stdint.h>
#include <vector>

struct ElfExecutable::ProgramHeader {
  const uint32_t kType;
  const uint32_t kFlags;
  const uint64_t kOffset;
  const uint64_t kVirtualAddress;
  const uint64_t kPhysicalAddress;
  const uint64_t kFileSize;
  const uint64_t kMemorySize;
  const uint64_t kAlign;
};

bool ValidElfProgramHeader(const ElfExecutable::ProgramHeader &program_header);

std::vector<ElfExecutable::ProgramHeader>
ParseElfProgramHeaders(const uint8_t *const buf,
                       const ElfExecutable::Header *const header);

#endif // BINARY_MATCHER_ELF_EXECUTABLE_PROGRAM_HEADER_H
