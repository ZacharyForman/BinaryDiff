#ifndef BINARY_MATCHER_ELF_EXECUTABLE_HEADER_H
#define BINARY_MATCHER_ELF_EXECUTABLE_HEADER_H

#include "elf_executable.h"
#include <stdint.h>
#include <string>

struct ElfExecutable::Header {
  const uint8_t kClass;
  const uint8_t kData;
  const uint8_t kShortVersion;
  const uint8_t kOsAbi;
  const uint8_t kAbiVersion;
  const uint16_t kType;
  const uint16_t kMachine;
  const uint32_t kLongVersion;
  const uint64_t kEntryPoint;
  const uint64_t kProgramHeaderOffset;
  const uint64_t kSectionHeaderOffset;
  const uint32_t kFlags;
  const uint16_t kHeaderSize;
  const uint16_t kProgramHeaderSize;
  const uint16_t kProgramHeaderCount;
  const uint16_t kSectionHeaderSize;
  const uint16_t kSectionHeaderCount;
  const uint16_t kSectionHeaderNamesIndex;

  std::string ToString() const;
};

bool ValidElfHeader(const ElfExecutable::Header *const head);

ElfExecutable::Header *ParseElfHeader(const uint8_t *const buf);


#endif // BINARY_MATCHER_ELF_EXECUTABLE_HEADER_H
