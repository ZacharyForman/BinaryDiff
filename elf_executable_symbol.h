#ifndef BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_H
#define BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_H

#include "elf_executable.h"

#include <stdint.h>
#include <string>

struct ElfExecutable::Symbol {
  const uint32_t kName;
  const uint8_t *const kStringName;
  const uint64_t kValue;
  const uint64_t kSize;
  const uint8_t kInfo;
  const uint8_t kOther;
  const uint16_t kSectionHeaderIndex;

  std::string ToString() const;
};

#endif // BINARY_MATCHER_ELF_EXECUTABLE_SYMBOL_H
