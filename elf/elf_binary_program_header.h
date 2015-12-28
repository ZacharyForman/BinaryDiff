#ifndef BINARY_MATCHER_ELF_BINARY_PROGRAM_HEADER_H
#define BINARY_MATCHER_ELF_BINARY_PROGRAM_HEADER_H

#include "elf/elf_binary.h"
#include "elf/elf_binary_header.h"

#include <stdint.h>
#include <string>
#include <vector>

// Type that represents an ELF program header.
// An elf program header contains information about
// the segments within the binary.
struct ElfBinary::ProgramHeader {
  // The type of the segment this header describes.
  // Potential values and their meanings are:
  //  PT_NULL:         Unused.
  //  PT_LOAD:         Loadable segment
  //  PT_DYNAMIC:      Dynamic linking information.
  //  PT_INTERP:       Specifies the binary's interpreter.
  //  PT_NOTE:         Auxiliary information about the binary.
  //  PT_SHLIB:        Reserved, but unspecified.
  //  PT_PHDR:         The location and size of this table.
  //  PT_GNU_STACK:    GNU Extension.
  //  PT_GNU_EH_FRAME: GNU Extension.
  //  PT_GNU_RELRO:    GNU Extension.
  //  PT_TLS:          Thread local storage.
  const uint32_t kType;
  // A bitmask giving the segment's properties.
  // Potential values and their meanings are:
  // PF_X: Executable segment.
  // PF_W: A writable segment.
  // PF_R: A readable segment.
  const uint32_t kFlags;
  // The offset from the start of the file to the segment
  // described in this program header.
  const uint64_t kOffset;
  // The virtual address at which the start of the segment
  // lives in memory.
  const uint64_t kVirtualAddress;
  // Where physical addresses are used, the physical address
  // that the segment must be loaded to.
  const uint64_t kPhysicalAddress;
  // The size of the segment in the file.
  const uint64_t kFileSize;
  // The size of the segment in memory.
  const uint64_t kMemorySize;
  // The alignment requirements of the segment.
  const uint64_t kAlign;

  // Constructs a string representation of the program header
  // that contains all of the information in the above fields.
  std::string ToString() const;
};

// Validates that the given program header is a valid ELF program header.
bool ValidElfProgramHeader(const ElfBinary::ProgramHeader &program_header);

// Parses the ELF program headers from the given buffer.
// Returns an empty vector on failure.
std::vector<ElfBinary::ProgramHeader>
ParseElfProgramHeaders(const uint8_t *const buf,
                       const ElfBinary::Header *const header);

#endif // BINARY_MATCHER_ELF_BINARY_PROGRAM_HEADER_H
