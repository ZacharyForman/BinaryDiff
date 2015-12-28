#ifndef BINARY_MATCHER_ELF_BINARY_HEADER_H
#define BINARY_MATCHER_ELF_BINARY_HEADER_H

#include "elf/elf_binary.h"

#include <stdint.h>
#include <string>

// Type that represents an ELF header.
// The ELF header contains information about the
// type and layout of the binary.
struct ElfBinary::Header {
  // Determines if the binary is in a 32 or 64 bit format.
  // Potential values and their meanings are:
  //  ELFCLASSNONE: The binary is in an invalid format.
  //  ELFCLASS32:   The binary is ELF32 format.
  //  ELFCLASS64:   The binary is ELF64 format.
  const uint8_t kClass;
  // Determines if the binary is stores in a little or big endian format.
  // Potential values and their meanings are:
  //  ELFDATANONE: Unknown data format.
  //  ELFDATA2LSB: The binary is little endian.
  //  ELFDATA2MSB: The binary is big endian.
  const uint8_t kData;
  // The short version of the binary.
  // Potential values and their meanings are:
  //  EV_NONE:    Invalid version.
  //  EV_CURRENT: Current version.
  const uint8_t kShortVersion;
  // The OS ABI that the binary meets.
  // Potential values and their meanings are:
  //  ELFOSABI_SYSV:       UNIX System V ABI
  //  ELFOSABI_HPUX:       HP-UX ABI
  //  ELFOSABI_NETBSD:     NetBSD ABI
  //  ELFOSABI_LINUX:      Linux ABI
  //  ELFOSABI_SOLARIS:    Solaris ABI
  //  ELFOSABI_IRIX:       IRIX ABI
  //  ELFOSABI_FREEBSD:    FreeBSD ABI
  //  ELFOSABI_TRU64:      TRU64 Unix ABI
  //  ELFOSABI_ARM:        ARM architecture ABI
  //  ELFOSABI_STANDALONE: Stand-alone (embedded) ABI
  const uint8_t kOsAbi;
  // If standards conforming, always 0.
  const uint8_t kAbiVersion;
  // The type of the binary.
  // Potential values and their meanings are:
  //  ET_NONE: Unknown type.
  //  ET_REL:  A relocatable file.
  //  ET_EXEC: An executable file.
  //  ET_DYN:  A shared object.
  //  ET_CORE: A core file.
  const uint16_t kType;
  // The required architecture to execute the file.
  // Potential values and their meanings are:
  //  EM_M32: AT&T WE 32100
  //  EM_SPARC: Sun Microsystems SPARC
  //  EM_386: Intel 80386
  //  EM_68K: Motorola 68000
  //  EM_88K: Motorola 88000
  //  EM_860: Intel 80860
  //  EM_MIPS: MIPS RS3000 (big-endian only)
  //  EM_PARISC: HP/PA
  //  EM_SPARC32PLUS: SPARC with enhanced instruction set
  //  EM_PPC: PowerPC
  //  EM_PPC64: PowerPC 64-bit
  //  EM_S390: IBM S/390
  //  EM_ARM: Advanced RISC Machines
  //  EM_SH: Renesas SuperH
  //  EM_SPARCV9: SPARC v9 64-bit
  //  EM_IA_64: Intel Itanium
  //  EM_X86_64: AMD x86-64
  //  EM_VAX: DEC Vax
  const uint16_t kMachine;
  // The long version of the binary.
  // Potential values and their meanings are:
  //  EV_NONE:    Invalid version.
  //  EV_CURRENT: Current version.
  const uint32_t kLongVersion;
  // The virtual address where the program should
  // start executing. If not executable, 0.
  const uint64_t kEntryPoint;
  // The file offset of the program header table.
  // If there are no program headers, holds 0.
  const uint64_t kProgramHeaderOffset;
  // The file offset of the section header table.
  // If there are no section headers, holds 0.
  const uint64_t kSectionHeaderOffset;
  // Processor specific flags.
  const uint32_t kFlags;
  // The size of this header in bytes.
  const uint16_t kHeaderSize;
  // The size of each program header.
  const uint16_t kProgramHeaderSize;
  // The number of program headers.
  const uint16_t kProgramHeaderCount;
  // The size of each section header.
  const uint16_t kSectionHeaderSize;
  // The number of section headers.
  const uint16_t kSectionHeaderCount;
  // The section header that corresponds to the string table that
  // contains the names for the section headers.
  const uint16_t kSectionHeaderNamesIndex;

  // Constructs a string representation of the header, that
  // contains all of the information in the above fields.
  std::string ToString() const;
};

// Validates that the given header is a valid ELF header.
bool ValidElfHeader(const ElfBinary::Header *const head);

// Parses an ELF header from the given buffer.
// Returns nullptr on failure.
ElfBinary::Header *ParseElfHeader(const uint8_t *const buf);


#endif // BINARY_MATCHER_ELF_BINARY_HEADER_H
