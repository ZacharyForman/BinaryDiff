#ifndef BINARY_MATCHER_ELF_BINARY_H
#define BINARY_MATCHER_ELF_BINARY_H

#include "binary.h"

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

// Represents an ELF format binary.
// See man 5 elf for a thorough description
// of the ELF file format.
class ElfBinary final : public Binary {
public:
  // Type representing an ELF Header.
  struct Header;
  // Type representing an ELF Program Header.
  struct ProgramHeader;
  // Type representing an ELF Section Header.
  struct SectionHeader;
  // Type representing an ELF Symbol.
  struct Symbol;
  // Type representing an ELF Symbol Table.
  class SymbolTable;

  // Parses an ElfBinary from the given file.
  // Returns nullptr in case of failure.
  static ElfBinary *ParseFile(const File *file);

  // Returns a pointer to the binary's ELF header.
  const Header *header() const;

  // Returns the binary's program headers.
  const std::vector<ProgramHeader> &program_headers() const;

  // Returns the binary's section headers.
  const std::vector<SectionHeader> &section_headers() const;

  // Returns the binary's symbol tables.
  const std::vector<SymbolTable> &symbol_tables() const;

  Binary::Type GetType() const override;
  std::string ToString() const override;
private:
  ElfBinary(const File *file, Header *header,
                std::vector<ProgramHeader> &&program_headers,
                std::vector<SectionHeader> &&section_headers,
                std::vector<SymbolTable> &&symbol_tables);

  // The binary's ELF header.
  std::unique_ptr<Header> header_;

  // The binary's program headers.
  std::vector<ProgramHeader> program_headers_;

  // The binary's section headers.
  std::vector<SectionHeader> section_headers_;

  // The binary's symbol tables.
  std::vector<SymbolTable> symbol_tables_;
};

#endif // BINARY_MATCHER_ELF_BINARY_H
