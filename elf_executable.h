#ifndef BINARY_MATCHER_ELF_EXECUTABLE_H
#define BINARY_MATCHER_ELF_EXECUTABLE_H

#include "executable.h"

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

class ElfExecutable : public Executable {
public:
  static ElfExecutable *ParseFile(const File *file);
  struct Header;
  struct ProgramHeader;
  struct SectionHeader;
  struct Symbol;
  class SymbolTable;

  Executable::Type GetType() const;
  const Header *const header() const;
  const std::vector<ProgramHeader> &program_headers() const;
  const std::vector<SectionHeader> &section_headers() const;

  std::string ToString() const;
private:
  ElfExecutable(const File *file, Header *header,
                std::vector<ProgramHeader> &&program_headers,
                std::vector<SectionHeader> &&section_headers,
                std::vector<SymbolTable> &&symbol_tables);
  std::unique_ptr<Header> header_;
  std::vector<ProgramHeader> program_headers_;
  std::vector<SectionHeader> section_headers_;
  std::vector<SymbolTable> symbol_tables_;
};

#endif // BINARY_MATCHER_ELF_EXECUTABLE_H
